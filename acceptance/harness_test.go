//go:build integration

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/go-kt/mcp/registry"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The fixtures: a zone every server holds, one only the first holds, and the
// reverse zone for the shared zone's addresses, which only the first holds
// too - in a cluster as well, where it is not made a member of the catalog.
const (
	sharedZone  = "acc.test"
	firstZone   = "only1.acc.test"
	reverseZone = "0.0.10.in-addr.arpa"
)

// The zones the tests that change records work in, so that what they change
// is in no table another test reads whole: a zone on the first server - in a
// cluster a member of the catalog, so the second holds a copy that refuses a
// change - and the reverse zone for its addresses, on the first alone.
const (
	writeZone        = "writes.test"
	writeReverseZone = "8.9.10.in-addr.arpa"
)

// cacheZone is a zone the second server holds and the first forwards to it
// for, so that what the first resolves there it keeps in its cache: the one
// way to put something in a cache without the internet. With one server there
// is no second to forward to, and its cache stays empty.
const cacheZone = "cached.test"

// ownZones are the zones the first server holds alone; the reverse zone for
// the addresses it leases joins them once the network is known (see start).
var ownZones = []string{firstZone, reverseZone, writeReverseZone, dhcpZone, setupZone, splitZone, mirrorZone}

// leftZones are the zones the tests of the changes make and delete again:
// taken away with the rest when a run starts and when it ends, on whichever
// server has them and as whatever type.
var leftZones = []string{madeZone, sourceZone, cloneZone, signedZone, hostZone, hostReverse, messZone, messReverse, lifeZone, lifeClone, restoredZone, busyZone, bothZone, kindsZone, kindsForward, keyedZone, importZone, setupJourneyZone, setupJourneyReverse, setupJourneyForward}

// fixture is a record a server is given in the shared zone.
type fixture struct {
	// on is the servers the record is added on when the two know nothing of
	// each other. With one server, and in a cluster, the first server's are
	// added on it - and the cluster gives them to the second.
	on         []string
	name       string
	recordType string
	ttl        int
	comment    string
	data       technitium.RData
}

// fixtures are the shared zone's records. For two servers on their own: most
// on both alike, one on each alone, one held with a different TTL on each,
// and one more on the first so the two copies differ in size and serial.
var fixtures = []fixture{
	{[]string{testenv.NS1, testenv.NS2}, "emby.van." + sharedZone, "A", 3600, "", technitium.RData{"ipAddress": "10.0.0.4"}},
	{[]string{testenv.NS1, testenv.NS2}, "m." + sharedZone, "CNAME", 3600, "", technitium.RData{"cname": "emby.van." + sharedZone}},
	{[]string{testenv.NS1, testenv.NS2}, "jf." + sharedZone, "CNAME", 3600, "", technitium.RData{"cname": "m." + sharedZone}},
	{[]string{testenv.NS1, testenv.NS2}, sharedZone, "MX", 3600, "", technitium.RData{"preference": 10, "exchange": "mail." + sharedZone}},
	{[]string{testenv.NS1}, "dock.van." + sharedZone, "A", 3600, "the docker host", technitium.RData{"ipAddress": "10.0.0.2"}},
	{[]string{testenv.NS2}, "rpi.van." + sharedZone, "A", 3600, "", technitium.RData{"ipAddress": "10.0.0.3"}},
	{[]string{testenv.NS1}, "edge.van." + sharedZone, "A", 300, "", technitium.RData{"ipAddress": "10.0.0.252"}},
	{[]string{testenv.NS2}, "edge.van." + sharedZone, "A", 3600, "", technitium.RData{"ipAddress": "10.0.0.252"}},
	{[]string{testenv.NS1}, "extra." + sharedZone, "TXT", 3600, "", technitium.RData{"text": "only on ns1"}},
	{[]string{testenv.NS1, testenv.NS2}, "*.wild." + sharedZone, "A", 3600, "", technitium.RData{"ipAddress": "10.0.0.9"}},
	// one thing wrong, for the audits: a CNAME to a name with no record
	{[]string{testenv.NS1, testenv.NS2}, "gone." + sharedZone, "CNAME", 3600, "", technitium.RData{"cname": "nothing." + sharedZone}},
}

var (
	// world is the servers under test and how they are arranged
	world *testenv.World
	// suite is the one client session every test calls the tools through,
	// and the record of what was called
	suite = &acctest.Suite{NotReady: testenv.NotConfigured}
)

// runSuite arranges the servers as the environment asks, lays the fixtures
// out, runs the tests, takes the fixtures away again and holds the run to
// having called every tool, returning the code to exit with.
func runSuite(m *testing.M) int {
	if !testenv.Configured() {
		return m.Run() // every test skips
	}

	ctx := context.Background()
	var err error
	if world, err = testenv.Open(ctx); err == nil {
		err = start(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "acceptance setup:", err)

		return 1
	}

	code := m.Run()
	// no tool may have shown a secret a test gave one: a password, a one-time code, a transfer key's secret
	if report := suite.LeakReport(); report != "" {
		fmt.Fprint(os.Stderr, report)
		code = 1
	}
	removeBinary()
	if err := removeFixtures(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "acceptance teardown:", err)
		code = 1
	}

	// every registered tool must have answered something above, not only
	// refused it. Only a whole-suite run can say that, so a -run or -skip
	// filter skips the check.
	if acctest.WholeRun() {
		report, err := suite.CoverageReport()
		if err != nil {
			fmt.Fprintln(os.Stderr, "\n"+err.Error())
			code = 1
		}
		if report != "" {
			fmt.Fprint(os.Stderr, report)
			code = 1
		}
	}

	return code
}

// start lays the fixtures out and connects the suite to an MCP server
// registering every tool for the servers.
func start(ctx context.Context) error {
	var leasing bool
	if pool, leasing = world.Pool(); !leasing {
		return errors.New("the environment names no network to lease addresses on, which the DHCP tools are tested by: start the servers with .scripts/testenv.sh, which gives one")
	}
	ownZones = append(ownZones, pool.ReverseZone())

	// a run that was cut short may have left its zones behind
	_ = removeFixtures(ctx)
	if err := makeFixtures(ctx); err != nil {
		return err
	}

	srv := mcp.NewServer(&mcp.Implementation{Name: "technitium", Version: "acceptance"}, nil)
	if _, err := tools.RegisterAll(srv, world.Set, tools.Options{Toolsets: []string{registry.All}, EnableWrite: true, EnableDelete: true}); err != nil {
		return err
	}
	connected, err := acctest.Connect(ctx, srv)
	if err != nil {
		return err
	}
	connected.NotReady = suite.NotReady
	suite = connected
	// everything a tool says all run long is read for the servers' own credentials, and for each one a test hands a tool (suite.Secret)
	for _, secret := range world.Secrets() {
		suite.Secret(secret)
	}
	suite.CannotAnswer = map[string]string{}
	if alone() {
		// a copy needs a primary to be a copy of, and one server has no other
		suite.CannotAnswer["zone_resync"] = "one server has no other to hold a copy of a zone from"
	}
	if clustered() {
		// a node of a cluster is in it already, and the run that takes the cluster apart is where one joins
		suite.CannotAnswer["cluster_join"] = "both servers are in the cluster already: the run that ends the suite has one join"
	} else {
		for _, tool := range []string{"cluster_edit", "cluster_node_delete", "cluster_leave", "cluster_promote", "cluster_delete"} {
			suite.CannotAnswer[tool] = "the servers are in no cluster: the cluster topology calls it"
		}
	}

	return nil
}

// clustered reports whether the servers are a cluster, where a zone made on
// the first is given to the second rather than made there too.
func clustered() bool { return world.Topology == testenv.Cluster }

// alone reports whether there is one server.
func alone() bool { return world.Topology == testenv.Single }

// holder is the server a fixture is added on, by the name it has in this
// arrangement, and whether it is added at all: with one server, and in a
// cluster, only the first server's are.
func holder(scriptName string) (name string, added bool) {
	if world.Topology == testenv.Pair {
		return scriptName, true
	}

	return world.First, scriptName == testenv.NS1
}

func makeFixtures(ctx context.Context) error {
	first, err := world.Client(world.First)
	if err != nil {
		return err
	}

	// the shared zone: on every server when they are apart, and in a cluster
	// on the primary alone as a member of the cluster's catalog
	shared := technitium.NewZone{Name: sharedZone, Type: technitium.ZonePrimary}
	on := world.Names()
	if clustered() {
		shared.Catalog, on = testenv.ClusterCatalog, []string{world.First}
	}
	for _, name := range on {
		c, err := world.Client(name)
		if err != nil {
			return err
		}
		if _, err := c.CreateZone(ctx, shared); err != nil {
			return fmt.Errorf("%s: creating %s: %w", name, sharedZone, err)
		}
	}
	for _, zone := range ownZones {
		if _, err := first.CreateZone(ctx, technitium.NewZone{Name: zone, Type: technitium.ZonePrimary}); err != nil {
			return fmt.Errorf("%s: creating %s: %w", world.First, zone, err)
		}
	}
	if _, err := first.CreateZone(ctx, technitium.NewZone{Name: writeZone, Type: technitium.ZonePrimary, Catalog: shared.Catalog}); err != nil {
		return fmt.Errorf("%s: creating %s: %w", world.First, writeZone, err)
	}
	if !alone() {
		second, err := world.Client(world.Second)
		if err != nil {
			return err
		}
		if _, err := second.CreateZone(ctx, technitium.NewZone{Name: cacheZone, Type: technitium.ZonePrimary}); err != nil {
			return fmt.Errorf("%s: creating %s: %w", world.Second, cacheZone, err)
		}
		for _, rec := range []technitium.NewRecord{
			{Zone: cacheZone, Name: "a." + cacheZone, Type: "A", TTL: 600, Data: technitium.RData{"ipAddress": "10.5.5.5"}},
			{Zone: cacheZone, Name: "c." + cacheZone, Type: "CNAME", TTL: 600, Data: technitium.RData{"cname": "a." + cacheZone}},
		} {
			if _, err := second.AddRecord(ctx, rec); err != nil {
				return fmt.Errorf("%s: adding %s: %w", world.Second, rec.Name, err)
			}
		}
		if _, err := first.CreateZone(ctx, technitium.NewZone{Name: cacheZone, Type: technitium.ZoneForwarder, Forwarder: world.Address(world.Second)}); err != nil {
			return fmt.Errorf("%s: creating the forwarder for %s: %w", world.First, cacheZone, err)
		}
	}
	if _, err := first.AddRecord(ctx, technitium.NewRecord{Zone: reverseZone, Name: "4." + reverseZone, Type: "PTR", Data: technitium.RData{"ptrName": "emby.van." + sharedZone}}); err != nil {
		return fmt.Errorf("%s: adding the PTR: %w", world.First, err)
	}

	for _, f := range fixtures {
		for _, scriptName := range f.on {
			name, added := holder(scriptName)
			if !added {
				continue
			}
			c, err := world.Client(name)
			if err != nil {
				return err
			}
			if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: sharedZone, Name: f.name, Type: f.recordType, TTL: f.ttl, Comments: f.comment, Data: f.data}); err != nil {
				return fmt.Errorf("%s: adding the %s at %s: %w", name, f.recordType, f.name, err)
			}
		}
	}

	if err := makeDHCP(ctx, first); err != nil {
		return err
	}
	if err := makeBlocking(ctx, first); err != nil {
		return err
	}
	if err := makeSetup(ctx, first); err != nil {
		return err
	}
	if err := makeSplit(ctx, first); err != nil {
		return err
	}

	if clustered() {
		return waitForCopy(ctx)
	}

	return nil
}

// holdsCopy reports whether the cluster's second node holds a zone as a live
// copy at the first node's serial.
func holdsCopy(ctx context.Context, zone string) bool {
	first, err := world.Client(world.First)
	if err != nil {
		return false
	}
	second, err := world.Client(world.Second)
	if err != nil {
		return false
	}
	serial := func(c *technitium.Client) (uint32, bool) {
		zones, err := c.Zones(ctx, technitium.ZoneFilter{})
		for i := range zones {
			if zones[i].Name == zone && !zones[i].SyncFailed {
				return zones[i].SOASerial, err == nil
			}
		}

		return 0, false
	}
	want, ok := serial(first)
	got, held := serial(second)

	return ok && held && got == want
}

// waitForCopy waits for the cluster's second node to hold the shared zone
// whole: the same serial as the primary's and as many records.
func waitForCopy(ctx context.Context) error {
	first, err := world.Client(world.First)
	if err != nil {
		return err
	}
	second, err := world.Client(world.Second)
	if err != nil {
		return err
	}

	var last string
	if acctest.EventuallyWithin(2*time.Minute, func() bool {
		want, err := first.ZoneRecords(ctx, sharedZone)
		if err != nil {
			last = err.Error()

			return false
		}
		zones, err := second.Zones(ctx, technitium.ZoneFilter{})
		if err != nil || !slices.ContainsFunc(zones, func(z technitium.Zone) bool { return z.Name == sharedZone && !z.SyncFailed }) {
			last = fmt.Sprintf("%s does not hold the zone yet (%v)", world.Second, err)

			return false
		}
		got, err := second.ZoneRecords(ctx, sharedZone)
		if err != nil {
			last = err.Error()

			return false
		}
		last = fmt.Sprintf("%s holds %d records and %s holds %d", world.First, len(want.Records), world.Second, len(got.Records))
		if len(got.Records) != len(want.Records) {
			return false
		}
		last = fmt.Sprintf("%s does not hold %s at %s's serial yet", world.Second, writeZone, world.First)

		return holdsCopy(ctx, writeZone)
	}) {
		return nil
	}

	return fmt.Errorf("the cluster never gave %s to %s whole: %s", sharedZone, world.Second, last)
}

// removeFixtures deletes the suite's zones from every server; a zone that is
// not there is nothing to remove, and a copy a cluster made goes with the
// zone it is a copy of.
func removeFixtures(ctx context.Context) error {
	var errs []error
	// the scope first, while the zones its records are in are still there
	if first, err := world.Client(world.First); err != nil {
		errs = append(errs, err)
	} else if err := first.DeleteScope(ctx, dhcpScope); err != nil {
		errs = append(errs, fmt.Errorf("%s: deleting the scope %s: %w", world.First, dhcpScope, err))
	}
	if err := removeBlocking(ctx); err != nil {
		errs = append(errs, err)
	}
	for _, srv := range world.Set.Every() {
		// a scope that is not there is nothing to delete, and the server says so of none
		errs = append(errs, srv.Client.DeleteScope(ctx, guestScope))
	}
	for _, srv := range world.Set.Every() {
		held, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", srv.Name, err))

			continue
		}
		for i := range held {
			ours := held[i].Name == sharedZone || held[i].Name == writeZone || held[i].Name == cacheZone || slices.Contains(ownZones, held[i].Name)
			// a copy of one of the left zones is made by hand, not by the cluster, and goes by hand
			if !slices.Contains(leftZones, held[i].Name) && (!ours || (held[i].Type != technitium.ZonePrimary && held[i].Type != technitium.ZoneForwarder)) {
				continue
			}
			if err := srv.Client.DeleteZone(ctx, held[i].Name); err != nil {
				errs = append(errs, fmt.Errorf("%s: deleting %s: %w", srv.Name, held[i].Name, err))
			}
		}
	}
	if err := errors.Join(errs...); err != nil || !clustered() {
		return err
	}

	// the next run makes the zone again, which a copy still there refuses
	second, err := world.Client(world.Second)
	if err != nil {
		return err
	}
	if !acctest.EventuallyWithin(2*time.Minute, func() bool {
		zones, err := second.Zones(ctx, technitium.ZoneFilter{})

		return err == nil && !slices.ContainsFunc(zones, func(z technitium.Zone) bool { return z.Name == sharedZone || z.Name == writeZone })
	}) {
		return fmt.Errorf("%s and %s were deleted on %s and %s still holds a copy", sharedZone, writeZone, world.First, world.Second)
	}

	return nil
}

// rowFor is the row for one server, or one zone, in a list of rows that each
// name theirs under key.
func rowFor(t *testing.T, rows []map[string]any, key, want string) map[string]any {
	t.Helper()

	for _, row := range rows {
		if row[key] == want {
			return row
		}
	}
	t.Fatalf("no row with %s %q in %v", key, want, rows)

	return nil
}

// mustClient is the client for one of the servers by name, for the checks a
// test makes of a server itself rather than through a tool.
func mustClient(t *testing.T, name string) *technitium.Client {
	t.Helper()

	c, err := world.Client(name)
	if err != nil {
		t.Fatal(err)
	}

	return c
}
