// Package testenv is what the two live suites share: the servers
// scripts/testenv.sh started for them, and which of the three ways
// technitium-mcp is used they stand for - one server, two that know nothing
// of each other, or two that are a cluster. The machinery for reading the
// environment is go-kt's (test/env).
//
// The integration suite (../../integration) drives the client in
// sdk/technitium and the acceptance suite (../../acceptance) drives the tools
// over MCP. Each runs three times on the same servers, in order: on one
// server, then with a second started beside it, then with the two made a
// cluster - which this package does, through the client, as part of opening
// the third.
//
// It is also where a machine asks the servers for a lease (Lease): the one
// thing the suites need that no API makes.
package testenv

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/katbyte/go-kt/test/env"
	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// Topology is one of the ways the servers under test are arranged.
type Topology string

const (
	// Single is one server, configured as one is: an address and a token,
	// with no name.
	Single Topology = "single"
	// Pair is two servers that know nothing of each other.
	Pair Topology = "pair"
	// Cluster is two servers in a cluster, the first its primary node.
	Cluster Topology = "cluster"
)

const (
	// NS1 and NS2 are the two servers scripts/testenv.sh starts, by the
	// names it gives them when there are two.
	NS1 = "ns1"
	NS2 = "ns2"

	// ClusterDomain is the domain the suites' cluster is made under, and
	// ClusterCatalog the catalog zone a cluster makes for itself there: a
	// zone made a member of it on the primary is given to every node.
	ClusterDomain  = "cluster.test"
	ClusterCatalog = "cluster-catalog." + ClusterDomain

	// NotConfigured is why a live test skips when the environment names no
	// servers.
	NotConfigured = `TECHNITIUM_SERVER and TECHNITIUM_TOKEN are not set: run "make testacc", or eval "$(scripts/testenv.sh up)" first`

	// joinPatience is how long a join is tried for: a server just made a
	// cluster's primary takes a few seconds to start answering over HTTPS,
	// and refuses the connection until it does
	joinPatience = 90 * time.Second
	joinWait     = 2 * time.Second
	// settlePatience is how long a server whose console is restarting is
	// waited for
	settlePatience = 30 * time.Second
)

// environment is what scripts/testenv.sh writes, every variable of which
// begins TECHNITIUM_.
var environment = env.New("TECHNITIUM")

// Configured reports whether the environment names servers and tokens for
// them.
func Configured() bool { return environment.Configured() }

// World is the servers a live suite runs against and how they are arranged.
type World struct {
	Topology Topology
	Set      *servers.Set
	// First is the name of the server the suites make their zones on: the
	// only one, or the first of two, which in a cluster is its primary node
	First string
	// Second is the other server's name, "" when there is one
	Second string

	addresses map[string]string
}

// Address is a server's address on the network the servers share, which is
// where another server reaches its DNS.
func (w *World) Address(name string) string {
	if name == servers.Default {
		name = NS1
	}

	return w.addresses[name]
}

// Names are the servers' names, the first first.
func (w *World) Names() []string { return w.Set.Names() }

// Password is the administrator's password on the servers
// scripts/testenv.sh started, which signing in to one takes.
func (*World) Password() string { return environment.Get("TEST_PASSWORD") }

// Client is the client for one of the servers by name.
func (w *World) Client(name string) (*technitium.Client, error) {
	srv, err := w.Set.One(name)
	if err != nil {
		return nil, err
	}

	return srv.Client, nil
}

// Domain is the domain name a server calls itself: the name the script gave
// it, under the cluster's domain once it is a node of one.
func (w *World) Domain(name string) string {
	own := name
	if name == servers.Default {
		own = NS1
	}
	if w.Topology == Cluster {
		return own + "." + ClusterDomain
	}

	return own
}

// Pool is the part of the network the servers share that the suites lease
// from: its last addresses, all in one /24, far from the ones Docker gives
// the containers from the other end.
type Pool struct {
	// Subnet is the whole network, and Mask its mask as a DHCP scope takes
	// one
	Subnet netip.Prefix
	Mask   string
	// First and Last are the range to lease from
	First, Last netip.Addr
}

// poolSize is how many addresses a Pool's range holds.
const poolSize = 60

// At is the nth address of the range, from 0.
func (p Pool) At(n int) string {
	addr := p.First
	for range n {
		addr = addr.Next()
	}

	return addr.String()
}

// ReverseZone is the reverse zone the whole range falls in.
func (p Pool) ReverseZone() string {
	b := p.First.As4()

	return fmt.Sprintf("%d.%d.%d.in-addr.arpa", b[2], b[1], b[0])
}

// Pool is the range the suites lease from, and whether the environment gave
// what leasing needs: the network's name and range and a DHCP client's
// image, as scripts/testenv.sh prints them. Servers started some other way
// lease nothing, and the tests that need a lease skip.
func (*World) Pool() (Pool, bool) {
	subnet, err := netip.ParsePrefix(environment.Get("TEST_SUBNET"))
	if err != nil || !subnet.Addr().Is4() || subnet.Bits() > 24 || environment.Get("TEST_NETWORK") == "" || environment.Get("TEST_CLIENT_IMAGE") == "" {
		return Pool{}, false
	}

	// the network's last address is its broadcast address: every bit past
	// the mask set
	last, mask := subnet.Masked().Addr().As4(), [4]byte{}
	for bit := range 32 {
		if bit < subnet.Bits() {
			mask[bit/8] |= 1 << (7 - bit%8)
		} else {
			last[bit/8] |= 1 << (7 - bit%8)
		}
	}
	last[3] = 250
	first := last
	first[3] -= poolSize - 1

	return Pool{Subnet: subnet.Masked(), Mask: netip.AddrFrom4(mask).String(), First: netip.AddrFrom4(first), Last: netip.AddrFrom4(last)}, true
}

// Lease has a machine ask the servers for an address: a DHCP client run for
// a moment in a container of its own on the network they share, with the
// hardware address given and, when one is given, a host name to tell the
// server. It takes whatever lease it is offered, sets nothing by it, and is
// gone; the server goes on holding the lease. The address it was given is
// the server's to say.
func (w *World) Lease(ctx context.Context, hardwareAddress, hostName string) error {
	if _, ok := w.Pool(); !ok {
		return fmt.Errorf("%s, %s and %s must name the servers' network, its range and a DHCP client's image, as scripts/testenv.sh prints them", environment.Var("TEST_NETWORK"), environment.Var("TEST_SUBNET"), environment.Var("TEST_CLIENT_IMAGE"))
	}

	// udhcpc: once (-n -q), in the foreground, with a script that does nothing so the container's own address stays as Docker set it
	args := []string{"run", "--rm", "--network", environment.Get("TEST_NETWORK"), "--mac-address", hardwareAddress, environment.Get("TEST_CLIENT_IMAGE"), "udhcpc", "-i", "eth0", "-n", "-q", "-f", "-s", "/bin/true"}
	if hostName != "" {
		args = append(args, "-x", "hostname:"+hostName)
	}
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil { //nolint:gosec // G204: the suites' own client, on the suites' own network
		return fmt.Errorf("%s (%s) was given no lease: %w: %s", hardwareAddress, hostName, err, strings.TrimSpace(string(out)))
	}

	return nil
}

// named reads a setting of the form name=value,name=value into a map; a
// value given alone, as one server's is, goes under the name given.
func named(setting, alone string) map[string]string {
	out := map[string]string{}
	for entry := range strings.SplitSeq(setting, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		name, value, hasName := strings.Cut(entry, "=")
		if !hasName || strings.Contains(name, "://") {
			name, value = alone, entry
		}
		out[name] = value
	}

	return out
}

// Open reads the environment and returns the servers arranged as it asks
// (TECHNITIUM_TEST_TOPOLOGY: single, pair or cluster; with none, single for
// one server and pair for two). The arrangement asked for is checked against
// what is there, and for cluster it is made: the first server is made the
// primary node of a new cluster and the second joins it, both through the
// client, unless they already are one.
func Open(ctx context.Context) (*World, error) {
	set, err := servers.New([]string{environment.Server()}, []string{environment.Token()})
	if err != nil {
		return nil, err
	}

	topology := Topology(environment.Get("TEST_TOPOLOGY"))
	if topology == "" {
		topology = Pair
		if set.Len() == 1 {
			topology = Single
		}
	}

	switch topology {
	case Single:
		if !slices.Equal(set.Names(), []string{servers.Default}) {
			return nil, fmt.Errorf("the single topology is one server configured with no name, and the environment names %v: start it with scripts/testenv.sh up single", set.Names())
		}

		return &World{Topology: Single, Set: set, First: servers.Default, addresses: named(environment.Get("TEST_ADDRESSES"), NS1)}, nil
	case Pair, Cluster:
		// never anything but the two servers the script starts: a suite makes
		// and deletes zones, and a cluster cannot be unmade again from here
		if !slices.Equal(set.Names(), []string{NS1, NS2}) {
			return nil, fmt.Errorf("the %s topology is the two servers scripts/testenv.sh starts, %s and %s, and the environment names %v: never point the suites at servers that are in use", topology, NS1, NS2, set.Names())
		}
	default:
		return nil, fmt.Errorf("%s=%q: the topologies are %s, %s and %s", environment.Var("TEST_TOPOLOGY"), topology, Single, Pair, Cluster)
	}

	world := &World{Topology: topology, Set: set, First: NS1, Second: NS2, addresses: named(environment.Get("TEST_ADDRESSES"), "")}
	if topology == Pair {
		if err := world.checkApart(ctx); err != nil {
			return nil, err
		}

		return world, nil
	}
	if world.Set, err = formCluster(ctx, set); err != nil {
		return nil, fmt.Errorf("making the cluster: %w", err)
	}

	return world, nil
}

// checkApart makes sure two servers that are meant to know nothing of each
// other are in no cluster: one left from an earlier run would make every
// answer the pair's tests expect wrong.
func (w *World) checkApart(ctx context.Context) error {
	for _, srv := range w.Set.Every() {
		state, err := srv.Client.ClusterState(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", srv.Name, err)
		}
		if state.Initialized {
			return fmt.Errorf("%s is a node of the cluster %s, and the pair topology is two servers on their own: the cluster stage runs last, so start fresh servers (scripts/testenv.sh up)", srv.Name, state.Domain)
		}
	}

	return nil
}

// formCluster makes the two servers a cluster, the first its primary, and
// returns the set to use from then on: joining writes the primary's accounts
// and tokens over the second server's, so the token the script minted for
// the second stops working and the first's works on both.
func formCluster(ctx context.Context, set *servers.Set) (*servers.Set, error) {
	urls, tokens, addresses := named(environment.Server(), ""), named(environment.Token(), ""), named(environment.Get("TEST_ADDRESSES"), "")
	password := environment.Get("TEST_PASSWORD")
	if addresses[NS1] == "" || addresses[NS2] == "" || password == "" {
		return nil, fmt.Errorf("%s and %s must give each server's address and the administrator's password, as scripts/testenv.sh prints them", environment.Var("TEST_ADDRESSES"), environment.Var("TEST_PASSWORD"))
	}
	clustered, err := servers.New([]string{NS1 + "=" + urls[NS1], NS2 + "=" + urls[NS2]}, []string{tokens[NS1]})
	if err != nil {
		return nil, err
	}
	first, second := clustered.Every()[0].Client, clustered.Every()[1].Client

	// a server restarts its console to serve HTTPS as it is made a node, and
	// can cut the very connection its answer was coming on: after a call
	// that failed, what it did is asked of the server again
	primary, err := first.ClusterState(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", NS1, err)
	}
	if !primary.Initialized {
		if _, initErr := first.InitCluster(ctx, ClusterDomain, []string{addresses[NS1]}); initErr != nil {
			if now, took := settled(ctx, first); !took || !now.Initialized {
				return nil, fmt.Errorf("%s: %w", NS1, initErr)
			}
		}
		// asked again once its console is back: nothing is listening while it restarts, and a read is not sent again for that
		now, answered := settled(ctx, first)
		if !answered {
			return nil, fmt.Errorf("%s was made a cluster's primary and did not answer again", NS1)
		}
		primary = now
	}
	if primary.Domain != ClusterDomain || primary.Primary() == nil || primary.Self() == nil || primary.Self().Type != technitium.NodePrimary {
		return nil, fmt.Errorf("%s is in the cluster %q and is not its primary node: the suites make their own cluster, %s, on fresh servers", NS1, primary.Domain, ClusterDomain)
	}

	// the second server takes the first's token only once it has joined
	if now, answered := settled(ctx, second); answered && now.Initialized {
		return clustered, awaitClusterZones(ctx, second)
	}

	joining, err := set.One(NS2)
	if err != nil {
		return nil, err
	}
	if err := joinNode(ctx, joining.Client, second, NS2, technitium.ClusterJoin{Addresses: []string{addresses[NS2]}, PrimaryURL: primary.Primary().URL, PrimaryAddress: addresses[NS1], IgnoreCertificateErrors: true, Username: "admin", Password: password}); err != nil {
		return nil, err
	}

	return clustered, awaitClusterZones(ctx, second)
}

// joinNode has a server join a cluster and waits until it has: asked as the
// client that works on it now, and looked at afterwards as the one that
// works on it once it is in, which is the cluster's own.
func joinNode(ctx context.Context, joining, joined *technitium.Client, name string, join technitium.ClusterJoin) error {
	deadline := time.Now().Add(joinPatience)
	for {
		_, joinErr := joining.JoinCluster(ctx, join)
		if joinErr == nil {
			break
		}
		if now, answered := settled(ctx, joined); answered && now.Initialized {
			break
		}
		// two failures pass by themselves: the primary refuses the
		// connection until its HTTPS is up, which the joining server says in
		// an answer; and the joining server turns its own HTTPS on before it
		// joins, cutting the connection it was asked on, so the first ask of
		// a fresh server gets no answer at all
		_, answered := errors.AsType[*technitium.APIError](joinErr)
		if (answered && !strings.Contains(joinErr.Error(), "Connection refused")) || time.Now().After(deadline) {
			return fmt.Errorf("%s joining: %w", name, joinErr)
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), joinErr)
		case <-time.After(joinWait):
		}
	}

	// the cluster's token works on the server from here on, once its console is back
	if _, answered := settled(ctx, joined); !answered {
		return fmt.Errorf("%s joined the cluster and did not answer again with the primary's token", name)
	}
	if _, err := joined.Session(ctx); err != nil {
		return fmt.Errorf("%s has joined, and the primary's token is not taken there: %w", name, err)
	}

	return nil
}

// TakingApart reports whether this run is the one that ends a suite by
// taking its cluster apart, which nothing can run after: make starts it
// last, alone (see the makefile's testacc-integration).
func (w *World) TakingApart() bool {
	return w.Topology == Cluster && environment.Get("TEST_APART") != ""
}

// Join has one of the two servers join the cluster the other is the primary
// of, and waits until it holds the cluster's zones. Both are asked with the
// cluster's token, which a server that has left a cluster still takes.
func (w *World) Join(ctx context.Context, joiner, primary string) error {
	joining, err := w.Client(joiner)
	if err != nil {
		return err
	}
	leading, err := w.Client(primary)
	if err != nil {
		return err
	}
	state, answered := settled(ctx, leading)
	if !answered || state.Primary() == nil {
		return fmt.Errorf("%s is not the primary of a cluster to join: %+v", primary, state)
	}
	if err := joinNode(ctx, joining, joining, joiner, technitium.ClusterJoin{Addresses: []string{w.Address(joiner)}, PrimaryURL: state.Primary().URL, PrimaryAddress: w.Address(primary), IgnoreCertificateErrors: true, Username: "admin", Password: w.Password()}); err != nil {
		return err
	}

	return awaitClusterZones(ctx, joining)
}

// Settled asks a server how it stands in a cluster, waiting out a console
// that is restarting, as one does when it joins or leaves. It reports false
// when the server never answers.
func (w *World) Settled(ctx context.Context, name string) (*technitium.Cluster, bool) {
	c, err := w.Client(name)
	if err != nil {
		return nil, false
	}

	return settled(ctx, c)
}

// awaitClusterZones waits for a node that has just joined to hold the
// cluster's two zones as live copies: it makes them empty as it joins and
// fills them by transfer a few seconds later, and until then it is a node of
// a cluster whose catalog it cannot read.
func awaitClusterZones(ctx context.Context, second *technitium.Client) error {
	var last string
	deadline := time.Now().Add(joinPatience)
	for {
		zones, err := second.Zones(ctx, technitium.ZoneFilter{})
		live := 0
		for i := range zones {
			z := &zones[i]
			if (z.Name == ClusterCatalog || z.Name == ClusterDomain) && !z.IsExpired && !z.SyncFailed && z.SOASerial > 0 {
				live++
			}
		}
		if err == nil && live == 2 {
			return nil
		}
		last = fmt.Sprintf("%d of its 2 zones are live (%v)", live, err)
		if time.Now().After(deadline) {
			return fmt.Errorf("a server joined the cluster and never took its zones: %s", last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(joinWait):
		}
	}
}

// settled asks a server how it stands in a cluster, with the primary's
// token, waiting out a console that is restarting. It reports false when the
// server answers that it does not know the token - a second server that has
// not joined - or never answers.
func settled(ctx context.Context, c *technitium.Client) (*technitium.Cluster, bool) {
	deadline := time.Now().Add(settlePatience)
	for {
		state, err := c.ClusterState(ctx)
		if err == nil {
			return state, true
		}
		if technitium.IsInvalidToken(err) || time.Now().After(deadline) {
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(joinWait):
		}
	}
}
