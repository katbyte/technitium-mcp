//go:build integration

package acceptance

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// The zone the audits of how zones are set up are given something to find
// in, on the first server alone: it names a name server that is no server
// here, and is open to anyone to transfer and to change.
const (
	setupZone = "acc-setup.test"
	strangeNS = "ns9.acc-elsewhere.test"
)

// The zones the split audit reads. splitZone is one the first server holds
// for the inside and the second, standing for the outside, holds as its own
// with other answers: one name answered differently, which is the split
// working; one the outside does not have; one it gives a private address
// for; and one it alone has. Their addresses are ones no network uses, of
// the public kind, so that a private one stands out. mirrorZone is a domain
// on the first server meant to answer as splitZone does, with one name
// alike, one elsewhere and one missing. madeZone is the zone the test of the
// changes makes.
const (
	splitZone  = "acc-split.test"
	mirrorZone = "acc-mirror.test"
	madeZone   = "acc-made.test"
)

// makeSplit lays the split audit's zones out. One server has no other to
// stand for the outside, and is its own.
func makeSplit(ctx context.Context, first *technitium.Client) error {
	add := func(c *technitium.Client, on, zone string, records map[string]string) error {
		for name, address := range records {
			if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: zone, Name: name + "." + zone, Type: "A", Data: technitium.RData{"ipAddress": address}}); err != nil {
				return fmt.Errorf("%s: adding %s.%s: %w", on, name, zone, err)
			}
		}

		return nil
	}
	if err := add(first, world.First, splitZone, map[string]string{"www": "198.51.100.4", "gone": "198.51.100.5", "leak": "198.51.100.6"}); err != nil {
		return err
	}
	if err := add(first, world.First, mirrorZone, map[string]string{"www": "198.51.100.4", "gone": "198.51.100.99"}); err != nil {
		return err
	}
	if alone() {
		return nil
	}

	second, err := world.Client(world.Second)
	if err != nil {
		return err
	}
	if _, err := second.CreateZone(ctx, technitium.NewZone{Name: splitZone, Type: technitium.ZonePrimary}); err != nil {
		return fmt.Errorf("%s: creating %s: %w", world.Second, splitZone, err)
	}

	return add(second, world.Second, splitZone, map[string]string{"www": "203.0.113.4", "leak": "10.6.6.6", "ext": "203.0.113.7"})
}

// makeSetup gives the first server's setup zone its mistakes. The zone
// itself is made with the first server's other zones.
func makeSetup(ctx context.Context, first *technitium.Client) error {
	if _, err := first.AddRecord(ctx, technitium.NewRecord{Zone: setupZone, Name: setupZone, Type: "NS", Data: technitium.RData{"nameServer": strangeNS}}); err != nil {
		return fmt.Errorf("%s: adding a name server to %s: %w", world.First, setupZone, err)
	}
	if err := first.SetZoneOptions(ctx, setupZone, technitium.ZoneChange{ZoneTransfer: technitium.PolicyAllow, Update: technitium.PolicyAllow}); err != nil {
		return fmt.Errorf("%s: opening %s: %w", world.First, setupZone, err)
	}

	return nil
}

// zone_get sets how each server holding a zone serves and copies it side by
// side; zone_export gives one whole as a zone file; and the two audits of
// how zones are set up find the mistakes the setup zone was given, and
// nothing in the zones that have none.
func TestZoneSetup(t *testing.T) {
	t.Parallel()

	servers := names(t)
	out := suite.Call(t, "zone_get", map[string]any{"zone": sharedZone})
	rows := acctest.Rows(t, out["servers"], "servers")
	if out["zone"] != sharedZone || len(rows) != len(servers) || out["missing_on"] != nil {
		t.Fatalf("%s = %v", sharedZone, out)
	}
	first := rowFor(t, rows, "server", world.First)
	// its own primary names itself in its SOA and its NS records, lets its name servers transfer it and tells them of a change, and takes no updates
	if first["type"] != "Primary" || first["error"] != nil || first["soa_primary"] != world.Domain(world.First) || !slices.Contains(acctest.Texts(first["name_servers"]), world.Domain(world.First)) || acctest.Num(t, first["serial"], "serial") < 2 || acctest.Num(t, first["refresh"], "refresh") == 0 || acctest.Num(t, first["expire"], "expire") == 0 || first["query"] != "Allow" || first["update"] != "Deny" || first["primary_addresses"] != nil {
		t.Errorf("%s on %s = %v", sharedZone, world.First, first)
	}
	switch world.Topology {
	case testenv.Single:
		if out["differ"] != nil || first["catalog"] != nil || first["transfer"] != "AllowOnlyZoneNameServers" || first["notify"] != "ZoneNameServers" {
			t.Errorf("%s on the one server = %v, differing in %v", sharedZone, first, out["differ"])
		}
	case testenv.Pair:
		// each its own primary, naming itself
		second := rowFor(t, rows, "server", world.Second)
		if second["type"] != "Primary" || second["soa_primary"] != world.Domain(world.Second) || !slices.Contains(acctest.Strs(t, out["differ"], "differ"), "soa_primary") || !slices.Contains(acctest.Strs(t, out["differ"], "differ"), "name_servers") || slices.Contains(acctest.Strs(t, out["differ"], "differ"), "type") {
			t.Errorf("%s on %s = %v, differing in %v", sharedZone, world.Second, second, out["differ"])
		}
	case testenv.Cluster:
		// the primary's zone, a member of the cluster's catalog, and the copy the other node took: both nodes its name servers
		second := rowFor(t, rows, "server", world.Second)
		if first["catalog"] != testenv.ClusterCatalog || second["type"] != "Secondary" || second["catalog"] != testenv.ClusterCatalog || second["soa_primary"] != world.Domain(world.First) || !slices.Equal(acctest.Texts(first["name_servers"]), []string{world.Domain(world.First), world.Domain(world.Second)}) || !slices.Contains(acctest.Strs(t, out["differ"], "differ"), "type") {
			t.Errorf("%s = %v on %s and %v on %s, differing in %v", sharedZone, first, world.First, second, world.Second, out["differ"])
		}
	}

	// the zone given its mistakes: open to anyone, with a name server that is none of these
	open := suite.Call(t, "zone_get", map[string]any{"zone": setupZone})
	if got := acctest.Rows(t, open["servers"], "servers"); len(got) != 1 || got[0]["server"] != world.First || got[0]["transfer"] != "Allow" || got[0]["update"] != "Allow" || !slices.Contains(acctest.Texts(got[0]["name_servers"]), strangeNS) || (alone() != (open["missing_on"] == nil)) {
		t.Errorf("%s = %v", setupZone, open)
	}
	if msg := suite.CallErr(t, "zone_get", map[string]any{"zone": "acc-no-such-zone.test"}); !strings.Contains(msg, "no server asked holds a zone named acc-no-such-zone.test") {
		t.Errorf("a zone nobody holds = %q", msg)
	}

	// exported: from the one server that holds it as its own, with the comment one of its records has
	export := suite.Call(t, "zone_export", map[string]any{"zone": firstZone})
	if export["server"] != world.First || !strings.HasPrefix(acctest.Str(export["text"]), "$ORIGIN "+firstZone+".") || acctest.Num(t, export["lines"], "lines") < 3 || !strings.Contains(acctest.Str(export["text"]), "SOA") {
		t.Errorf("%s exported = %v", firstZone, export)
	}
	shared := suite.Call(t, "zone_export", on(map[string]any{"zone": sharedZone}))
	if text := acctest.Str(shared["text"]); shared["server"] != world.First || !strings.Contains(text, "10.0.0.4") || !strings.Contains(text, ";the docker host") || !strings.Contains(text, "CNAME") {
		t.Errorf("%s exported from %s = %v", sharedZone, world.First, shared)
	}
	if world.Topology == testenv.Pair {
		// two servers each holding it as their own: which is asked
		if msg := suite.CallErr(t, "zone_export", map[string]any{"zone": sharedZone}); !strings.Contains(msg, "each hold "+sharedZone+" as a zone of their own: say which to export from with server") {
			t.Errorf("a zone two hold as their own, exported from neither = %q", msg)
		}
	}
	paged := suite.Call(t, "zone_export", on(map[string]any{"zone": sharedZone, "limit": 2, "offset": 1}))
	if strings.Count(acctest.Str(paged["text"]), "\n") != 1 || !strings.Contains(acctest.Str(paged["note"]), "read on with offset 3") {
		t.Errorf("two lines of it = %v", paged)
	}

	// the audits: the name server that is none of these, and nothing else in zones made as they should be
	wrong, counts := findings(t, "audit_zones", map[string]any{"zone": "*"})
	stranger := one(t, wrong, "ns_unknown", setupZone)
	if !strings.Contains(acctest.Str(stranger["detail"]), setupZone+" names "+strangeNS+" as a name server of its own, which is the name of no server asked") || !slices.Equal(acctest.Texts(stranger["servers"]), []string{world.First}) {
		t.Errorf("the name server that is none of these = %v", stranger)
	}
	if len(wrong) != 1 {
		t.Errorf("audit_zones found %d things (%v), want the one: %v", len(wrong), counts, wrong)
	}

	// what is left open: the zone anyone may transfer and change, and a console over plain HTTP, which a cluster's nodes no longer have
	wrong, counts = findings(t, "audit_security", map[string]any{"zone": "*", "problems": []string{"transfer_open", "update_open", "console_plain", "default_password", "recursion_open", "token_unused"}})
	if f := one(t, wrong, "transfer_open", setupZone); !strings.Contains(acctest.Str(f["detail"]), "anyone who can reach the server may transfer "+setupZone+" whole") {
		t.Errorf("the zone anyone may transfer = %v", f)
	}
	if f := one(t, wrong, "update_open", setupZone); !strings.Contains(acctest.Str(f["detail"]), "with no key asked for") {
		t.Errorf("the zone anyone may change = %v", f)
	}
	want := 3
	if clustered() {
		want = 2
	}
	if len(wrong) != want || (acctest.NumOr0(counts["console_plain"]) == 1) == clustered() {
		t.Errorf("audit_security found %d things (%v) in the %s topology, want %d: %v", len(wrong), counts, world.Topology, want, wrong)
	}
}

// audit_split asks the outside - here the second server, or with one server
// itself - for the names of a zone the first holds: a name answered
// differently is the split working and is not found; the name the outside
// lacks, the one it gives a private address for and the one it alone has
// are; and the mirror's names are held against the zone's.
func TestAuditSplit(t *testing.T) {
	t.Parallel()

	names(t)
	resolver := world.Address(world.First)
	if !alone() {
		resolver = world.Address(world.Second)
	}
	out := suite.Call(t, "audit_split", map[string]any{"server": world.First, "zone": splitZone, "resolvers": []string{resolver}, "names": []string{"ext." + splitZone, "www." + splitZone}, "mirror": []string{splitZone + "=" + mirrorZone}})
	found, counts := acctest.Rows(t, out["findings"], "findings"), acctest.Object(t, out["counts"], "counts")
	if out["failed"] != nil || out["unread"] != nil || out["note"] != nil || out["internal"] != nil || !slices.Equal(acctest.Strs(t, out["asked"], "asked"), []string{world.First}) {
		t.Fatalf("audit_split could not read or ask everything: %v", out)
	}
	// the three names the zone holds, and the one given beside them that it does not
	if acctest.Num(t, out["outside"], "outside") != 4 {
		t.Errorf("%v names were asked of the outside, want 4", out["outside"])
	}

	// the mirror, whatever stands for the outside: one name alike, one elsewhere, one missing
	if f := one(t, found, "mirror_differs", "gone."+splitZone); !strings.Contains(acctest.Str(f["detail"]), "gone."+splitZone+" ends at 198.51.100.5, and gone."+mirrorZone+", which is meant to answer alike, ends at 198.51.100.99 when "+world.First+" is asked") || f["servers"] != nil {
		t.Errorf("the mirror's name that ends elsewhere = %v", f)
	}
	if f := one(t, found, "mirror_differs", "leak."+splitZone); !strings.Contains(acctest.Str(f["detail"]), "ends nowhere when "+world.First+" is asked (NxDomain)") {
		t.Errorf("the mirror's name that is missing = %v", f)
	}
	want := 2
	if !alone() {
		// the second server's own zone of the name is the outside's
		if f := one(t, found, "public_gone", "gone."+splitZone); !strings.Contains(acctest.Str(f["detail"]), "gone."+splitZone+" ends at 198.51.100.5 here and the outside has no address for it (NxDomain), though it has for other names of "+splitZone) {
			t.Errorf("the name the outside does not have = %v", f)
		}
		if f := one(t, found, "private_outside", "leak."+splitZone); !strings.Contains(acctest.Str(f["detail"]), "the outside is told leak."+splitZone+" is at 10.6.6.6, a private address") {
			t.Errorf("the private address the outside gives = %v", f)
		}
		if f := one(t, found, "no_override", "ext."+splitZone); !strings.Contains(acctest.Str(f["detail"]), "ext."+splitZone+" resolves outside to 203.0.113.7 and no zone here has a record for it") {
			t.Errorf("the name the outside alone has = %v", f)
		}
		want = 5
	}
	if len(found) != want || acctest.Num(t, out["total"], "total") != want {
		t.Errorf("audit_split found %d things (%v) in the %s topology, want %d: %v", len(found), counts, world.Topology, want, found)
	}
	if msg := suite.CallErr(t, "audit_split", map[string]any{"resolvers": []string{"not-an-address"}}); !strings.Contains(msg, "is not an address") {
		t.Errorf("a resolver by name = %q", msg)
	}
}

// A zone made, changed and, where there is a second server, copied there and
// resynced - each change first as a dry run, then read back from the server.
//
// It does not run beside the other tests: several of them read every zone a
// server lists, and a zone deleted between the listing and the reading is a
// zone they could not read.
//
//nolint:paralleltest // it makes and deletes a zone, which a test reading every zone beside it would list and then not find
func TestZoneChanges(t *testing.T) {
	names(t)
	first, err := world.Client(world.First)
	if err != nil {
		t.Fatal(err)
	}
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	holds := func(c *technitium.Client) *technitium.Zone {
		t.Helper()
		zones, listErr := c.Zones(ctx, technitium.ZoneFilter{})
		if listErr != nil {
			t.Fatal(listErr)
		}
		if i := slices.IndexFunc(zones, func(z technitium.Zone) bool { return z.Name == madeZone }); i >= 0 {
			return &zones[i]
		}

		return nil
	}
	t.Cleanup(func() {
		for _, srv := range world.Set.Every() {
			_ = srv.Client.DeleteZone(ctx, madeZone)
		}
	})

	// made: a dry run makes nothing; then a primary that names the server, read back; and made again it is found there
	dry := suite.Call(t, "zone_create", on(map[string]any{"zone": madeZone, "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have made " + madeZone + " on " + world.First + " as a Primary zone"}) || dry["after"] != nil || holds(first) != nil {
		t.Errorf("a dry run = %v, and the zone is there: %v", dry, holds(first) != nil)
	}
	made := suite.Call(t, "zone_create", on(map[string]any{"zone": strings.ToUpper(madeZone) + "."}))
	if after := acctest.Object(t, made["after"], "after"); made["zone"] != madeZone || !acctest.BoolOf(made["changed"]) || after["type"] != "Primary" || after["soa_primary"] != world.Domain(world.First) || !slices.Equal(acctest.Texts(after["name_servers"]), []string{world.Domain(world.First)}) || after["transfer"] != "AllowOnlyZoneNameServers" || holds(first) == nil {
		t.Errorf("made = %v", made)
	}
	if again := suite.Call(t, "zone_create", on(map[string]any{"zone": madeZone})); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 {
		t.Errorf("made again = %v", again)
	}
	if msg := suite.CallErr(t, "zone_create", on(map[string]any{"zone": madeZone, "type": "Forwarder", "forwarder": "10.9.9.9"})); !strings.Contains(msg, "holds "+madeZone+" already, as a Primary zone") {
		t.Errorf("made again as another type = %q", msg)
	}

	// changed: a dry run changes nothing; then its policies with their lists, its SOA, and off and on, each read back
	other := "10.9.9.9"
	if !alone() {
		other = world.Address(world.Second)
	}
	change := map[string]any{"zone": madeZone, "transfer": "usespecifiednetworkacl", "transfer_networks": []string{other}, "notify": "SpecifiedNameServers", "notify_servers": []string{other}, "soa_responsible": "ops@" + madeZone, "refresh": 600}
	dry = suite.Call(t, "zone_edit", on(map[string]any{"zone": madeZone, "transfer": "Allow", "dry_run": true}))
	if got, err := first.ZoneOptions(ctx, madeZone); err != nil || got.ZoneTransfer != "AllowOnlyZoneNameServers" || len(acctest.Strs(t, dry["changes"], "changes")) != 1 || !strings.Contains(acctest.Str(dry["note"]), "anyone who can reach the server may now transfer the zone whole") {
		t.Errorf("a dry run = %v, and the zone's transfer policy is %v, %v", dry, got.ZoneTransfer, err)
	}
	edited := suite.Call(t, "zone_edit", on(change))
	if after := acctest.Object(t, edited["after"], "after"); len(acctest.Strs(t, edited["changes"], "changes")) != 6 || after["transfer"] != "UseSpecifiedNetworkACL" || !slices.Equal(acctest.Texts(after["transfer_networks"]), []string{other}) || after["notify"] != "SpecifiedNameServers" || !slices.Equal(acctest.Texts(after["notify_servers"]), []string{other}) || after["soa_responsible"] != "ops@"+madeZone || acctest.Num(t, after["refresh"], "refresh") != 600 || after["soa_primary"] != world.Domain(world.First) || acctest.Object(t, edited["before"], "before")["transfer"] != "AllowOnlyZoneNameServers" {
		t.Errorf("changed = %v", edited)
	}
	if same := suite.Call(t, "zone_edit", on(change)); acctest.BoolOf(same["changed"]) || len(acctest.Strs(t, same["changes"], "changes")) != 0 {
		t.Errorf("changed to what it is = %v", same)
	}
	off := suite.Call(t, "zone_edit", on(map[string]any{"zone": madeZone, "disabled": true}))
	if !acctest.BoolOf(acctest.Object(t, off["after"], "after")["disabled"]) || !holds(first).Disabled {
		t.Errorf("switched off = %v", off)
	}
	if back := suite.Call(t, "zone_edit", on(map[string]any{"zone": madeZone, "disabled": false})); acctest.Object(t, back["after"], "after")["disabled"] != nil || holds(first).Disabled {
		t.Errorf("switched back on = %v", back)
	}
	if msg := suite.CallErr(t, "zone_edit", on(map[string]any{"zone": madeZone, "transfer": "Whoever"})); !strings.Contains(msg, `transfer "Whoever": it takes Allow`) {
		t.Errorf("a policy there is none of = %q", msg)
	}

	if alone() {
		// one server has nothing to copy a zone from: a zone of its own is refused, which is all there is to ask
		if msg := suite.CallErr(t, "zone_resync", map[string]any{"zone": madeZone}); !strings.Contains(msg, "holds "+madeZone+" as a Primary zone, which is no copy") {
			t.Errorf("a primary resynced = %q", msg)
		}

		return
	}

	// copied to the second server, which the first now lets transfer it: a secondary that says where it transfers from
	second, err := world.Client(world.Second)
	if err != nil {
		t.Fatal(err)
	}
	copied := suite.Call(t, "zone_create", map[string]any{"server": world.Second, "zone": madeZone, "type": "Secondary", "primary_addresses": []string{world.Address(world.First)}})
	if after := acctest.Object(t, copied["after"], "after"); after["type"] != "Secondary" || !slices.Equal(acctest.Texts(after["primary_addresses"]), []string{world.Address(world.First)}) || after["soa_primary"] != world.Domain(world.First) || holds(second) == nil {
		t.Errorf("copied = %v", copied)
	}
	// both hold it now, each said in zone_get; and a copy's SOA is not its own to change
	both := suite.Call(t, "zone_get", map[string]any{"zone": madeZone})
	if got := acctest.Rows(t, both["servers"], "servers"); len(got) != 2 || !slices.Contains(acctest.Strs(t, both["differ"], "differ"), "type") {
		t.Errorf("the zone on both = %v", both)
	}
	if msg := suite.CallErr(t, "zone_edit", map[string]any{"server": world.Second, "zone": madeZone, "soa_primary": "elsewhere.test"}); !strings.Contains(msg, "a copy: its SOA record is its primary's") {
		t.Errorf("a copy's SOA changed = %q", msg)
	}

	// a record added on the first, and the copy resynced: it has the record
	suite.Call(t, "record_set", on(map[string]any{"name": "late." + madeZone, "type": "A", "value": "10.4.4.9"}))
	dry = suite.Call(t, "zone_resync", map[string]any{"server": world.Second, "zone": madeZone, "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have asked " + world.Second + " to transfer its copy of " + madeZone + " from the primary again"}) {
		t.Errorf("a dry run of a resync = %v", dry)
	}
	resynced := suite.Call(t, "zone_resync", map[string]any{"server": world.Second, "zone": madeZone})
	if resynced["type"] != "Secondary" || resynced["server"] != world.Second || len(acctest.Strs(t, resynced["changes"], "changes")) != 1 {
		t.Errorf("resynced = %v", resynced)
	}
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		at, readErr := second.RecordsAt(ctx, "late."+madeZone, madeZone)

		return readErr == nil && len(at.Records) == 1 && at.Records[0].Value() == "10.4.4.9"
	}) {
		t.Errorf("%s's copy never had the record added on %s after it was resynced", world.Second, world.First)
	}
	if msg := suite.CallErr(t, "zone_resync", on(map[string]any{"zone": madeZone})); !strings.Contains(msg, "which is no copy") {
		t.Errorf("a primary resynced = %q", msg)
	}
}
