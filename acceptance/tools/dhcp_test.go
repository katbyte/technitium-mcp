//go:build acceptance

package tools_test

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

// The DHCP fixtures: one scope on the first server, over the end of the
// network the servers share, recording its leases in a zone the first server
// holds alone. Its leases are real ones: machines that asked for them (see
// testenv.World.Lease).
const (
	dhcpZone  = "leased.test"
	dhcpScope = "acc-lan"

	// the machines, by hardware address as the server writes one: three with
	// leases, of which the printer's is reserved; one that gave no name; and
	// reservations nobody holds, two of which could not work
	macPrinter  = "02-42-AC-CC-00-01"
	macLaptop   = "02-42-AC-CC-00-02"
	macNameless = "02-42-AC-CC-00-03"
	macPhone    = "02-42-AC-CC-00-04"
	macNAS      = "02-42-AC-CC-00-05"
	macBare     = "02-42-AC-CC-00-06"
	macTwin     = "02-42-AC-CC-00-07"
	macOutside  = "02-42-AC-CC-00-08"
	// the machines the test of the changes brings and takes away again
	macCam    = "02-42-AC-CC-00-20"
	macByHand = "02-42-AC-CC-00-21"
	macTemp   = "02-42-AC-CC-00-22"

	// an address no server here has, which the scope tells machines to resolve through
	strangerDNS = "10.99.99.99"

	// the scope the test of the changes makes, on a network no server here is on
	guestScope = "acc-guest"
)

// pool is the part of the servers' network the scope leases from: sixty
// addresses, the last ten of which the scope leaves out.
var pool testenv.Pool

// The addresses of the range the fixtures use, by what each is for.
const (
	atFixed    = 20 // a record made by hand, in the range
	atCam      = 30 // the test of the changes
	atByHand   = 31
	atPrinter  = 40 // reserved, and held
	atGone     = 45 // records the server is said to have written, for nothing that is there
	atStale    = 46
	atExcluded = 50 // the first address left out
	atNAS      = 55 // reserved in the part left out, with a name
	atBare     = 56 // reserved there with no name
	atLast     = 59
)

// makeDHCP gives the first server its scope, its reservations and its
// leases, and the records made by hand that the DHCP audit is there to find.
func makeDHCP(ctx context.Context, first *technitium.Client) error {
	dnsServers := []string{world.Address(world.First), strangerDNS}
	if err := first.SetScope(ctx, &technitium.NewScope{Name: dhcpScope, StartingAddress: pool.First.String(), EndingAddress: pool.Last.String(), SubnetMask: pool.Mask, DomainName: dhcpZone, DNSUpdates: new(true), RouterAddress: pool.Subnet.Addr().Next().String(), DNSServers: dnsServers, LeaseTimeDays: 1, Exclusions: [][2]string{{pool.At(atExcluded), pool.At(atLast)}}}); err != nil {
		return fmt.Errorf("%s: making the scope: %w", world.First, err)
	}
	byHand := func(name, address, comment string) error {
		if _, err := first.AddRecord(ctx, technitium.NewRecord{Zone: dhcpZone, Name: name + "." + dhcpZone, Type: "A", Comments: comment, Data: technitium.RData{"ipAddress": address}}); err != nil {
			return fmt.Errorf("%s: adding %s: %w", world.First, name, err)
		}

		return nil
	}

	// a name a machine is about to ask for, which a record made by hand has already
	if err := byHand("phone", "10.9.9.9", "by hand"); err != nil {
		return err
	}
	for _, r := range []technitium.Reservation{
		{HostName: "printer", HardwareAddress: macPrinter, Address: pool.At(atPrinter), Comments: "the printer"},
		{HostName: "nas", HardwareAddress: macNAS, Address: pool.At(atNAS)},
		{HardwareAddress: macBare, Address: pool.At(atBare)},
		// the server takes these two, and neither can work: an address reserved already, and one outside the network
		{HardwareAddress: macTwin, Address: pool.At(atPrinter)},
		{HardwareAddress: macOutside, Address: "10.1.1.1"},
	} {
		if err := first.AddReservation(ctx, dhcpScope, r); err != nil {
			return fmt.Errorf("%s: reserving %s: %w", world.First, r.Address, err)
		}
	}
	for _, m := range []struct{ mac, name string }{{macLaptop, "laptop"}, {macNameless, ""}, {macPhone, "phone"}, {macPrinter, "it-says-otherwise"}} {
		if err := world.Lease(ctx, strings.ReplaceAll(m.mac, "-", ":"), m.name); err != nil {
			return err
		}
	}

	laptop, err := leaseOf(ctx, first, macLaptop)
	if err != nil {
		return err
	}
	for _, rec := range []struct{ name, address, comment string }{
		{"fixed", pool.At(atFixed), "by hand"},
		{"squatter", laptop.Address, "by hand"},
		{"gone", pool.At(atGone), "Via 'acc-gone' DHCP scope"},
		{"stale", pool.At(atStale), "Via '" + dhcpScope + "' DHCP scope"},
	} {
		if err := byHand(rec.name, rec.address, rec.comment); err != nil {
			return err
		}
	}

	return nil
}

// leaseOf is the lease a machine holds on the first server, read through the
// client: what the tools' answers are held against.
func leaseOf(ctx context.Context, first *technitium.Client, mac string) (technitium.Lease, error) {
	leases, err := first.Leases(ctx)
	if err != nil {
		return technitium.Lease{}, err
	}
	for _, l := range leases {
		if l.HardwareAddress == mac {
			return l, nil
		}
	}

	return technitium.Lease{}, fmt.Errorf("%s holds no lease on %s", mac, world.First)
}

// leased are the rows dhcp_leases gives for the arguments, on the first
// server.
func leased(t *testing.T, args map[string]any) []map[string]any {
	t.Helper()

	args["server"] = world.First
	out := suite.Call(t, "dhcp_leases", args)
	if out["failed"] != nil {
		t.Errorf("dhcp_leases could not ask every server: %v", out["failed"])
	}

	return acctest.Rows(t, out["leases"], "leases")
}

// DHCP on servers that lease: the scopes side by side, the machines found by
// name, address and hardware address, what the audit finds in fixtures with
// one of each mistake, and then the changes - a reservation set, changed and
// removed and a lease forgotten, each first as a dry run, each read back from
// the server with the records the server keeps for it.
func TestDHCP(t *testing.T) {
	t.Parallel()

	servers := names(t)
	first, err := world.Client(world.First)
	if err != nil {
		t.Fatal(err)
	}
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	laptop, err := leaseOf(ctx, first, macLaptop)
	if err != nil {
		t.Fatal(err)
	}

	// the scopes: the one a server ships with on each, switched off, and the suite's on the first
	out := suite.Call(t, "dhcp_scopes", nil)
	rows := acctest.Rows(t, out["scopes"], "scopes")
	if len(rows) != len(servers)+1 || !slices.Equal(acctest.Strs(t, out["serving"], "serving"), []string{world.First}) || out["failed"] != nil {
		t.Fatalf("scopes = %v, serving %v", rows, out["serving"])
	}
	for _, row := range rows {
		if row["scope"] == "Default" && (acctest.BoolOf(row["enabled"]) || row["interface"] != nil || acctest.Num(t, row["leased"], "leased") != 0) {
			t.Errorf("the scope %s ships with = %v", row["server"], row)
		}
	}
	lan := rowFor(t, rows, "scope", dhcpScope)
	if lan["server"] != world.First || !acctest.BoolOf(lan["enabled"]) || lan["network"] != pool.Subnet.String() || lan["range"] != pool.First.String()+"-"+pool.Last.String() || !slices.Equal(acctest.Texts(lan["exclusions"]), []string{pool.At(atExcluded) + "-" + pool.At(atLast)}) || lan["interface"] != world.Address(world.First) || lan["lease_time"] != "1d" || lan["domain"] != dhcpZone || !acctest.BoolOf(lan["dns_updates"]) || lan["router"] != pool.Subnet.Addr().Next().String() || !slices.Equal(acctest.Texts(lan["dns_servers"]), []string{world.Address(world.First), strangerDNS}) || lan["only_reserved"] != nil {
		t.Errorf("%s = %v", dhcpScope, lan)
	}
	// sixty addresses less the ten left out; taken are the three dynamic leases and the printer's address
	if acctest.Num(t, lan["addresses"], "addresses") != 50 || acctest.Num(t, lan["free"], "free") != 46 || acctest.Num(t, lan["leased"], "leased") != 4 || acctest.Num(t, lan["reserved"], "reserved") != 5 {
		t.Errorf("%s's addresses = %v", dhcpScope, lan)
	}
	if byName := acctest.Rows(t, suite.Call(t, "dhcp_scopes", map[string]any{"scope": "acc-*"})["scopes"], "scopes"); len(byName) != 1 || byName[0]["scope"] != dhcpScope {
		t.Errorf("the scopes named acc-* = %v", byName)
	}

	// the machines: four leases, and the four reservations nobody holds
	all := suite.Call(t, "dhcp_leases", map[string]any{"scope": dhcpScope})
	counts := acctest.Object(t, all["counts"], "counts")
	if acctest.Num(t, all["total"], "total") != 8 || acctest.NumOr0(counts["dynamic"]) != 3 || acctest.NumOr0(counts["reserved"]) != 5 || acctest.NumOr0(counts["unclaimed"]) != 4 || all["failed"] != nil {
		t.Fatalf("leases = %v", all)
	}
	// found however the hardware address is written
	for _, written := range []string{macLaptop, strings.ToLower(strings.ReplaceAll(macLaptop, "-", ":")), strings.ReplaceAll(macLaptop, "-", "")} {
		got := leased(t, map[string]any{"find": written})
		if len(got) != 1 || got[0]["server"] != world.First || got[0]["scope"] != dhcpScope || got[0]["type"] != "Dynamic" || got[0]["address"] != laptop.Address || got[0]["hardware_address"] != macLaptop || got[0]["host_name"] != "laptop."+dhcpZone || !recent(t, got[0]["obtained"], time.Hour) || got[0]["unclaimed"] != nil {
			t.Errorf("the laptop, found by %s = %v", written, got)
		}
		if expires, err := time.Parse(time.RFC3339, acctest.Str(got[0]["expires"])); err != nil || time.Until(expires) < 23*time.Hour || time.Until(expires) > 25*time.Hour {
			t.Errorf("a day's lease expires %v", got[0]["expires"])
		}
	}
	// the reserved lease has the name and the comment of its reservation, not the name the machine gave
	if got := leased(t, map[string]any{"find": "printer*"}); len(got) != 1 || got[0]["type"] != "Reserved" || got[0]["address"] != pool.At(atPrinter) || got[0]["host_name"] != "printer."+dhcpZone || got[0]["comment"] != "the printer" || got[0]["unclaimed"] != nil {
		t.Errorf("the printer = %v", got)
	}
	// what has this address: the machine that holds it, and the other it is kept for
	if got := leased(t, map[string]any{"find": pool.At(atPrinter)}); len(got) != 2 || got[0]["hardware_address"] != macPrinter || got[1]["hardware_address"] != macTwin || !acctest.BoolOf(got[1]["unclaimed"]) || got[1]["expires"] != nil {
		t.Errorf("who has %s = %v", pool.At(atPrinter), got)
	}
	if got := leased(t, map[string]any{"type": "unclaimed", "scope": dhcpScope}); len(got) != 4 || got[0]["address"] != "10.1.1.1" || got[3]["address"] != pool.At(atBare) || got[2]["host_name"] != "nas."+dhcpZone {
		t.Errorf("the reservations nobody holds = %v", got)
	}
	if got := leased(t, map[string]any{"type": "dynamic", "limit": 2, "offset": 1}); len(got) != 2 || got[0]["hardware_address"] != macNameless || got[0]["host_name"] != nil {
		t.Errorf("the dynamic leases from the second = %v", got)
	}
	if !alone() {
		if none := suite.Call(t, "dhcp_leases", map[string]any{"server": world.Second}); acctest.Num(t, none["total"], "total") != 0 {
			t.Errorf("%s leases nothing, and lists %v", world.Second, none["leases"])
		}
	}

	// the audit: one of each mistake the fixtures hold, and nothing else
	wrong, counts := findings(t, "audit_dhcp", map[string]any{"zone": "*"})
	said := func(problem, at, detail string) {
		t.Helper()
		f := one(t, wrong, problem, at)
		if !strings.Contains(acctest.Str(f["detail"]), detail) || acctest.Str(f["fix"]) == "" {
			t.Errorf("%s at %s = %v, want it to say %q and how to put it right", problem, at, f, detail)
		}
		if got := acctest.Texts(f["servers"]); (alone() && len(got) != 0) || (!alone() && !slices.Equal(got, []string{world.First})) {
			t.Errorf("%s at %s is on %v", problem, at, got)
		}
	}
	said("reservation_shared", pool.At(atPrinter), pool.At(atPrinter)+" is kept for 2 machines on "+world.First+": "+macPrinter+" (printer), "+macTwin)
	said("reservation_leased_away", pool.At(atPrinter), "keeps "+pool.At(atPrinter)+" for "+macTwin+", and "+macPrinter+" (printer."+dhcpZone+") holds a lease on it until ")
	said("reservation_outside", "10.1.1.1", "keeps 10.1.1.1 for "+macOutside+", which is outside its network "+pool.Subnet.String())
	said("reservation_no_record", "10.1.1.1", "no record on "+world.First+" names that address")
	said("reservation_no_record", pool.At(atBare), "keeps "+pool.At(atBare)+" for "+macBare)
	said("static_in_pool", "fixed."+dhcpZone, "fixed."+dhcpZone+" holds "+pool.At(atFixed)+" by a record made by hand, and scope "+dhcpScope+" on "+world.First+" leases from "+pool.First.String()+"-"+pool.Last.String())
	said("address_leased_elsewhere", "squatter."+dhcpZone, "squatter."+dhcpZone+" holds "+laptop.Address+" by a record made by hand, and scope "+dhcpScope+" on "+world.First+" has leased that address to "+macLaptop+" (laptop."+dhcpZone+") until ")
	said("lease_name_taken", "phone."+dhcpZone, macPhone+" on "+world.First+" is leased ")
	said("record_left_behind", "gone."+dhcpZone, "was written by the DHCP scope acc-gone on "+world.First+", which is gone")
	said("record_left_behind", "stale."+dhcpZone, "was written by the DHCP scope "+dhcpScope+" on "+world.First+", which has no lease and no reservation for "+pool.At(atStale)+" now")
	said("scope_dns_unknown", dhcpScope, "tells machines to resolve through "+strangerDNS+", which is no address of a server asked")
	want := 11
	if !alone() {
		// the second server leases nothing, and no machine is told of it
		said("scope_dns_missing", dhcpScope, "and not through "+world.Second+" ("+world.Address(world.Second)+")")
		if i := slices.IndexFunc(wrong, func(f map[string]any) bool { return f["problem"] == "dhcp_one_server" }); i < 0 || !strings.Contains(acctest.Str(wrong[i]["detail"]), world.First+" alone leases addresses, and "+world.Second+" has no scope switched on") {
			t.Errorf("one server leasing alone was not found among %v", wrong)
		}
		want = 13
	}
	if len(wrong) != want {
		t.Errorf("audit_dhcp found %d things (%v), want %d: %v", len(wrong), counts, want, wrong)
	}

	reserved := func(mac string) *technitium.Reservation {
		t.Helper()
		scope, scopeErr := first.Scope(ctx, dhcpScope)
		if scopeErr != nil {
			t.Fatal(scopeErr)
		}
		for i := range scope.ReservedLeases {
			if scope.ReservedLeases[i].HardwareAddress == mac {
				return &scope.ReservedLeases[i]
			}
		}

		return nil
	}
	// recorded are the addresses the first server's zone holds at a name, read through the client
	recorded := func(name string) []string {
		t.Helper()
		at, readErr := first.RecordsAt(ctx, name+"."+dhcpZone, dhcpZone)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var out []string
		for i := range at.Records {
			if at.Records[i].Type == "A" {
				out = append(out, at.Records[i].Name+" A "+at.Records[i].Value())
			}
		}

		return out
	}
	t.Cleanup(func() {
		for _, mac := range []string{macCam, macByHand, macTemp} {
			_ = first.RemoveLease(ctx, dhcpScope, mac)
			_ = first.RemoveReservation(ctx, dhcpScope, mac)
		}
	})

	// a reservation: a dry run changes nothing
	cam := map[string]any{"hardware_address": strings.ToLower(strings.ReplaceAll(macCam, "-", ":")), "address": pool.At(atCam), "host_name": "cam", "comment": "the camera"}
	dry := suite.Call(t, "dhcp_reservation_set", on(map[string]any{"hardware_address": cam["hardware_address"], "address": cam["address"], "host_name": "cam", "comment": "the camera", "dry_run": true}))
	if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != 2 || got[0] != "would have reserved "+pool.At(atCam)+" for "+macCam+" (cam) in scope "+dhcpScope || !acctest.BoolOf(dry["changed"]) || dry["after"] != nil || reserved(macCam) != nil {
		t.Errorf("a dry run = %v, and the server holds %v", dry, reserved(macCam))
	}
	// set: read back, with the records the server wrote for it itself
	set := suite.Call(t, "dhcp_reservation_set", on(cam))
	if after := acctest.Object(t, set["after"], "after"); set["scope"] != dhcpScope || set["before"] != nil || after["hardware_address"] != macCam || after["address"] != pool.At(atCam) || after["host_name"] != "cam" || after["comment"] != "the camera" {
		t.Errorf("set = %v", set)
	}
	if records := acctest.Rows(t, set["records"], "records"); len(records) != 2 || records[0]["name"] != "cam."+dhcpZone || records[0]["value"] != pool.At(atCam) || records[0]["comment"] != "Via '"+dhcpScope+"' DHCP scope" || records[1]["type"] != "PTR" || records[1]["value"] != "cam."+dhcpZone {
		t.Errorf("the records the server keeps for it = %v", set["records"])
	}
	if r := reserved(macCam); r == nil || r.Address != pool.At(atCam) || r.HostName != "cam" || r.Comments != "the camera" {
		t.Errorf("the server holds %+v", r)
	}
	// again: already so
	if again := suite.Call(t, "dhcp_reservation_set", on(cam)); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 {
		t.Errorf("set again = %v", again)
	}
	// its comment alone: the rest is kept, the records with it
	changed := suite.Call(t, "dhcp_reservation_set", on(map[string]any{"hardware_address": macCam, "comment": "moved"}))
	if before, after := acctest.Object(t, changed["before"], "before"), acctest.Object(t, changed["after"], "after"); before["comment"] != "the camera" || after["comment"] != "moved" || after["address"] != pool.At(atCam) || after["host_name"] != "cam" || len(acctest.Rows(t, changed["records"], "records")) != 2 {
		t.Errorf("its comment changed = %v", changed)
	}

	// what the server would take and could not work is refused, and nothing is changed
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"an address kept for another machine": {map[string]any{"hardware_address": macByHand, "address": pool.At(atCam)}, pool.At(atCam) + " is kept for " + macCam + " (cam) in scope " + dhcpScope + " already"},
		"an address another machine holds":    {map[string]any{"hardware_address": macByHand, "address": laptop.Address}, laptop.Address + " is held by " + macLaptop + " (laptop." + dhcpZone + ") until "},
		"an address outside the network":      {map[string]any{"hardware_address": macByHand, "address": "10.1.1.2", "scope": dhcpScope}, "10.1.1.2 is outside " + pool.Subnet.String() + ", the network of scope " + dhcpScope},
		"the server's own address":            {map[string]any{"hardware_address": macByHand, "address": world.Address(world.First)}, world.Address(world.First) + " is " + world.First + "'s own address on the network"},
	} {
		if msg := suite.CallErr(t, "dhcp_reservation_set", on(refused.args)); !strings.Contains(msg, refused.with) || !strings.Contains(msg, "Nothing was changed") {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
	if reserved(macByHand) != nil {
		t.Errorf("a refused reservation was made: %+v", reserved(macByHand))
	}

	// a name a record made by hand has: the dry run says the server writes over it, and it does
	suite.Call(t, "record_set", on(map[string]any{"name": "byhand." + dhcpZone, "type": "A", "value": "10.9.9.8", "comment": "by hand"}))
	over := map[string]any{"hardware_address": macByHand, "address": pool.At(atByHand), "host_name": "byhand"}
	dry = suite.Call(t, "dhcp_reservation_set", on(map[string]any{"hardware_address": macByHand, "address": pool.At(atByHand), "host_name": "byhand", "dry_run": true}))
	if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != 3 || got[1] != "would have had the server write over A 10.9.9.8 at byhand."+dhcpZone+", as it does for a reservation's name" {
		t.Errorf("a dry run over a record made by hand = %v", got)
	}
	if got := recorded("byhand"); !slices.Equal(got, []string{"byhand." + dhcpZone + " A 10.9.9.8"}) {
		t.Errorf("after the dry run the name holds %v", got)
	}
	suite.Call(t, "dhcp_reservation_set", on(over))
	if got := recorded("byhand"); !slices.Equal(got, []string{"byhand." + dhcpZone + " A " + pool.At(atByHand)}) {
		t.Errorf("the name holds %v: the server no longer writes a reservation's name over a record made by hand, and dhcp_reservation_set says it does", got)
	}

	// the camera takes its lease, and the server is made to forget it: the reservation stays, though the server drops it with the lease
	if err := world.Lease(ctx, strings.ReplaceAll(macCam, "-", ":"), "cam-says-otherwise"); err != nil {
		t.Fatal(err)
	}
	if got := leased(t, map[string]any{"find": macCam}); len(got) != 1 || got[0]["type"] != "Reserved" || got[0]["address"] != pool.At(atCam) || got[0]["comment"] != "moved" {
		t.Fatalf("the camera's lease = %v", got)
	}
	dry = suite.Call(t, "dhcp_lease_delete", on(map[string]any{"address": pool.At(atCam), "dry_run": true}))
	if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != 2 || !strings.HasPrefix(got[0], "would have had "+world.First+" forget the lease of "+pool.At(atCam)+" to "+macCam) || len(leased(t, map[string]any{"find": macCam})) != 1 {
		t.Errorf("a dry run of forgetting a lease = %v", dry)
	}
	forgot := suite.Call(t, "dhcp_lease_delete", on(map[string]any{"address": pool.At(atCam)}))
	if got := acctest.Strs(t, forgot["changes"], "changes"); len(got) != 2 || got[1] != "put back the reservation of "+pool.At(atCam)+" for the machine, which the server dropped with its lease" {
		t.Errorf("forgetting a reserved lease = %v: the server no longer drops the reservation with it, or the tool no longer puts it back", forgot)
	}
	if removed := acctest.Object(t, forgot["removed"], "removed"); removed["type"] != "Reserved" || removed["hardware_address"] != macCam || acctest.Object(t, forgot["reservation"], "reservation")["comment"] != "moved" {
		t.Errorf("forgot = %v", forgot)
	}
	if r, got := reserved(macCam), leased(t, map[string]any{"find": macCam}); r == nil || r.Comments != "moved" || r.HostName != "cam" || len(got) != 1 || !acctest.BoolOf(got[0]["unclaimed"]) {
		t.Errorf("after its lease was forgotten the camera's reservation = %+v and its row = %v", r, got)
	}
	if got := recorded("cam"); !slices.Equal(got, []string{"cam." + dhcpZone + " A " + pool.At(atCam)}) {
		t.Errorf("the camera's record after its lease was forgotten = %v", got)
	}

	// the reservation removed: as it was, with the records the server took away with it
	dry = suite.Call(t, "dhcp_reservation_delete", on(map[string]any{"hardware_address": macCam, "dry_run": true}))
	if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != 3 || got[1] != "would have removed A "+pool.At(atCam)+" at cam."+dhcpZone+", which the server takes away with the reservation" || reserved(macCam) == nil {
		t.Errorf("a dry run of removing a reservation = %v", dry)
	}
	gone := suite.Call(t, "dhcp_reservation_delete", on(map[string]any{"address": pool.At(atCam)}))
	if removed := acctest.Object(t, gone["removed"], "removed"); removed["hardware_address"] != macCam || removed["host_name"] != "cam" || removed["comment"] != "moved" || gone["records"] != nil || gone["note"] != nil {
		t.Errorf("removed = %v", gone)
	}
	if got := acctest.Strs(t, gone["changes"], "changes"); len(got) != 3 || got[1] != "removed A "+pool.At(atCam)+" at cam."+dhcpZone+", which the server took away with the reservation" || !strings.HasPrefix(got[2], "removed PTR cam."+dhcpZone) {
		t.Errorf("changes = %v", got)
	}
	if reserved(macCam) != nil || len(recorded("cam")) != 0 || len(leased(t, map[string]any{"find": macCam})) != 0 {
		t.Errorf("after the removal: reservation %+v, records %v", reserved(macCam), recorded("cam"))
	}
	if msg := suite.CallErr(t, "dhcp_reservation_delete", on(map[string]any{"hardware_address": macCam})); !strings.Contains(msg, "keeps no such reservation") {
		t.Errorf("removing it again = %q", msg)
	}
	suite.Call(t, "dhcp_reservation_delete", on(map[string]any{"hardware_address": macByHand, "scope": dhcpScope}))

	// a dynamic lease: forgotten, with the record the server kept for it
	if err := world.Lease(ctx, strings.ReplaceAll(macTemp, "-", ":"), "temp"); err != nil {
		t.Fatal(err)
	}
	temp, err := leaseOf(ctx, first, macTemp)
	if err != nil {
		t.Fatal(err)
	}

	// the lease made a reservation where it stands, found by the machine's name, and made ordinary again: a dry run changes nothing, and asked again there is nothing to do
	dry = suite.Call(t, "dhcp_lease_reserve", on(map[string]any{"machine": "temp", "dry_run": true}))
	if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != 1 || !strings.HasPrefix(got[0], "would have made the lease of "+temp.Address+" to "+macTemp) || dry["type"] != "Dynamic" || reserved(macTemp) != nil {
		t.Errorf("a dry run of reserving a lease = %v", dry)
	}
	kept := suite.Call(t, "dhcp_lease_reserve", on(map[string]any{"machine": "temp"}))
	if r := reserved(macTemp); kept["type"] != "Reserved" || kept["address"] != temp.Address || kept["machine"] != macTemp || kept["scope"] != dhcpScope || r == nil || r.Address != temp.Address {
		t.Errorf("the lease reserved = %v, and the reservation %+v", kept, r)
	}
	if again := suite.Call(t, "dhcp_lease_reserve", on(map[string]any{"machine": temp.Address})); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 {
		t.Errorf("reserved twice = %v", again)
	}
	freed := suite.Call(t, "dhcp_lease_reserve", on(map[string]any{"machine": strings.ToLower(macTemp), "scope": dhcpScope, "reserved": false}))
	if freed["type"] != "Dynamic" || reserved(macTemp) != nil || !strings.Contains(acctest.Strs(t, freed["changes"], "changes")[0], "removing the reservation") {
		t.Errorf("the lease made ordinary again = %v, and the reservation %+v", freed, reserved(macTemp))
	}
	if msg := suite.CallErr(t, "dhcp_lease_reserve", on(map[string]any{"machine": "02-42-AC-CC-00-99"})); !strings.Contains(msg, "has given no lease to 02-42-AC-CC-00-99") {
		t.Errorf("a machine that holds no lease = %q", msg)
	}

	forgot = suite.Call(t, "dhcp_lease_delete", on(map[string]any{"hardware_address": macTemp}))
	if got := acctest.Strs(t, forgot["changes"], "changes"); len(got) != 3 || got[1] != "removed A "+temp.Address+" at temp."+dhcpZone+", which the server took away with the lease" || forgot["reservation"] != nil || forgot["records"] != nil {
		t.Errorf("forgetting a dynamic lease = %v", forgot)
	}
	if _, err := leaseOf(ctx, first, macTemp); err == nil || len(recorded("temp")) != 0 {
		t.Errorf("after it was forgotten the lease is still there (%v), or its record %v", err == nil, recorded("temp"))
	}
	if msg := suite.CallErr(t, "dhcp_lease_delete", on(map[string]any{"hardware_address": macTemp})); !strings.Contains(msg, "holds no such lease") {
		t.Errorf("forgetting it again = %q", msg)
	}

	// a scope made: a dry run makes none; made, it is left switched off; and made again it is found so
	t.Cleanup(func() {
		for _, srv := range world.Set.Every() {
			_ = srv.Client.DeleteScope(ctx, guestScope)
		}
	})
	scopeOn := func(c *technitium.Client) (there, enabled bool) {
		t.Helper()
		scopes, err := c.Scopes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(scopes, func(s technitium.Scope) bool { return s.Name == guestScope })

		return i >= 0, i >= 0 && scopes[i].Enabled
	}
	guest := map[string]any{"scope": guestScope, "first": "10.77.0.10", "last": "10.77.0.50", "mask": "24", "lease_time": "12h", "domain": "guest." + dhcpZone, "router": "10.77.0.1", "dns_servers": []string{world.Address(world.First)}, "exclusions": []string{"10.77.0.40-10.77.0.50"}}
	dry = suite.Call(t, "dhcp_scope_set", on(map[string]any{"scope": guestScope, "first": "10.77.0.10", "last": "10.77.0.50", "mask": "24", "dry_run": true}))
	if there, _ := scopeOn(first); there || len(acctest.Strs(t, dry["changes"], "changes")) != 2 || dry["after"] != nil {
		t.Errorf("a dry run = %v, and the scope is there: %v", dry, there)
	}
	made := suite.Call(t, "dhcp_scope_set", on(guest))
	if after := acctest.Object(t, made["after"], "after"); made["before"] != nil || acctest.BoolOf(after["enabled"]) || after["network"] != "10.77.0.0/24" || after["range"] != "10.77.0.10-10.77.0.50" || after["lease_time"] != "12h" || after["domain"] != "guest."+dhcpZone || after["router"] != "10.77.0.1" || !slices.Equal(acctest.Texts(after["exclusions"]), []string{"10.77.0.40-10.77.0.50"}) || acctest.Num(t, after["addresses"], "addresses") != 30 {
		t.Errorf("made = %v", made)
	}
	if there, enabled := scopeOn(first); !there || enabled {
		t.Errorf("the scope that was made is there: %v, and switched on: %v, want it there and off", there, enabled)
	}
	if again := suite.Call(t, "dhcp_scope_set", on(guest)); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 {
		t.Errorf("made again = %v", again)
	}
	// one thing of it changed, with the rest as it was; then switched on, on a network the server has no address in
	changed = suite.Call(t, "dhcp_scope_set", on(map[string]any{"scope": guestScope, "lease_time": "2d", "only_reserved": true}))
	if after := acctest.Object(t, changed["after"], "after"); after["lease_time"] != "2d" || !acctest.BoolOf(after["only_reserved"]) || after["router"] != "10.77.0.1" || after["domain"] != "guest."+dhcpZone || acctest.Object(t, changed["before"], "before")["lease_time"] != "12h" {
		t.Errorf("its lease time changed = %v", changed)
	}
	switched := suite.Call(t, "dhcp_scope_set", on(map[string]any{"scope": guestScope, "enabled": true}))
	if _, enabled := scopeOn(first); !enabled || !acctest.BoolOf(acctest.Object(t, switched["after"], "after")["enabled"]) || !strings.Contains(acctest.Str(switched["note"]), world.First+" has no address of its own in 10.77.0.0/24") {
		t.Errorf("switched on = %v", switched)
	}
	if msg := suite.CallErr(t, "dhcp_scope_set", on(map[string]any{"scope": "acc-over", "first": pool.At(5), "last": pool.At(15), "mask": pool.Mask})); !strings.Contains(msg, "runs into that of scope "+dhcpScope+" on "+world.First) {
		t.Errorf("a scope over another's range = %q", msg)
	}
	if !alone() {
		// on the second server: over what the first leases it is refused when it is to be on, and made when it is left off
		over := map[string]any{"server": world.Second, "scope": guestScope, "first": pool.At(0), "last": pool.At(20), "mask": pool.Mask, "enabled": true}
		if msg := suite.CallErr(t, "dhcp_scope_set", over); !strings.Contains(msg, world.First+" leases "+pool.At(0)+"-"+pool.At(20)+" from its scope "+dhcpScope+", which is on, and this scope would lease the same") {
			t.Errorf("a scope on the second server over what the first leases = %q", msg)
		}
		second, err := world.Client(world.Second)
		if err != nil {
			t.Fatal(err)
		}
		delete(over, "enabled")
		spare := suite.Call(t, "dhcp_scope_set", over)
		if there, enabled := scopeOn(second); !there || enabled || acctest.BoolOf(acctest.Object(t, spare["after"], "after")["enabled"]) {
			t.Errorf("the same scope left off = %v, there: %v, on: %v", spare, there, enabled)
		}
	}
	off := suite.Call(t, "dhcp_scope_set", on(map[string]any{"scope": guestScope, "enabled": false}))
	if _, enabled := scopeOn(first); enabled || acctest.BoolOf(acctest.Object(t, off["after"], "after")["enabled"]) {
		t.Errorf("switched off = %v", off)
	}

	// and deleted: a dry run says what would go and leaves it; then it is gone, and a scope that is not there is said to be
	dry = suite.Call(t, "dhcp_scope_delete", on(map[string]any{"scope": guestScope, "dry_run": true}))
	if there, _ := scopeOn(first); !there || !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have deleted the scope " + guestScope + " on " + world.First + " with its 0 reservations and 0 leases"}) {
		t.Errorf("a dry run of deleting a scope = %v", dry)
	}
	deleted := suite.Call(t, "dhcp_scope_delete", on(map[string]any{"scope": guestScope}))
	if there, _ := scopeOn(first); there || !acctest.BoolOf(deleted["changed"]) || deleted["note"] != nil {
		t.Errorf("the scope deleted = %v", deleted)
	}
	if msg := suite.CallErr(t, "dhcp_scope_delete", on(map[string]any{"scope": guestScope})); !strings.Contains(msg, "has no scope named "+guestScope) {
		t.Errorf("a scope that is not there, deleted = %q", msg)
	}
}
