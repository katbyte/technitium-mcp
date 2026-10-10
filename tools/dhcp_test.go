package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// The reservations the LAN scope starts with in dhcpPair, by the machine
// each is for.
var lanReserved = map[string]string{
	"emby":    reservedJSON("AA-00-00-00-00-01", "10.20.0.4", "emby", "the emby vm"),
	"nas":     reservedJSON("AA-00-00-00-00-02", "10.20.0.30", "nas", ""),
	"twin":    reservedJSON("AA-00-00-00-00-05", "10.20.0.40", "twin", ""),
	"twin2":   reservedJSON("AA-00-00-00-00-06", "10.20.0.40", "", ""),
	"printer": reservedJSON("AA-00-00-00-00-07", "10.20.0.50", "printer", ""),
}

// The leases dock holds on the LAN scope in dhcpPair.
var lanLeases = map[string]string{
	"emby":   leaseJSON("LAN", "Reserved", "AA-00-00-00-00-01", "10.20.0.4", "emby.lan.example"),
	"laptop": leaseJSON("LAN", "Dynamic", "AA-00-00-00-00-10", "10.20.0.100", "laptop.lan.example"),
}

// lanScope makes dock answer for its LAN scope with these reservations, and
// lanLeased for its leases with these.
func lanScope(p *pair, reserved ...string) {
	p.dock.AnswerWhen("dhcp/scopes/get", "name", "LAN", scopeJSON("LAN", "10.20.0.100", "10.20.0.119", lanScopeOptions, reserved...))
}

func lanLeased(p *pair, leases ...string) {
	p.dock.Answer("dhcp/leases/list", `{"leases":[`+strings.Join(leases, ",")+`]}`)
}

// dhcpPair is two servers for the changes to DHCP: dock leases on its LAN
// and holds the zone the scope records names in and the reverse zone for its
// addresses; rpi leases nothing.
func dhcpPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	auditDHCPOf(p)
	lanScope(p, lanReserved["emby"], lanReserved["nas"], lanReserved["twin"], lanReserved["twin2"], lanReserved["printer"])
	lanLeased(p, lanLeases["emby"], lanLeases["laptop"])
	p.dock.Answer("zones/list", `{"zones":[{"name":"lan.example","type":"Primary","soaSerial":4},{"name":"0.20.10.in-addr.arpa","type":"Primary","soaSerial":2}]}`)
	// what each call answers when a test does not say otherwise
	p.dock.Answer("zones/records/get", `{"zone":{"name":"lan.example"},"records":[]}`)
	at(p.dock, "emby.lan.example", addr("emby.lan.example", "10.20.0.4", byLAN))
	at(p.dock, "4.0.20.10.in-addr.arpa", rec("4.0.20.10.in-addr.arpa", "PTR", `{"ptrName":"emby.lan.example"}`, byLAN))
	at(p.dock, "laptop.lan.example", addr("laptop.lan.example", "10.20.0.100", byLAN))
	at(p.dock, "dock.lan.example", addr("dock.lan.example", "10.20.0.2", `"comments":"by hand"`))
	for _, path := range dhcpWrites {
		p.dock.Answer(path, `{}`)
	}

	return p
}

var dhcpWrites = []string{"dhcp/scopes/addReservedLease", "dhcp/scopes/removeReservedLease", "dhcp/leases/remove", "dhcp/scopes/set", "dhcp/scopes/delete"}

// dhcpWritten are the calls a server was sent that change its DHCP, in the
// order of dhcpWrites.
func dhcpWritten(server *technitiumtest.Server) []string {
	var out []string
	for _, path := range dhcpWrites {
		for _, req := range server.Requests(path) {
			out = append(out, strings.TrimPrefix(strings.TrimPrefix(path, "dhcp/scopes/"), "dhcp/")+" "+req.Params.Get("hardwareAddress")+" "+req.Params.Get("ipAddress"))
		}
	}

	return out
}

// Each server's scopes side by side, with what is free, and which servers
// lease at all.
func TestDHCPScopes(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	auditDHCPOf(p)
	suite := p.session(t, Options{})

	out := suite.Call(t, "dhcp_scopes", nil)
	rows := acctest.Rows(t, out["scopes"], "scopes")
	if len(rows) != 4 || !slices.Equal(acctest.Strs(t, out["serving"], "serving"), []string{"dock"}) || out["failed"] != nil {
		t.Fatalf("scopes = %v", out)
	}
	if d := rows[0]; d["server"] != "dock" || d["scope"] != "Default" || acctest.BoolOf(d["enabled"]) || d["interface"] != nil || d["network"] != "192.168.1.0/24" || acctest.Num(t, d["addresses"], "addresses") != 254 || acctest.Num(t, d["free"], "free") != 254 || !slices.Equal(acctest.Texts(d["dns_servers"]), []string{"this server"}) {
		t.Errorf("the scope a server ships with = %v", d)
	}
	lan := rows[1]
	if lan["scope"] != "LAN" || !acctest.BoolOf(lan["enabled"]) || lan["network"] != "10.20.0.0/24" || lan["range"] != "10.20.0.100-10.20.0.119" || !slices.Equal(acctest.Texts(lan["exclusions"]), []string{"10.20.0.118-10.20.0.119"}) || lan["interface"] != "10.20.0.2" || lan["lease_time"] != "1d" || lan["domain"] != "lan.example" || !acctest.BoolOf(lan["dns_updates"]) || lan["router"] != "10.20.0.1" || !slices.Equal(acctest.Texts(lan["dns_servers"]), []string{"10.20.0.2", "9.9.9.9"}) {
		t.Errorf("LAN = %v", lan)
	}
	// 20 addresses less the 2 left out; three leases are in the range, and no reservation is
	if acctest.Num(t, lan["addresses"], "addresses") != 18 || acctest.Num(t, lan["free"], "free") != 15 || acctest.Num(t, lan["leased"], "leased") != 5 || acctest.Num(t, lan["reserved"], "reserved") != 7 {
		t.Errorf("LAN's addresses = %v", lan)
	}
	if lab := rows[2]; lab["scope"] != "Lab" || acctest.Num(t, lab["addresses"], "addresses") != 10 || acctest.Num(t, lab["free"], "free") != 1 || acctest.Num(t, lab["leased"], "leased") != 9 || lab["dns_updates"] != nil {
		t.Errorf("Lab = %v", lab)
	}
	if rows[3]["server"] != "rpi" || rows[3]["scope"] != "Default" {
		t.Errorf("rpi's = %v", rows[3])
	}

	// by name: who serves is still said of every scope
	named := suite.Call(t, "dhcp_scopes", map[string]any{"scope": "la?"})
	if got := acctest.Rows(t, named["scopes"], "scopes"); len(got) != 2 || got[0]["scope"] != "LAN" || got[1]["scope"] != "Lab" || !slices.Equal(acctest.Strs(t, named["serving"], "serving"), []string{"dock"}) {
		t.Errorf("la? = %v", named)
	}

	// a server that cannot be asked is said beside the other's
	p.rpi.Fail("dhcp/scopes/list", "error", "Access was denied.")
	denied := suite.Call(t, "dhcp_scopes", nil)
	if failed := acctest.Rows(t, denied["failed"], "failed"); len(failed) != 1 || failed[0]["server"] != "rpi" || len(acctest.Rows(t, denied["scopes"], "scopes")) != 3 {
		t.Errorf("with rpi refusing = %v", denied)
	}
	p.dock.Fail("dhcp/scopes/list", "error", "Access was denied.")
	if msg := suite.CallErr(t, "dhcp_scopes", nil); !strings.Contains(msg, "dock: dhcp/scopes/list: Access was denied.") {
		t.Errorf("with both refusing = %q", msg)
	}
}

// Every lease and every reservation nobody holds, found by name, address or
// hardware address however written.
func TestDHCPLeases(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	auditDHCPOf(p)
	suite := p.session(t, Options{})

	out := suite.Call(t, "dhcp_leases", nil)
	rows := acctest.Rows(t, out["leases"], "leases")
	counts := acctest.Object(t, out["counts"], "counts")
	// 5 leases on LAN and 9 on Lab, and the 6 of LAN's 7 reservations that no machine holds
	if len(rows) != 20 || acctest.Num(t, out["total"], "total") != 20 || acctest.NumOr0(counts["dynamic"]) != 13 || acctest.NumOr0(counts["reserved"]) != 7 || acctest.NumOr0(counts["unclaimed"]) != 6 || out["note"] != nil {
		t.Fatalf("leases = %d, %v", len(rows), out["counts"])
	}
	// scope by scope, in the order of the addresses
	if rows[0]["scope"] != "Lab" || rows[0]["address"] != "10.20.5.10" || rows[8]["address"] != "10.20.5.18" || rows[9]["scope"] != "LAN" || rows[9]["address"] != "10.9.9.9" || rows[10]["address"] != "10.20.0.4" || rows[19]["address"] != "10.20.0.102" {
		t.Errorf("the order = %v", rows)
	}

	// a machine by its hardware address, however written
	for _, written := range []string{"aa:00:00:00:00:01", "AA-00-00-00-00-01", "aa0000000001", "AA00.0000.0001"} {
		got := acctest.Rows(t, suite.Call(t, "dhcp_leases", map[string]any{"find": written})["leases"], "leases")
		if len(got) != 1 || got[0]["server"] != "dock" || got[0]["type"] != "Reserved" || got[0]["address"] != "10.20.0.4" || got[0]["hardware_address"] != "AA-00-00-00-00-01" || got[0]["host_name"] != "emby.lan.example" || got[0]["obtained"] != "2026-10-09T17:52:51Z" || got[0]["expires"] != "2026-10-10T17:52:51Z" || got[0]["comment"] != "the emby vm" || got[0]["unclaimed"] != nil {
			t.Errorf("found by %s = %v", written, got)
		}
	}
	// what has this address: the machine that holds it, and the one it is kept for
	got := acctest.Rows(t, suite.Call(t, "dhcp_leases", map[string]any{"find": "10.20.0.50"})["leases"], "leases")
	if len(got) != 2 || got[0]["hardware_address"] != "AA-00-00-00-00-07" || !acctest.BoolOf(got[0]["unclaimed"]) || got[0]["host_name"] != "printer.lan.example" || got[0]["type"] != "Reserved" || got[0]["expires"] != nil || got[1]["hardware_address"] != "AA-00-00-00-00-99" || got[1]["type"] != "Dynamic" {
		t.Errorf("who has 10.20.0.50 = %v", got)
	}

	// by name, kind and scope, with a limit
	named := suite.Call(t, "dhcp_leases", map[string]any{"find": "*.lan.example", "type": "Dynamic"})
	if acctest.Num(t, named["total"], "total") != 3 || len(acctest.Object(t, named["counts"], "counts")) != 1 {
		t.Errorf("the dynamic leases with a name = %v", named)
	}
	if unclaimed := suite.Call(t, "dhcp_leases", map[string]any{"type": "unclaimed"}); acctest.Num(t, unclaimed["total"], "total") != 6 {
		t.Errorf("unclaimed = %v", unclaimed)
	}
	paged := suite.Call(t, "dhcp_leases", map[string]any{"scope": "lab", "limit": 4, "offset": 2})
	if got := acctest.Rows(t, paged["leases"], "leases"); len(got) != 4 || got[0]["address"] != "10.20.5.12" || acctest.Num(t, paged["total"], "total") != 9 || !strings.Contains(acctest.Str(paged["note"]), "9 leases matched and 4 are given, starting at the 3rd: read on with offset 6") {
		t.Errorf("paged = %v", paged)
	}
	if none := suite.Call(t, "dhcp_leases", map[string]any{"server": "rpi"}); len(acctest.Rows(t, none["leases"], "leases")) != 0 || acctest.Num(t, none["total"], "total") != 0 {
		t.Errorf("rpi's = %v", none)
	}
	if msg := suite.CallErr(t, "dhcp_leases", map[string]any{"type": "static"}); !strings.Contains(msg, "it takes dynamic, reserved or unclaimed") {
		t.Errorf("a kind there is none of = %q", msg)
	}
}

// A reservation is added, left alone when it is already so, and replaced
// when it differs; the answer is the reservation before and after, read
// back, with the records the server keeps for it.
func TestDHCPReservationSet(t *testing.T) {
	t.Parallel()

	p := dhcpPair(t)
	suite := p.session(t, everything)
	all := []string{lanReserved["emby"], lanReserved["nas"], lanReserved["twin"], lanReserved["twin2"], lanReserved["printer"]}

	// added: the scope is read, written to, and read back with the record the server made
	p.dock.Then("dhcp/scopes/addReservedLease", func(technitiumtest.Request) {
		lanScope(p, append(slices.Clone(all), reservedJSON("AA-00-00-00-00-20", "10.20.0.60", "cam", "the camera"))...)
		at(p.dock, "cam.lan.example", addr("cam.lan.example", "10.20.0.60", byLAN))
	})
	out := suite.Call(t, "dhcp_reservation_set", map[string]any{"server": "dock", "hardware_address": "aa:00:00:00:00:20", "address": "10.20.0.60", "host_name": "cam", "comment": "the camera"})
	if out["server"] != "dock" || out["scope"] != "LAN" || !acctest.BoolOf(out["changed"]) || out["before"] != nil || out["note"] != nil {
		t.Errorf("the answer = %v", out)
	}
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, []string{"reserved 10.20.0.60 for AA-00-00-00-00-20 (cam) in scope LAN", "had the server record 10.20.0.60 at cam.lan.example with its PTR, as a scope with dns_updates on does itself"}) {
		t.Errorf("changes = %v", got)
	}
	if after := acctest.Object(t, out["after"], "after"); after["scope"] != "LAN" || after["hardware_address"] != "AA-00-00-00-00-20" || after["address"] != "10.20.0.60" || after["host_name"] != "cam" || after["comment"] != "the camera" {
		t.Errorf("after = %v", after)
	}
	if records := acctest.Rows(t, out["records"], "records"); len(records) != 1 || records[0]["name"] != "cam.lan.example" || records[0]["value"] != "10.20.0.60" || records[0]["comment"] != "Via 'LAN' DHCP scope" {
		t.Errorf("records = %v", out["records"])
	}
	if asked := p.dock.Last("dhcp/scopes/addReservedLease"); asked.Params.Get("name") != "LAN" || asked.Params.Get("hardwareAddress") != "AA-00-00-00-00-20" || asked.Params.Get("ipAddress") != "10.20.0.60" || asked.Params.Get("hostName") != "cam" || asked.Params.Get("comments") != "the camera" {
		t.Errorf("the reservation was added with %v", asked.Params)
	}
	p.dock.Then("dhcp/scopes/addReservedLease", func(technitiumtest.Request) {})
	lanScope(p, all...)

	// already so: nothing is written
	sent := len(dhcpWritten(p.dock))
	again := suite.Call(t, "dhcp_reservation_set", map[string]any{"server": "dock", "hardware_address": "AA-00-00-00-00-01", "address": "10.20.0.4"})
	if acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 || len(dhcpWritten(p.dock)) != sent || acctest.Object(t, again["after"], "after")["comment"] != "the emby vm" {
		t.Errorf("a reservation already so = %v, with %d writes", again, len(dhcpWritten(p.dock))-sent)
	}

	// its comment alone: the server changes none in place, so it is removed and set again with the rest kept
	p.dock.Then("dhcp/scopes/addReservedLease", func(technitiumtest.Request) {
		lanScope(p, reservedJSON("AA-00-00-00-00-01", "10.20.0.4", "emby", "moved to the rack"), lanReserved["nas"])
	})
	out = suite.Call(t, "dhcp_reservation_set", map[string]any{"server": "dock", "hardware_address": "AA0000000001", "comment": "moved to the rack"})
	if got := acctest.Strs(t, out["changes"], "changes"); len(got) != 3 || got[0] != "removed the reservation of 10.20.0.4 for AA-00-00-00-00-01 (emby) in scope LAN, to set it again as asked: the server changes none in place" || got[1] != "reserved 10.20.0.4 for AA-00-00-00-00-01 (emby) in scope LAN" {
		t.Errorf("changes = %v", got)
	}
	if before, after := acctest.Object(t, out["before"], "before"), acctest.Object(t, out["after"], "after"); before["comment"] != "the emby vm" || after["comment"] != "moved to the rack" || after["host_name"] != "emby" {
		t.Errorf("before = %v, after = %v", before, after)
	}
	if removed, added := p.dock.Last("dhcp/scopes/removeReservedLease"), p.dock.Last("dhcp/scopes/addReservedLease"); removed.Params.Get("hardwareAddress") != "AA-00-00-00-00-01" || added.Params.Get("ipAddress") != "10.20.0.4" || added.Params.Get("hostName") != "emby" || added.Params.Get("comments") != "moved to the rack" {
		t.Errorf("removed with %v, added with %v", removed.Params, added.Params)
	}
	p.dock.Then("dhcp/scopes/addReservedLease", func(technitiumtest.Request) {})
	lanScope(p, all...)

	// a dry run says what would be done, the record made by hand it would write over among it, and writes nothing
	sent = len(dhcpWritten(p.dock))
	dry := suite.Call(t, "dhcp_reservation_set", map[string]any{"server": "dock", "hardware_address": "AA-00-00-00-00-21", "address": "10.20.0.62", "host_name": "dock", "dry_run": true})
	if got := acctest.Strs(t, dry["changes"], "changes"); !slices.Equal(got, []string{"would have reserved 10.20.0.62 for AA-00-00-00-00-21 (dock) in scope LAN", "would have had the server write over A 10.20.0.2 at dock.lan.example, as it does for a reservation's name", "would have had the server record 10.20.0.62 at dock.lan.example with its PTR, as a scope with dns_updates on does itself"}) {
		t.Errorf("a dry run's changes = %v", got)
	}
	if !acctest.BoolOf(dry["changed"]) || dry["after"] != nil || len(dhcpWritten(p.dock)) != sent || len(acctest.Rows(t, dry["records"], "records")) != 1 {
		t.Errorf("a dry run = %v, with %d writes", dry, len(dhcpWritten(p.dock))-sent)
	}

	// a machine that holds another address is told so
	held := suite.Call(t, "dhcp_reservation_set", map[string]any{"server": "dock", "hardware_address": "AA-00-00-00-00-10", "address": "10.20.0.63", "dry_run": true})
	if said := acctest.Str(held["note"]); !strings.Contains(said, "the machine holds 10.20.0.100 now, until 2026-10-10T17:52:51Z: the reservation is what it is given when it next asks for a lease") {
		t.Errorf("a machine holding another address = %q", said)
	}
	// in a scope that is off, or records no names, that is said
	if said := acctest.Str(suite.Call(t, "dhcp_reservation_set", map[string]any{"server": "dock", "hardware_address": "AA-00-00-00-00-22", "address": "192.168.1.9", "host_name": "spare", "dry_run": true})["note"]); !strings.Contains(said, "scope Default is switched off") || !strings.Contains(said, "does not record names in DNS") {
		t.Errorf("in a scope that is off = %q", said)
	}

	// what could not work is refused before anything is written, where the server would take it
	sent = len(dhcpWritten(p.dock))
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"no hardware address":           {map[string]any{"hardware_address": "the printer", "address": "10.20.0.64"}, `"the printer" is no hardware address: give the machine's six bytes as 00:11:22:aa:bb:cc`},
		"no address":                    {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "fe80::1"}, `"fe80::1" is not an IPv4 address`},
		"a name with a space":           {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.20.0.64", "host_name": "my printer"}, "it has a space in it"},
		"outside the scope's network":   {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.9.9.1", "scope": "LAN"}, "10.9.9.1 is outside 10.20.0.0/24, the network of scope LAN on dock"},
		"in no scope's network":         {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.9.9.1"}, "10.9.9.1 is in the network of no scope on dock, which has Default (192.168.1.0/24), LAN (10.20.0.0/24), Lab (10.20.5.0/24)"},
		"a scope there is none of":      {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.20.0.64", "scope": "WAN"}, "dock has no scope named WAN: it has Default"},
		"the network's own address":     {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.20.0.255"}, "which no machine can have"},
		"the server's own address":      {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.20.0.2"}, "10.20.0.2 is dock's own address on the network"},
		"the gateway":                   {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.20.0.1"}, "10.20.0.1 is the gateway scope LAN gives every machine"},
		"kept for another machine":      {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.20.0.30"}, "10.20.0.30 is kept for AA-00-00-00-00-02 (nas) in scope LAN already, and two machines cannot be given one address: remove that reservation with dhcp_reservation_delete"},
		"held by another machine":       {map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.20.0.100"}, "10.20.0.100 is held by AA-00-00-00-00-10 (laptop.lan.example) until 2026-10-10T17:52:51Z: choose another address, or once that machine is off it have the server forget the lease with dhcp_lease_delete"},
		"nothing to change and no room": {map[string]any{"hardware_address": "AA-00-00-00-00-30", "comment": "new"}, "AA-00-00-00-00-30 has no reservation on dock to change: give the address to keep for it"},
	} {
		refused.args["server"] = "dock"
		if msg := suite.CallErr(t, "dhcp_reservation_set", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
	if msg := suite.CallErr(t, "dhcp_reservation_set", map[string]any{"hardware_address": "AA-00-00-00-00-30", "address": "10.20.0.64"}); !strings.Contains(msg, "dock") || !strings.Contains(msg, "rpi") {
		t.Errorf("with no server named = %q, want the servers to choose from", msg)
	}
	if len(dhcpWritten(p.dock)) != sent {
		t.Errorf("%d refused changes reached the server: %v", len(dhcpWritten(p.dock))-sent, dhcpWritten(p.dock)[sent:])
	}

	// the new one refused by the server, the old one is put back
	p.dock.FailWhen("dhcp/scopes/addReservedLease", "ipAddress", "10.20.0.65", "error", "boom")
	msg := suite.CallErr(t, "dhcp_reservation_set", map[string]any{"server": "dock", "hardware_address": "AA-00-00-00-00-02", "address": "10.20.0.65"})
	if !strings.Contains(msg, "reserving 10.20.0.65 for AA-00-00-00-00-02: dhcp/scopes/addReservedLease: boom. The reservation of 10.20.0.30 it had was put back as it was") {
		t.Errorf("a refused replacement = %q", msg)
	}
	if back := p.dock.Last("dhcp/scopes/addReservedLease"); back.Params.Get("ipAddress") != "10.20.0.30" || back.Params.Get("hostName") != "nas" || back.Params.Get("hardwareAddress") != "AA-00-00-00-00-02" {
		t.Errorf("put back with %v", back.Params)
	}
}

// A reservation is removed by its machine or its address, and the answer is
// what it was and what the server took out of its zones with it.
func TestDHCPReservationDelete(t *testing.T) {
	t.Parallel()

	p := dhcpPair(t)
	suite := p.session(t, everything)

	// a dry run says what would go, the server's own records among it, and removes nothing
	dry := suite.Call(t, "dhcp_reservation_delete", map[string]any{"server": "dock", "hardware_address": "aa:00:00:00:00:01", "dry_run": true})
	if got := acctest.Strs(t, dry["changes"], "changes"); !slices.Equal(got, []string{"would have removed the reservation of 10.20.0.4 for AA-00-00-00-00-01 (emby) in scope LAN", "would have removed A 10.20.0.4 at emby.lan.example, which the server takes away with the reservation", "would have removed PTR emby.lan.example at 4.0.20.10.in-addr.arpa, which the server takes away with the reservation"}) {
		t.Errorf("a dry run's changes = %v", got)
	}
	if len(dhcpWritten(p.dock)) != 0 || len(acctest.Rows(t, dry["records"], "records")) != 2 {
		t.Errorf("a dry run = %v, with writes %v", dry, dhcpWritten(p.dock))
	}

	// removed: the reservation as it was, the records that went with it, and the lease the machine still holds
	p.dock.Then("dhcp/scopes/removeReservedLease", func(technitiumtest.Request) {
		lanScope(p, lanReserved["nas"], lanReserved["twin"], lanReserved["twin2"], lanReserved["printer"])
		at(p.dock, "emby.lan.example")
		at(p.dock, "4.0.20.10.in-addr.arpa")
	})
	out := suite.Call(t, "dhcp_reservation_delete", map[string]any{"server": "dock", "address": "10.20.0.4"})
	if removed := acctest.Object(t, out["removed"], "removed"); out["scope"] != "LAN" || removed["hardware_address"] != "AA-00-00-00-00-01" || removed["address"] != "10.20.0.4" || removed["host_name"] != "emby" || removed["comment"] != "the emby vm" {
		t.Errorf("removed = %v", out)
	}
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, []string{"removed the reservation of 10.20.0.4 for AA-00-00-00-00-01 (emby) in scope LAN", "removed A 10.20.0.4 at emby.lan.example, which the server took away with the reservation", "removed PTR emby.lan.example at 4.0.20.10.in-addr.arpa, which the server took away with the reservation"}) {
		t.Errorf("changes = %v", got)
	}
	if said := acctest.Str(out["note"]); out["records"] != nil || !strings.Contains(said, "the machine holds 10.20.0.4 until 2026-10-10T17:52:51Z and keeps it till then") {
		t.Errorf("records = %v, note = %q", out["records"], said)
	}
	if asked := p.dock.Last("dhcp/scopes/removeReservedLease"); asked.Params.Get("name") != "LAN" || asked.Params.Get("hardwareAddress") != "AA-00-00-00-00-01" {
		t.Errorf("removed with %v", asked.Params)
	}

	// which one must be plain
	sent := len(dhcpWritten(p.dock))
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"an address kept twice":      {map[string]any{"address": "10.20.0.40"}, "2 reservations on dock match (10.20.0.40 for AA-00-00-00-00-05 (twin) in scope LAN; 10.20.0.40 for AA-00-00-00-00-06 in scope LAN): say which with hardware_address and scope. Nothing was removed"},
		"a machine with none":        {map[string]any{"hardware_address": "AA-00-00-00-00-77"}, "dock keeps no such reservation: dhcp_leases with type reserved lists the ones it has"},
		"a machine in another scope": {map[string]any{"hardware_address": "AA-00-00-00-00-02", "scope": "Lab"}, "dock keeps no such reservation"},
		"neither":                    {map[string]any{}, "which one: give the machine's hardware_address, or the address"},
		"no scope of that name":      {map[string]any{"address": "10.20.0.30", "scope": "WAN"}, "dock has no scope named WAN"},
	} {
		refused.args["server"] = "dock"
		if msg := suite.CallErr(t, "dhcp_reservation_delete", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
	if len(dhcpWritten(p.dock)) != sent {
		t.Errorf("%d refused removals reached the server", len(dhcpWritten(p.dock))-sent)
	}

	// both say which of two
	p.dock.Then("dhcp/scopes/removeReservedLease", func(technitiumtest.Request) {
		lanScope(p, lanReserved["nas"], lanReserved["twin"], lanReserved["printer"])
	})
	out = suite.Call(t, "dhcp_reservation_delete", map[string]any{"server": "dock", "address": "10.20.0.40", "hardware_address": "AA-00-00-00-00-06"})
	if asked := p.dock.Last("dhcp/scopes/removeReservedLease"); asked.Params.Get("hardwareAddress") != "AA-00-00-00-00-06" || len(acctest.Strs(t, out["changes"], "changes")) != 1 || out["note"] != nil {
		t.Errorf("one of two = %v, removed with %v", out, asked.Params)
	}

	// the server says it is gone and still keeps it: that is an error, not a success
	p.dock.Then("dhcp/scopes/removeReservedLease", func(technitiumtest.Request) {})
	if msg := suite.CallErr(t, "dhcp_reservation_delete", map[string]any{"server": "dock", "address": "10.20.0.30"}); !strings.Contains(msg, "the server took the removal and scope LAN still keeps 10.20.0.30 for AA-00-00-00-00-02") {
		t.Errorf("a removal that did not take = %q", msg)
	}
}

// A lease is forgotten by its machine or its address; a reserved one's
// reservation, which the server drops with it, is put back.
func TestDHCPLeaseDelete(t *testing.T) {
	t.Parallel()

	p := dhcpPair(t)
	suite := p.session(t, everything)
	all := []string{lanReserved["emby"], lanReserved["nas"], lanReserved["twin"], lanReserved["twin2"], lanReserved["printer"]}

	// a dry run
	dry := suite.Call(t, "dhcp_lease_delete", map[string]any{"server": "dock", "address": "10.20.0.100", "dry_run": true})
	if got := acctest.Strs(t, dry["changes"], "changes"); !slices.Equal(got, []string{"would have had dock forget the lease of 10.20.0.100 to AA-00-00-00-00-10 (laptop.lan.example) in scope LAN", "would have removed A 10.20.0.100 at laptop.lan.example, which the server takes away with the lease"}) || len(dhcpWritten(p.dock)) != 0 {
		t.Errorf("a dry run's changes = %v, with writes %v", got, dhcpWritten(p.dock))
	}
	reserved := suite.Call(t, "dhcp_lease_delete", map[string]any{"server": "dock", "hardware_address": "aa0000000001", "dry_run": true})
	if got := acctest.Strs(t, reserved["changes"], "changes"); len(got) != 2 || got[1] != "would have put back the reservation of 10.20.0.4 for the machine, should the server drop it with the lease as it does a reserved one's" || acctest.Object(t, reserved["reservation"], "reservation")["address"] != "10.20.0.4" || len(dhcpWritten(p.dock)) != 0 {
		t.Errorf("a dry run on a reserved lease = %v", reserved)
	}

	// a dynamic lease: forgotten, with the record the server kept for it
	p.dock.Then("dhcp/leases/remove", func(technitiumtest.Request) {
		lanLeased(p, lanLeases["emby"])
		at(p.dock, "laptop.lan.example")
	})
	out := suite.Call(t, "dhcp_lease_delete", map[string]any{"server": "dock", "address": "10.20.0.100"})
	if removed := acctest.Object(t, out["removed"], "removed"); out["scope"] != "LAN" || removed["type"] != "Dynamic" || removed["hardware_address"] != "AA-00-00-00-00-10" || removed["host_name"] != "laptop.lan.example" || removed["expires"] != "2026-10-10T17:52:51Z" || out["reservation"] != nil {
		t.Errorf("removed = %v", out)
	}
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, []string{"had dock forget the lease of 10.20.0.100 to AA-00-00-00-00-10 (laptop.lan.example) in scope LAN", "removed A 10.20.0.100 at laptop.lan.example, which the server took away with the lease"}) {
		t.Errorf("changes = %v", got)
	}
	if asked := p.dock.Last("dhcp/leases/remove"); asked.Params.Get("name") != "LAN" || asked.Params.Get("hardwareAddress") != "AA-00-00-00-00-10" {
		t.Errorf("forgotten with %v", asked.Params)
	}

	// a reserved lease: the server drops the reservation with it, and it is put back as it was
	p.dock.Then("dhcp/leases/remove", func(technitiumtest.Request) {
		lanLeased(p)
		lanScope(p, all[1:]...)
	})
	out = suite.Call(t, "dhcp_lease_delete", map[string]any{"server": "dock", "hardware_address": "AA-00-00-00-00-01"})
	if got := acctest.Strs(t, out["changes"], "changes"); len(got) != 2 || got[1] != "put back the reservation of 10.20.0.4 for the machine, which the server dropped with its lease" {
		t.Errorf("changes = %v", got)
	}
	if back := p.dock.Last("dhcp/scopes/addReservedLease"); back.Params.Get("name") != "LAN" || back.Params.Get("hardwareAddress") != "AA-00-00-00-00-01" || back.Params.Get("ipAddress") != "10.20.0.4" || back.Params.Get("hostName") != "emby" || back.Params.Get("comments") != "the emby vm" {
		t.Errorf("put back with %v", back.Params)
	}
	if kept := acctest.Object(t, out["reservation"], "reservation"); kept["address"] != "10.20.0.4" || kept["host_name"] != "emby" {
		t.Errorf("the reservation kept = %v", out["reservation"])
	}

	// which one must be plain, and there
	lanLeased(p, lanLeases["emby"], lanLeases["laptop"])
	sent := len(dhcpWritten(p.dock))
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"a machine with no lease":  {map[string]any{"hardware_address": "AA-00-00-00-00-77"}, "dock holds no such lease: dhcp_leases lists the ones it has"},
		"a lease in another scope": {map[string]any{"address": "10.20.0.100", "scope": "Lab"}, "dock holds no such lease"},
		"neither":                  {map[string]any{}, "which one: give the machine's hardware_address, or the address"},
		"no hardware address":      {map[string]any{"hardware_address": "laptop"}, `"laptop" is no hardware address`},
	} {
		refused.args["server"] = "dock"
		if msg := suite.CallErr(t, "dhcp_lease_delete", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
	if len(dhcpWritten(p.dock)) != sent {
		t.Errorf("%d refused removals reached the server", len(dhcpWritten(p.dock))-sent)
	}

	// the server says it forgot and still lists the lease: an error, not a success
	p.dock.Then("dhcp/leases/remove", func(technitiumtest.Request) {})
	if msg := suite.CallErr(t, "dhcp_lease_delete", map[string]any{"server": "dock", "address": "10.20.0.100"}); !strings.Contains(msg, "the server took the removal and still lists 10.20.0.100 as leased to AA-00-00-00-00-10 in scope LAN") {
		t.Errorf("a removal that did not take = %q", msg)
	}
}

// A hardware address is read however it is written, and nothing else is one.
func TestMacKey(t *testing.T) {
	t.Parallel()

	for _, written := range []string{"00:11:22:AA:BB:CC", "00-11-22-aa-bb-cc", "0011.22aa.bbcc", "001122aabbcc", " 00:11:22:aa:bb:cc "} {
		if got := macKey(written); got != "001122aabbcc" || macText(got) != "00-11-22-AA-BB-CC" {
			t.Errorf("macKey(%q) = %q, written back as %q", written, got, macText(got))
		}
	}
	for _, not := range []string{"", "printer", "00:11:22:aa:bb", "00:11:22:aa:bb:cc:dd", "10.0.0.4", "gg:11:22:aa:bb:cc"} {
		if got := macKey(not); got != "" {
			t.Errorf("macKey(%q) = %q, want none", not, got)
		}
	}
}
