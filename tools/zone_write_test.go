package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// zonePair is setupPair with what the changes to a zone answer.
func zonePair(t *testing.T) *pair {
	t.Helper()

	p := setupPair(t)
	for _, path := range []string{"zones/options/set", "zones/resync"} {
		p.both(path, `{}`)
	}
	p.both("zones/create", `{"domain":"made"}`)
	p.both("zones/records/update", `{"updatedRecord":{"name":"example.com","type":"SOA","ttl":900,"rData":{"primaryNameServer":"dock"}}}`)

	return p
}

// zoneWrites are the calls a server was sent that change a zone.
func zoneWrites(server *technitiumtest.Server) int {
	return len(server.Requests("zones/create")) + len(server.Requests("zones/options/set")) + len(server.Requests("zones/records/update")) + len(server.Requests("zones/resync"))
}

// A zone is made as asked, left alone when it is there, and refused when it
// is there as something else.
func TestZoneCreate(t *testing.T) {
	t.Parallel()

	p := zonePair(t)
	suite := p.session(t, everything)

	p.dock.Then("zones/create", func(technitiumtest.Request) {
		p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"only.example","type":"Primary","soaSerial":1},{"name":"new.example","type":"Primary","soaSerial":1}]}`)
	})
	out := suite.Call(t, "zone_create", map[string]any{"server": "dock", "zone": "New.Example."})
	if out["server"] != "dock" || out["zone"] != "new.example" || !acctest.BoolOf(out["changed"]) || !slices.Equal(acctest.Strs(t, out["changes"], "changes"), []string{"made new.example on dock as a Primary zone"}) || out["note"] != "making a zone can empty the server's cache: what it had resolved for clients is then resolved again as they ask" {
		t.Errorf("the answer = %v", out)
	}
	if after := acctest.Object(t, out["after"], "after"); after["type"] != "Primary" || after["server"] != "dock" || after["transfer"] != "UseSpecifiedNetworkACL" {
		t.Errorf("the zone read back = %v", after)
	}
	if asked := p.dock.Last("zones/create"); asked.Params.Get("zone") != "new.example" || asked.Params.Get("type") != "Primary" || asked.Params.Has("catalog") || asked.Params.Has("forwarder") {
		t.Errorf("the zone was made with %v", asked.Params)
	}

	// there already: as asked it is left alone, as another type it is refused
	sent := zoneWrites(p.dock) + zoneWrites(p.rpi)
	if again := suite.Call(t, "zone_create", map[string]any{"server": "dock", "zone": "example.com"}); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 || acctest.Object(t, again["after"], "after")["type"] != "Primary" {
		t.Errorf("a zone that is there = %v", again)
	}
	if msg := suite.CallErr(t, "zone_create", map[string]any{"server": "rpi", "zone": "example.com"}); !strings.Contains(msg, "rpi holds example.com already, as a Secondary zone") {
		t.Errorf("a zone there as another type = %q", msg)
	}

	// a reverse zone by its network; a zone under one that is held; and what each kind needs
	dry := suite.Call(t, "zone_create", map[string]any{"server": "dock", "zone": "10.0.0.0/24", "dry_run": true})
	if dry["zone"] != "0.0.10.in-addr.arpa" || !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have made 0.0.10.in-addr.arpa on dock as a Primary zone"}) || dry["after"] != nil || !strings.Contains(acctest.Str(dry["note"]), "making a zone can empty the server's cache: what it had resolved for clients is then resolved again as they ask; a reverse zone always does") {
		t.Errorf("a reverse zone by its network = %v", dry)
	}
	if wide := suite.Call(t, "zone_create", map[string]any{"server": "dock", "zone": "10.20.0.0/16", "dry_run": true}); wide["zone"] != "20.10.in-addr.arpa" {
		t.Errorf("a /16 = %v", wide["zone"])
	}
	if under := suite.Call(t, "zone_create", map[string]any{"server": "dock", "zone": "van.example.com", "dry_run": true}); !strings.Contains(acctest.Str(under["note"]), "dock holds example.com above it: every name under van.example.com is answered from the new zone from now on") {
		t.Errorf("a zone under one that is held = %v", under["note"])
	}
	p.rpi.Then("zones/create", func(technitiumtest.Request) {
		p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Secondary","soaSerial":6},{"name":"fwd.example","type":"Forwarder","soaSerial":1}]}`)
	})
	suite.Call(t, "zone_create", map[string]any{"server": "rpi", "zone": "fwd.example", "type": "forwarder", "forwarder": "10.0.0.9"})
	if asked := p.rpi.Last("zones/create"); asked.Params.Get("type") != "Forwarder" || asked.Params.Get("forwarder") != "10.0.0.9" {
		t.Errorf("a forwarder was made with %v", asked.Params)
	}
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"a network of 20 bits":             {map[string]any{"zone": "10.0.0.0/20"}, "a reverse zone is made for an IPv4 network of 8, 16 or 24 bits"},
		"no name":                          {map[string]any{"zone": " "}, "which zone"},
		"an address":                       {map[string]any{"zone": "https://example.com"}, "is no zone name"},
		"a kind there is none of":          {map[string]any{"zone": "x.example", "type": "Tertiary"}, `type "Tertiary": it takes Forwarder, Primary, Secondary`},
		"a copy of nothing":                {map[string]any{"zone": "x.example", "type": "Secondary"}, "give the primary's address in primary_addresses"},
		"a forwarder to nowhere":           {map[string]any{"zone": "x.example", "type": "Forwarder"}, "give the name server to ask in forwarder"},
		"a primary with a primary":         {map[string]any{"zone": "x.example", "primary_addresses": []string{"10.0.0.2"}}, "a Primary takes neither"},
		"a catalog the server has not got": {map[string]any{"zone": "x.example", "catalog": "cat.example"}, "dock holds no catalog zone named cat.example: it holds none"},
	} {
		refused.args["server"] = "dock"
		if msg := suite.CallErr(t, "zone_create", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
	if now := zoneWrites(p.dock) + zoneWrites(p.rpi); now != sent+1 {
		t.Errorf("%d writes for one forwarder made and the rest refused or dry", now-sent)
	}

	// a server with a catalog says how the zone would be shared, and makes it a member when asked
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"cluster-catalog.example","type":"Catalog","soaSerial":1}]}`)
	if alone := suite.Call(t, "zone_create", map[string]any{"server": "dock", "zone": "shared.example", "dry_run": true}); !strings.Contains(acctest.Str(alone["note"]), "the zone is on dock alone: made a member of the catalog cluster-catalog.example, with catalog, it is given to every server that follows it") {
		t.Errorf("with a catalog on the server = %v", alone["note"])
	}
	p.dock.Then("zones/create", func(technitiumtest.Request) {
		p.dock.Answer("zones/list", `{"zones":[{"name":"shared.example","type":"Primary","soaSerial":1,"catalog":"cluster-catalog.example"}]}`)
	})
	member := suite.Call(t, "zone_create", map[string]any{"server": "dock", "zone": "shared.example", "catalog": "cluster-catalog.example"})
	if asked := p.dock.Last("zones/create"); asked.Params.Get("catalog") != "cluster-catalog.example" || strings.Contains(acctest.Str(member["note"]), "alone") || acctest.Object(t, member["after"], "after")["catalog"] != "cluster-catalog.example" {
		t.Errorf("a member of the catalog = %v, made with %v", member, asked.Params)
	}
}

// A zone's options and SOA are changed by what differs, read back, and a
// change the server did not take is an error.
func TestZoneEdit(t *testing.T) {
	t.Parallel()

	p := zonePair(t)
	suite := p.session(t, everything)

	// already as asked: nothing is written
	same := suite.Call(t, "zone_edit", map[string]any{"server": "dock", "zone": "example.com", "transfer": "usespecifiednetworkacl", "transfer_networks": []string{"10.0.0.3"}, "soa_primary": "dock", "refresh": 900, "disabled": false})
	if acctest.BoolOf(same["changed"]) || len(acctest.Strs(t, same["changes"], "changes")) != 0 || zoneWrites(p.dock) != 0 || acctest.Object(t, same["after"], "after")["transfer"] != "UseSpecifiedNetworkACL" {
		t.Errorf("a zone already as asked = %v, with %d writes", same, zoneWrites(p.dock))
	}
	// a dry run says what would be set
	dry := suite.Call(t, "zone_edit", map[string]any{"server": "dock", "zone": "example.com", "transfer": "Allow", "notify": "None", "dry_run": true})
	if got := acctest.Strs(t, dry["changes"], "changes"); !slices.Equal(got, []string{"would have set who may transfer it from UseSpecifiedNetworkACL to Allow", "would have set who is told when it changes from ZoneNameServers to None"}) || zoneWrites(p.dock) != 0 || dry["after"] != nil || !strings.Contains(acctest.Str(dry["note"]), "anyone who can reach the server may now transfer the zone whole") {
		t.Errorf("a dry run = %v", dry)
	}

	// set: only what differs is sent, and the zone is read back
	p.dock.Then("zones/options/set", func(technitiumtest.Request) {
		p.dock.Answer("zones/options/get", strings.NewReplacer(`"zoneTransfer":"UseSpecifiedNetworkACL"`, `"zoneTransfer":"AllowOnlyZoneNameServers"`, `"zoneTransferNetworkACL":["10.0.0.3"]`, `"zoneTransferNetworkACL":[]`, `"notify":"ZoneNameServers","notifyNameServers":[]`, `"notify":"SpecifiedNameServers","notifyNameServers":["10.0.0.3"]`, `"disabled":false`, `"disabled":true`).Replace(primaryOptions))
		p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":8,"disabled":true}]}`)
	})
	p.dock.Then("zones/records/update", func(technitiumtest.Request) {
		p.dock.Answer("zones/records/get", strings.NewReplacer(`"primaryNameServer":"dock"`, `"primaryNameServer":"dock.example.com"`, `"refresh":900`, `"refresh":600`).Replace(apexRecords))
	})
	out := suite.Call(t, "zone_edit", map[string]any{"server": "dock", "zone": "example.com", "transfer": "AllowOnlyZoneNameServers", "transfer_networks": []string{}, "notify": "SpecifiedNameServers", "notify_servers": []string{"10.0.0.3"}, "update": "UseSpecifiedNetworkACL", "disabled": true, "soa_primary": "dock.example.com", "refresh": 600})
	want := []string{"set who may transfer it from UseSpecifiedNetworkACL to AllowOnlyZoneNameServers", "set who is told when it changes from ZoneNameServers to SpecifiedNameServers", "set the networks that may transfer it from 10.0.0.3 to none", "set the servers told of a change from none to 10.0.0.3", "switched the zone off", "set the SOA's primary name server from dock to dock.example.com", "set the SOA's refresh from 900 to 600 seconds"}
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, want) {
		t.Errorf("changes = %q, want %q", got, want)
	}
	if before, after := acctest.Object(t, out["before"], "before"), acctest.Object(t, out["after"], "after"); before["transfer"] != "UseSpecifiedNetworkACL" || after["transfer"] != "AllowOnlyZoneNameServers" || after["soa_primary"] != "dock.example.com" || acctest.Num(t, after["refresh"], "refresh") != 600 || !acctest.BoolOf(after["disabled"]) {
		t.Errorf("before = %v, after = %v", before, after)
	}
	asked := p.dock.Last("zones/options/set")
	for param, value := range map[string]string{"zone": "example.com", "zoneTransfer": "AllowOnlyZoneNameServers", "zoneTransferNetworkACL": "false", "notify": "SpecifiedNameServers", "notifyNameServers": "10.0.0.3", "disabled": "true"} {
		if asked.Params.Get(param) != value {
			t.Errorf("the options were set with %s=%q, want %q", param, asked.Params.Get(param), value)
		}
	}
	// the update policy was as asked already, and is not sent
	if asked.Params.Has("update") || len(asked.Params) != 6 {
		t.Errorf("the options were set with %v", asked.Params)
	}
	if soa := p.dock.Last("zones/records/update"); soa.Params.Get("primaryNameServer") != "dock.example.com" || soa.Params.Get("refresh") != "600" || soa.Params.Get("retry") != "300" || soa.Params.Get("responsiblePerson") != "hostadmin@example.com" || soa.Params.Get("serial") != "7" || soa.Params.Get("ttl") != "900" {
		t.Errorf("the SOA was set with %v", soa.Params)
	}

	// the server says ok and the option is as it was: an error that says which
	p.dock.Then("zones/options/set", nil)
	if msg := suite.CallErr(t, "zone_edit", map[string]any{"server": "dock", "zone": "example.com", "update": "Allow", "update_networks": []string{}}); !strings.Contains(msg, "the server said ok and example.com on dock does not have what was asked for: update (still UseSpecifiedNetworkACL), update_networks (still 10.0.0.0/24)") {
		t.Errorf("a change that did not hold = %q", msg)
	}

	sent := zoneWrites(p.dock) + zoneWrites(p.rpi)
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"a copy's SOA":                 {map[string]any{"server": "rpi", "zone": "example.com", "soa_primary": "rpi"}, "rpi holds example.com as a Secondary zone, a copy: its SOA record is its primary's, and is changed there"},
		"a policy there is none of":    {map[string]any{"server": "dock", "zone": "example.com", "transfer": "Whoever"}, `transfer "Whoever": it takes Allow, AllowOnlyZoneNameServers`},
		"a notify policy there is not": {map[string]any{"server": "dock", "zone": "example.com", "notify": "Everyone"}, `notify "Everyone": it takes BothZoneAndSpecifiedNameServers, None`},
		"a zone the server has not":    {map[string]any{"server": "rpi", "zone": "only.example", "disabled": true}, "rpi holds no zone named only.example"},
		"no zone":                      {map[string]any{"server": "dock", "zone": ""}, "which zone"},
	} {
		if msg := suite.CallErr(t, "zone_edit", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
	if now := zoneWrites(p.dock) + zoneWrites(p.rpi); now != sent {
		t.Errorf("%d refused changes reached a server", now-sent)
	}
}

// Only a copy is resynced, on the server that holds it.
func TestZoneResync(t *testing.T) {
	t.Parallel()

	p := zonePair(t)
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Secondary","soaSerial":6,"syncFailed":true}]}`)
	suite := p.session(t, everything)

	dry := suite.Call(t, "zone_resync", map[string]any{"server": "rpi", "zone": "example.com", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have asked rpi to transfer its copy of example.com from the primary again"}) || len(p.rpi.Requests("zones/resync")) != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	out := suite.Call(t, "zone_resync", map[string]any{"server": "rpi", "zone": "Example.com"})
	if out["server"] != "rpi" || out["type"] != "Secondary" || acctest.Num(t, out["serial"], "serial") != 6 || !acctest.BoolOf(out["sync_failed"]) || !strings.Contains(acctest.Str(out["note"]), "the server makes the transfer after it answers") || p.rpi.Last("zones/resync").Params.Get("zone") != "example.com" {
		t.Errorf("resynced = %v, asked with %v", out, p.rpi.Last("zones/resync").Params)
	}
	if msg := suite.CallErr(t, "zone_resync", map[string]any{"server": "dock", "zone": "example.com"}); !strings.Contains(msg, "dock holds example.com as a Primary zone, which is no copy") || len(p.dock.Requests("zones/resync")) != 0 {
		t.Errorf("a primary resynced = %q", msg)
	}
	if msg := suite.CallErr(t, "zone_resync", map[string]any{"server": "rpi", "zone": "nope.example"}); !strings.Contains(msg, "rpi holds no zone named nope.example") {
		t.Errorf("a zone that is not there = %q", msg)
	}
}
