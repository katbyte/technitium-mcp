package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// listsPair is blockPair with the calls that add many names, empty a list
// and walk one answered.
func listsPair(t *testing.T) *pair {
	t.Helper()

	p := blockPair(t)
	for _, path := range []string{"blocked/import", "allowed/import", "blocked/flush", "allowed/flush"} {
		p.both(path, `{}`)
	}
	p.both("blocked/list", `{"domain":"","zones":["org","net","com","test"],"records":[]}`)
	p.dock.AnswerWhen("blocked/list", "domain", "example.net", `{"domain":"ads.example.net","zones":[],"records":[{"name":"ads.example.net","type":"SOA"}]}`)
	p.both("allowed/list", `{"domain":"","zones":["net"],"records":[]}`)
	p.rpi.Fail("allowed/list", "error", "Access was denied.")

	return p
}

// listWrites are how many calls that add many names or empty a list a
// server got.
func listWrites(server *technitiumtest.Server) int {
	n := 0
	for _, path := range []string{"blocked/import", "allowed/import", "blocked/flush", "allowed/flush"} {
		n += len(server.Requests(path))
	}

	return n
}

// Many names are added at once, and only the ones the list did not have are
// sent.
func TestBlockImport(t *testing.T) {
	t.Parallel()

	p := listsPair(t)
	suite := p.session(t, everything)

	dry := suite.Call(t, "block_import", map[string]any{"server": "dock", "names": []string{"New.example.net.", "ads.example.net", " ", "new.example.net", "other.example.org"}, "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have added 2 names to the blocked names of dock"}) || !slices.Equal(acctest.Strs(t, dry["added"], "added"), []string{"new.example.net", "other.example.org"}) || !slices.Equal(acctest.Strs(t, dry["already"], "already"), []string{"ads.example.net"}) || acctest.Num(t, dry["total"], "total") != 6 || listWrites(p.dock) != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	p.dock.Then("blocked/import", func(technitiumtest.Request) {
		p.dock.AnswerText("blocked/export", "tracker.example.org\nads.example.net\nheld.example.com\nads.blocked.test\nnew.example.net\nother.example.org\n")
	})
	added := suite.Call(t, "block_import", map[string]any{"server": "dock", "names": []string{"new.example.net", "ads.example.net", "other.example.org"}})
	if asked := p.dock.Last("blocked/import"); asked.Params.Get("blockedZones") != "new.example.net,other.example.org" || acctest.Num(t, added["total"], "total") != 6 || added["list"] != "blocked" || added["note"] != nil {
		t.Errorf("added = %v, asked with %v", added, asked.Params)
	}
	if same := suite.Call(t, "block_import", map[string]any{"server": "dock", "names": []string{"ads.example.net", "Tracker.example.org"}}); acctest.BoolOf(same["changed"]) || !strings.Contains(acctest.Str(same["note"]), "on the list already") || len(p.dock.Requests("blocked/import")) != 1 {
		t.Errorf("names it has = %v", same)
	}

	// the allowed names are the other list, by its own call
	allowed := suite.Call(t, "block_import", map[string]any{"server": "rpi", "list": "Allowed", "names": []string{"fine.example.net"}})
	if asked := p.rpi.Last("allowed/import"); asked.Params.Get("allowedZones") != "fine.example.net" || allowed["list"] != "allowed" || len(p.rpi.Requests("blocked/import")) != 0 {
		t.Errorf("allowed = %v, asked with %v", allowed, asked.Params)
	}

	sent := listWrites(p.dock) + listWrites(p.rpi)
	for msg, args := range map[string]map[string]any{
		`list "denied": it is blocked or allowed`: {"server": "dock", "list": "denied", "names": []string{"a.example"}},
		"which names":                        {"server": "dock", "names": []string{" ", ""}},
		`"two words" is no domain name`:      {"server": "dock", "names": []string{"fine.example", "two words"}},
		`"a.example,b.example" is no domain`: {"server": "dock", "names": []string{"a.example,b.example"}},
	} {
		if got := suite.CallErr(t, "block_import", args); !strings.Contains(got, msg) {
			t.Errorf("block_import %v = %q, want %q in it", args, got, msg)
		}
	}
	if now := listWrites(p.dock) + listWrites(p.rpi); now != sent {
		t.Errorf("%d refused imports reached a server", now-sent)
	}
}

// On a cluster's secondary node the names go to the primary, which is said.
func TestBlockImportOnASecondaryNode(t *testing.T) {
	t.Parallel()

	p := listsPair(t)
	p.rpi.Answer("admin/cluster/state", asSecondary)
	suite := p.session(t, everything)

	if out := suite.Call(t, "block_import", map[string]any{"server": "rpi", "names": []string{"new.example.net"}}); !strings.Contains(acctest.Str(out["note"]), "secondary node of a cluster") {
		t.Errorf("on a secondary node = %v", out)
	}
}

// A list is emptied only when it is named, with how many names it held.
func TestBlockFlush(t *testing.T) {
	t.Parallel()

	p := listsPair(t)
	suite := p.session(t, everything)

	for msg, args := range map[string]map[string]any{
		"which list: blocked or allowed": {"server": "dock", "list": " "},
		`list "both"`:                    {"server": "dock", "list": "both"},
	} {
		if got := suite.CallErr(t, "block_flush", args); !strings.Contains(got, msg) {
			t.Errorf("block_flush %v = %q, want %q in it", args, got, msg)
		}
	}
	dry := suite.Call(t, "block_flush", map[string]any{"server": "dock", "list": "blocked", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have emptied the blocked names of dock, which held 4"}) || acctest.Num(t, dry["removed"], "removed") != 4 {
		t.Errorf("a dry run = %v", dry)
	}
	if nothing := suite.Call(t, "block_flush", map[string]any{"server": "rpi", "list": "allowed"}); acctest.BoolOf(nothing["changed"]) || !strings.Contains(acctest.Str(nothing["note"]), "empty already") {
		t.Errorf("a list that is empty, emptied = %v", nothing)
	}
	if listWrites(p.dock)+listWrites(p.rpi) != 0 {
		t.Error("a list was emptied before one was asked to be")
	}

	if out := suite.Call(t, "block_flush", map[string]any{"server": "dock", "list": "ALLOWED"}); acctest.Num(t, out["removed"], "removed") != 1 || len(p.dock.Requests("allowed/flush")) != 1 || len(p.dock.Requests("blocked/flush")) != 0 {
		t.Errorf("the allowed names emptied = %v", out)
	}
	if out := suite.Call(t, "block_flush", map[string]any{"server": "dock", "list": "blocked"}); acctest.Num(t, out["removed"], "removed") != 4 || len(p.dock.Requests("blocked/flush")) != 1 {
		t.Errorf("the blocked names emptied = %v", out)
	}
}

func TestBlockTree(t *testing.T) {
	t.Parallel()

	p := listsPair(t)
	suite := p.session(t, Options{})

	top := suite.Call(t, "block_tree", nil)
	rows := acctest.Rows(t, top["servers"], "servers")
	if top["list"] != "blocked" || rows[0]["at"] != "" || acctest.BoolOf(rows[0]["listed"]) || !slices.Equal(acctest.Strs(t, rows[0]["below"], "below"), []string{"org", "net", "com", "test"}) || p.dock.Last("blocked/list").Params.Has("domain") {
		t.Errorf("the top of the list = %v", top)
	}
	// asked under a name that only leads on, the server answers for the listed name below it, which is said
	under := acctest.Rows(t, suite.Call(t, "block_tree", map[string]any{"server": "dock", "under": "Example.net."})["servers"], "servers")[0]
	if under["at"] != "ads.example.net" || !acctest.BoolOf(under["listed"]) || len(acctest.Strs(t, under["below"], "below")) != 0 || p.dock.Last("blocked/list").Params.Get("domain") != "example.net" {
		t.Errorf("under a name = %v", under)
	}
	allowed := acctest.Rows(t, suite.Call(t, "block_tree", map[string]any{"list": "allowed"})["servers"], "servers")
	if !slices.Equal(acctest.Strs(t, allowed[0]["below"], "below"), []string{"net"}) || !strings.Contains(acctest.Str(allowed[1]["error"]), "Access was denied") || len(acctest.Strs(t, allowed[1]["below"], "below")) != 0 {
		t.Errorf("the allowed names = %v", allowed)
	}
	if msg := suite.CallErr(t, "block_tree", map[string]any{"list": "neither"}); !strings.Contains(msg, "it is blocked or allowed") {
		t.Errorf("a list that is neither = %q", msg)
	}
}

// A scope is deleted with what goes with it counted first.
func TestDHCPScopeDelete(t *testing.T) {
	t.Parallel()

	p := dhcpPair(t)
	suite := p.session(t, everything)

	dry := suite.Call(t, "dhcp_scope_delete", map[string]any{"server": "dock", "scope": "lan", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have deleted the scope LAN on dock with its 5 reservations and 2 leases"}) || dry["scope"] != "LAN" || acctest.Num(t, dry["leases"], "leases") != 2 || acctest.Num(t, dry["reservations"], "reservations") != 5 || len(dhcpWritten(p.dock)) != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	out := suite.Call(t, "dhcp_scope_delete", map[string]any{"server": "dock", "scope": "LAN"})
	if asked := p.dock.Last("dhcp/scopes/delete"); asked.Params.Get("name") != "LAN" || !acctest.BoolOf(out["changed"]) || !strings.Contains(acctest.Str(out["note"]), "was leasing addresses when it was deleted") {
		t.Errorf("deleted = %v, asked with %v", out, asked.Params)
	}
	for msg, args := range map[string]map[string]any{
		"dock has no scope named WAN": {"server": "dock", "scope": "WAN"},
		"which scope":                 {"server": "dock", "scope": " "},
	} {
		if got := suite.CallErr(t, "dhcp_scope_delete", args); !strings.Contains(got, msg) {
			t.Errorf("dhcp_scope_delete %v = %q, want %q in it", args, got, msg)
		}
	}
	if len(p.dock.Requests("dhcp/scopes/delete")) != 1 {
		t.Errorf("%d scopes were deleted, want the one", len(p.dock.Requests("dhcp/scopes/delete")))
	}
}

// The lease a machine holds is made a reservation, or an ordinary lease
// again, with the machine found by what dhcp_leases gives of it.
func TestDHCPLeaseReserve(t *testing.T) {
	t.Parallel()

	p := dhcpPair(t)
	p.dock.Answer("dhcp/leases/convertToReserved", `{}`)
	p.dock.Answer("dhcp/leases/convertToDynamic", `{}`)
	suite := p.session(t, everything)
	converted := func() int {
		return len(p.dock.Requests("dhcp/leases/convertToReserved")) + len(p.dock.Requests("dhcp/leases/convertToDynamic"))
	}

	dry := suite.Call(t, "dhcp_lease_reserve", map[string]any{"server": "dock", "machine": "laptop", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have made the lease of 10.20.0.100 to AA-00-00-00-00-10 (laptop.lan.example) in scope LAN a reservation"}) || dry["type"] != "Dynamic" || converted() != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	// by its hardware address however it is written, by its address, by its whole name
	for _, machine := range []string{"aa:00:00:00:00:10", "10.20.0.100", "Laptop.lan.example"} {
		out := suite.Call(t, "dhcp_lease_reserve", map[string]any{"server": "dock", "machine": machine})
		if asked := p.dock.Last("dhcp/leases/convertToReserved"); out["type"] != "Reserved" || out["address"] != "10.20.0.100" || asked.Params.Get("name") != "LAN" || asked.Params.Get("hardwareAddress") != "AA-00-00-00-00-10" {
			t.Errorf("reserved by %s = %v, asked with %v", machine, out, asked.Params)
		}
	}
	// what is as asked already is left alone
	sent := converted()
	if same := suite.Call(t, "dhcp_lease_reserve", map[string]any{"server": "dock", "machine": "emby"}); acctest.BoolOf(same["changed"]) || same["type"] != "Reserved" || converted() != sent {
		t.Errorf("a lease that is reserved, reserved = %v", same)
	}
	if same := suite.Call(t, "dhcp_lease_reserve", map[string]any{"server": "dock", "machine": "laptop", "reserved": false}); acctest.BoolOf(same["changed"]) || converted() != sent {
		t.Errorf("an ordinary lease, made ordinary = %v", same)
	}
	back := suite.Call(t, "dhcp_lease_reserve", map[string]any{"server": "dock", "machine": "emby", "scope": "lan", "reserved": false})
	if asked := p.dock.Last("dhcp/leases/convertToDynamic"); back["type"] != "Dynamic" || asked.Params.Get("hardwareAddress") != "AA-00-00-00-00-01" || !strings.HasSuffix(acctest.Strs(t, back["changes"], "changes")[0], "an ordinary one, removing the reservation") {
		t.Errorf("made ordinary = %v, asked with %v", back, asked.Params)
	}

	sent = converted()
	lanLeased(p, lanLeases["emby"], lanLeases["laptop"], leaseJSON("LAB", "Dynamic", "AA-00-00-00-00-11", "10.20.5.100", "laptop.lab.example"))
	for msg, args := range map[string]map[string]any{
		"which machine":                      {"server": "dock", "machine": " "},
		"dock has given no lease to printer": {"server": "dock", "machine": "printer"},
		"dock has given no lease to emby":    {"server": "dock", "machine": "emby", "scope": "LAB"},
		"2 leases on dock match laptop":      {"server": "dock", "machine": "laptop"},
	} {
		if got := suite.CallErr(t, "dhcp_lease_reserve", args); !strings.Contains(got, msg) {
			t.Errorf("dhcp_lease_reserve %v = %q, want %q in it", args, got, msg)
		}
	}
	// the scope tells two machines of one name apart
	if out := suite.Call(t, "dhcp_lease_reserve", map[string]any{"server": "dock", "machine": "laptop", "scope": "LAB"}); out["address"] != "10.20.5.100" || converted() != sent+1 {
		t.Errorf("told apart by the scope = %v", out)
	}
}
