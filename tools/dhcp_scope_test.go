package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

const guestScopeListed = `{"name":"Guest","enabled":%ENABLED%,"startingAddress":"10.30.0.10","endingAddress":"10.30.0.99","subnetMask":"255.255.255.0","networkAddress":"10.30.0.0","broadcastAddress":"10.30.0.255","interfaceAddress":"10.30.0.2"}`

// guest makes dock list a Guest scope beside its others, switched on or off.
func guest(p *pair, enabled bool) {
	on := map[bool]string{true: "true", false: "false"}[enabled]
	p.dock.Answer("dhcp/scopes/list", `{"scopes":[`+defaultScopeListed+`,`+lanScopeListed+`,`+labScopeListed+`,`+strings.Replace(guestScopeListed, "%ENABLED%", on, 1)+`]}`)
	p.dock.AnswerWhen("dhcp/scopes/get", "name", "Guest", strings.Replace(scopeJSON("Guest", "10.30.0.10", "10.30.0.99", `"domainName":"guest.example","dnsUpdates":false,"routerAddress":"10.30.0.1","useThisDnsServer":true`), `"leaseTimeDays":1,"leaseTimeHours":0`, `"leaseTimeDays":0,"leaseTimeHours":12`, 1))
}

// A scope is made switched off unless asked otherwise, changed by what is
// given, and refused where it would lease what another does.
func TestDHCPScopeSet(t *testing.T) {
	t.Parallel()

	p := dhcpPair(t)
	for _, path := range []string{"dhcp/scopes/enable", "dhcp/scopes/disable"} {
		p.dock.Answer(path, `{}`)
	}
	suite := p.session(t, everything)
	writes := func() []string {
		var out []string
		for _, path := range []string{"dhcp/scopes/set", "dhcp/scopes/enable", "dhcp/scopes/disable"} {
			for _, req := range p.dock.Requests(path) {
				out = append(out, strings.TrimPrefix(path, "dhcp/scopes/")+" "+req.Params.Get("name"))
			}
		}

		return out
	}

	// a dry run: what would be done, the switching off among it
	dry := suite.Call(t, "dhcp_scope_set", map[string]any{"server": "dock", "scope": "Guest", "first": "10.30.0.10", "last": "10.30.0.99", "mask": "24", "dry_run": true})
	if got := acctest.Strs(t, dry["changes"], "changes"); !slices.Equal(got, []string{"would have made the scope Guest on dock, leasing 10.30.0.10-10.30.0.99 in 10.30.0.0/24", "would have switched the scope off again, the server having switched it on as it made it: give enabled to have it lease"}) || len(writes()) != 0 || dry["before"] != nil || dry["after"] != nil {
		t.Errorf("a dry run = %v, with writes %v", dry, writes())
	}

	// made: the server switches it on, and it is switched off again at once
	p.dock.Then("dhcp/scopes/set", func(technitiumtest.Request) { guest(p, true) })
	p.dock.Then("dhcp/scopes/disable", func(technitiumtest.Request) { guest(p, false) })
	out := suite.Call(t, "dhcp_scope_set", map[string]any{"server": "dock", "scope": "Guest", "first": "10.30.0.10", "last": "10.30.0.99", "mask": "255.255.255.0", "lease_time": "12h", "domain": "Guest.Example.", "router": "10.30.0.1", "dns_servers": []string{"10.30.0.2", " "}, "use_this_dns_server": true, "dns_updates": false, "exclusions": []string{"10.30.0.90-10.30.0.99"}})
	if !acctest.BoolOf(out["changed"]) || len(acctest.Strs(t, out["changes"], "changes")) != 2 || out["before"] != nil || out["note"] != nil {
		t.Errorf("made = %v", out)
	}
	if after := acctest.Object(t, out["after"], "after"); after["scope"] != "Guest" || acctest.BoolOf(after["enabled"]) || after["range"] != "10.30.0.10-10.30.0.99" || after["network"] != "10.30.0.0/24" || after["lease_time"] != "12h" {
		t.Errorf("the scope read back = %v", after)
	}
	asked := p.dock.Last("dhcp/scopes/set")
	for param, want := range map[string]string{"name": "Guest", "startingAddress": "10.30.0.10", "endingAddress": "10.30.0.99", "subnetMask": "255.255.255.0", "leaseTimeDays": "0", "leaseTimeHours": "12", "leaseTimeMinutes": "0", "domainName": "guest.example", "routerAddress": "10.30.0.1", "dnsServers": "10.30.0.2", "useThisDnsServer": "true", "dnsUpdates": "false", "exclusions": "10.30.0.90|10.30.0.99"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the scope was made with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if got := writes(); !slices.Equal(got, []string{"set Guest", "disable Guest"}) {
		t.Errorf("the writes = %v", got)
	}

	// there, and asked for as it is: nothing is written; switched on: one call
	p.dock.Then("dhcp/scopes/set", nil)
	if same := suite.Call(t, "dhcp_scope_set", map[string]any{"server": "dock", "scope": "guest", "lease_time": "12h", "use_this_dns_server": true}); acctest.BoolOf(same["changed"]) || len(writes()) != 2 || acctest.Object(t, same["after"], "after")["scope"] != "Guest" {
		t.Errorf("a scope already as asked = %v, with writes %v", same, writes())
	}
	p.dock.Then("dhcp/scopes/enable", func(technitiumtest.Request) { guest(p, true) })
	on := suite.Call(t, "dhcp_scope_set", map[string]any{"server": "dock", "scope": "Guest", "enabled": true})
	if got := acctest.Strs(t, on["changes"], "changes"); !slices.Equal(got, []string{"switched the scope on: it leases from now"}) || !acctest.BoolOf(acctest.Object(t, on["after"], "after")["enabled"]) || !slices.Equal(writes(), []string{"set Guest", "enable Guest", "disable Guest"}) {
		t.Errorf("switched on = %v, with writes %v", on, writes())
	}
	// one thing of a scope that is there: its range goes with it, and the rest is left out to stay as it is
	changed := suite.Call(t, "dhcp_scope_set", map[string]any{"server": "dock", "scope": "Guest", "only_reserved": true})
	if asked = p.dock.Last("dhcp/scopes/set"); asked.Params.Get("allowOnlyReservedLeases") != "true" || asked.Params.Get("startingAddress") != "10.30.0.10" || asked.Params.Has("domainName") || asked.Params.Has("exclusions") || asked.Params.Has("dnsUpdates") || !slices.Equal(acctest.Strs(t, changed["changes"], "changes"), []string{"set the scope Guest on dock as asked: it leases 10.30.0.10-10.30.0.99 in 10.30.0.0/24"}) {
		t.Errorf("one thing changed = %v, sent %v", changed, asked.Params)
	}
	p.dock.Then("dhcp/scopes/disable", func(technitiumtest.Request) { guest(p, false) })
	off := suite.Call(t, "dhcp_scope_set", map[string]any{"server": "dock", "scope": "Guest", "enabled": false})
	if got := acctest.Strs(t, off["changes"], "changes"); !slices.Equal(got, []string{"switched the scope off: it leases nothing, and keeps its reservations and what it has leased"}) {
		t.Errorf("switched off = %v", got)
	}

	// what could not work, or would lease what another scope does, is refused before anything is written
	p.rpi.Answer("dhcp/scopes/list", `{"scopes":[`+strings.ReplaceAll(strings.ReplaceAll(lanScopeListed, "10.20.0.100", "10.40.0.50"), "10.20.0.119", "10.40.0.80")+`]}`)
	p.rpi.Answer("dhcp/scopes/get", scopeJSON("LAN", "10.40.0.50", "10.40.0.80", `"useThisDnsServer":true`))
	sent := len(writes())
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"a new scope with no range":          {map[string]any{"scope": "New"}, "dock has no scope named New (it has Default (192.168.1.0/24), LAN (10.20.0.0/24), Lab (10.20.5.0/24), Guest (10.30.0.0/24)), and one is made with the first and last address of its range and its mask"},
		"no address":                         {map[string]any{"scope": "New", "first": "ten", "last": "10.50.0.9", "mask": "24"}, `first "ten" is not an IPv4 address`},
		"no mask":                            {map[string]any{"scope": "New", "first": "10.50.0.1", "last": "10.50.0.9", "mask": "255.0.255.0"}, "is no subnet mask"},
		"a range that ends before it starts": {map[string]any{"scope": "New", "first": "10.50.0.9", "last": "10.50.0.1", "mask": "24"}, "the range ends at 10.50.0.1, before it starts at 10.50.0.9"},
		"a range in two networks":            {map[string]any{"scope": "New", "first": "10.50.0.9", "last": "10.50.1.9", "mask": "24"}, "are not in one network with the mask 255.255.255.0"},
		"an exclusion outside the range":     {map[string]any{"scope": "New", "first": "10.50.0.10", "last": "10.50.0.90", "mask": "24", "exclusions": []string{"10.50.0.95-10.50.0.99"}}, "is not a run of the range 10.50.0.10-10.50.0.90"},
		"a gateway in another network":       {map[string]any{"scope": "New", "first": "10.50.0.10", "last": "10.50.0.90", "mask": "24", "router": "10.51.0.1"}, "is not an address in 10.50.0.0/24"},
		"a name server by name":              {map[string]any{"scope": "New", "first": "10.50.0.10", "last": "10.50.0.90", "mask": "24", "dns_servers": []string{"dock.example.com"}}, "machines are told name servers by address"},
		"no lease time":                      {map[string]any{"scope": "Guest", "lease_time": "a while"}, "lease_time:"},
		"a range another scope here has":     {map[string]any{"scope": "New", "first": "10.20.0.110", "last": "10.20.0.150", "mask": "24"}, "the range 10.20.0.110-10.20.0.150 runs into that of scope LAN on dock, 10.20.0.100-10.20.0.119"},
		"a range another server leases":      {map[string]any{"scope": "New", "first": "10.40.0.70", "last": "10.40.0.120", "mask": "24", "enabled": true}, "rpi leases 10.40.0.70-10.40.0.80 from its scope LAN, which is on, and this scope would lease the same"},
		"no scope":                           {map[string]any{"scope": " "}, "which scope"},
	} {
		refused.args["server"] = "dock"
		if msg := suite.CallErr(t, "dhcp_scope_set", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
	if len(writes()) != sent {
		t.Errorf("%d refused changes reached the server: %v", len(writes())-sent, writes()[sent:])
	}
	// left off, a scope may share a range with one that is on elsewhere: it leases nothing
	if spare := suite.Call(t, "dhcp_scope_set", map[string]any{"server": "dock", "scope": "Spare", "first": "10.40.0.70", "last": "10.40.0.120", "mask": "24", "dry_run": true}); len(acctest.Strs(t, spare["changes"], "changes")) != 2 {
		t.Errorf("a scope left off over another server's range = %v", spare)
	}
}

// A mask is read as one or as its bits, and a run as its two ends.
func TestMaskOf(t *testing.T) {
	t.Parallel()

	for text, want := range map[string]string{"255.255.255.0": "255.255.255.0", "24": "255.255.255.0", "/16": "255.255.0.0", "255.255.240.0": "255.255.240.0", "30": "255.255.255.252"} {
		if got, ok := maskOf(text); !ok || got.String() != want {
			t.Errorf("maskOf(%q) = %s, %v, want %s", text, got, ok, want)
		}
	}
	for _, not := range []string{"", "0", "32", "255.0.255.0", "0.0.0.0", "mask", "10.0.0.1"} {
		if got, ok := maskOf(not); ok {
			t.Errorf("maskOf(%q) = %s, want none", not, got)
		}
	}
	if first, last, ok := rangeOf(" 10.0.0.5-10.0.0.9 "); !ok || first.String() != "10.0.0.5" || last.String() != "10.0.0.9" {
		t.Errorf("rangeOf = %s, %s, %v", first, last, ok)
	}
	for _, not := range []string{"10.0.0.5", "10.0.0.9-10.0.0.5", "a-b"} {
		if _, _, ok := rangeOf(not); ok {
			t.Errorf("rangeOf(%q) was read as a run", not)
		}
	}
}
