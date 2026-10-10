package tools

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// Every record type is set from one line, what a type has beside its value
// goes in options, and a record changed keeps the options it was not given:
// the server resets what a change leaves out.
func TestRecordSetEveryTypeAndItsOptions(t *testing.T) {
	t.Parallel()

	p := writePair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Forwarder","soaSerial":7}]}`)
	suite := p.session(t, everything)

	// a forwarder for part of the zone, added with how it is reached
	fwd := rec("lab.example.com", "FWD", `{"protocol":"Tls","forwarder":"10.0.0.53","priority":5,"dnssecValidation":true,"proxyType":"NoProxy"}`)
	p.dock.Then("zones/records/add", func(technitiumtest.Request) { at(p.dock, "lab.example.com", fwd) })
	added := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "lab.example.com", "type": "fwd", "value": "Tls 10.0.0.53", "options": map[string]string{"forwarderPriority": "5", "dnssecValidation": "true", "proxyType": "NoProxy"}})
	asked := p.dock.Last("zones/records/add")
	for param, want := range map[string]string{"type": "FWD", "protocol": "Tls", "forwarder": "10.0.0.53", "forwarderPriority": "5", "dnssecValidation": "true", "proxyType": "NoProxy"} {
		if asked.Params.Get(param) != want {
			t.Errorf("a forwarder was added with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	row := acctest.Rows(t, added["after"], "after")[0]
	if options := acctest.Object(t, row["options"], "options"); row["value"] != "Tls 10.0.0.53" || options["forwarderPriority"] != "5" || options["dnssecValidation"] != "true" || options["proxyType"] != "NoProxy" {
		t.Errorf("the forwarder read back = %v", row)
	}

	// set again as it is: nothing to do. Its TTL changed: every option goes with the change
	if same := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "lab.example.com", "type": "FWD", "value": "Tls 10.0.0.53", "options": map[string]string{"forwarderPriority": "5"}}); acctest.BoolOf(same["changed"]) || len(p.dock.Requests("zones/records/update")) != 0 {
		t.Errorf("set as it is = %v", same["changes"])
	}
	changed := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "lab.example.com", "type": "FWD", "value": "Tls 10.0.0.53", "options": map[string]string{"forwarderPriority": "9", "proxyPassword": "pr0xy-5ecre7"}})
	update := p.dock.Last("zones/records/update")
	for param, want := range map[string]string{"protocol": "Tls", "forwarder": "10.0.0.53", "newProtocol": "Tls", "newForwarder": "10.0.0.53", "forwarderPriority": "9", "dnssecValidation": "true", "proxyType": "NoProxy", "proxyPassword": "pr0xy-5ecre7"} {
		if update.Params.Get(param) != want {
			t.Errorf("the forwarder was changed with %s=%q, want %q", param, update.Params.Get(param), want)
		}
	}
	if got := acctest.Strs(t, changed["changes"], "changes"); !slices.Equal(got, []string{`changed the FWD record at lab.example.com: its forwarderPriority from "5" to "9", its proxyPassword`}) || strings.Contains(fmt.Sprint(changed), "pr0xy-5ecre7") {
		t.Errorf("changes = %q", got)
	}

	// an app's record, by the app's name with its spaces, with what the app is told
	// the canned server holds nothing it is sent, which the tool says of each: what it sent is what is looked at
	const notHeld = "the server took the change and does not hold"
	if msg := suite.CallErr(t, "record_set", map[string]any{"server": "dock", "name": "www.example.com", "type": "APP", "value": "Split Horizon SplitHorizon.SimpleAddress", "options": map[string]string{"recordData": `{"private":["10.0.0.4"]}`}}); !strings.Contains(msg, notHeld) {
		t.Errorf("an app's record = %q", msg)
	}
	if asked = p.dock.Last("zones/records/add"); asked.Params.Get("appName") != "Split Horizon" || asked.Params.Get("classPath") != "SplitHorizon.SimpleAddress" || asked.Params.Get("recordData") != `{"private":["10.0.0.4"]}` {
		t.Errorf("an app's record was added with %v", asked.Params)
	}
	// and the rest by their one line
	for recordType, tc := range map[string]struct{ value, param, want string }{
		"HTTPS": {"1 . alpn=h2,h3", "svcParams", "alpn|h2,h3"},
		"TLSA":  {"DANE-EE SPKI SHA2-256 AB12", "tlsaCertificateAssociationData", "AB12"},
		"SSHFP": {"Ed25519 SHA256 AB12", "sshfpFingerprint", "AB12"},
		"NAPTR": {`100 10 "S" "SIP+D2U" "" _sip._udp.example.com`, "naptrRegexp", ""},
		"URI":   {"10 1 https://example.com/", "uri", "https://example.com/"},
		"RP":    {"admin@example.com info.example.com", "txtDomain", "info.example.com"},
		"DS":    {"12345 ECDSAP256SHA256 SHA256 AB12", "digest", "AB12"},
		"LOC":   {"01:02:03", "rdata", "01:02:03"},
	} {
		if msg := suite.CallErr(t, "record_set", map[string]any{"server": "dock", "name": "t.example.com", "type": recordType, "value": tc.value}); !strings.Contains(msg, notHeld) {
			t.Errorf("a %s = %q", recordType, msg)
		}
		if asked = p.dock.Last("zones/records/add"); asked.Params.Get("type") != recordType || !asked.Params.Has(tc.param) || asked.Params.Get(tc.param) != tc.want {
			t.Errorf("a %s was added with %v", recordType, asked.Params)
		}
	}

	sent := len(writes(p.dock))
	for msg, args := range map[string]map[string]any{
		"a A record has no options beside its value":                           {"type": "A", "value": "10.0.0.4", "options": map[string]string{"glue": "10.0.0.9"}},
		"a FWD record has no option named glue: it has forwarderPriority":      {"type": "FWD", "value": "Udp 10.0.0.53", "options": map[string]string{"glue": "10.0.0.9"}},
		"takes one as its bytes in hex":                                        {"type": "LOC", "value": "52 22 23 N"},
		"a RRSIG record is not added, changed or deleted as other records are": {"type": "RRSIG", "value": "A 13 2"},
		"an APP record's value is the app's name and then the class":           {"type": "APP", "value": "SplitHorizon"},
	} {
		args["server"], args["name"] = "dock", "t.example.com"
		if got := suite.CallErr(t, "record_set", args); !strings.Contains(got, msg) {
			t.Errorf("record_set %v = %q, want %q in it", args, got, msg)
		}
	}
	if len(writes(p.dock)) != sent {
		t.Error("a record that was refused reached the server")
	}

	// zone_records gives a record's options beside its value, and two servers holding it with different ones as two rows
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Forwarder","soaSerial":7}]}`)
	glued := `{"name":"sub.example.com","type":"NS","ttl":3600,"rData":{"nameServer":"ns.sub.example.com"},"glueRecords":["10.0.0.9"]}`
	p.dock.Answer("zones/records/get", `{"zone":{"name":"example.com"},"records":[`+fwd+`,`+glued+`]}`)
	p.rpi.Answer("zones/records/get", `{"zone":{"name":"example.com"},"records":[`+strings.Replace(fwd, `"priority":5`, `"priority":0`, 1)+`,`+glued+`]}`)
	rows := acctest.Rows(t, suite.Call(t, "zone_records", map[string]any{"zone": "example.com"})["records"], "records")
	var forwarders, glue int
	for _, r := range rows {
		switch options := acctest.Object(t, r["options"], "options"); r["type"] {
		case "FWD":
			forwarders++
			if len(acctest.Strs(t, r["only_on"], "only_on")) != 1 || options["proxyType"] != "NoProxy" {
				t.Errorf("a forwarder two servers reach differently = %v", r)
			}
		case "NS":
			glue++
			if options["glue"] != "10.0.0.9" || r["only_on"] != nil {
				t.Errorf("a name server with glue = %v", r)
			}
		default:
		}
	}
	if forwarders != 2 || glue != 1 {
		t.Errorf("zone_records = %d forwarder rows and %d glued, want 2 and 1: %v", forwarders, glue, rows)
	}
}

// A scope is set with the rest of what it can hand out, renamed, and read
// back with it; set again as it is, nothing is sent.
func TestDHCPScopeSetTheRest(t *testing.T) {
	t.Parallel()

	p := dhcpPair(t)
	suite := p.session(t, everything)
	more := map[string]any{"server": "dock", "scope": "LAN", "dns_ttl": 600, "dns_overwrite": true, "domain_search": []string{"lan.example", "example.com"}, "ntp_servers": []string{"10.20.0.7"}, "ntp_server_names": []string{"pool.ntp.org"}, "wins_servers": []string{"10.20.0.6"}, "static_routes": []string{"10.30.0.0/16 via 10.20.0.2"}, "boot_server": "10.20.0.5", "boot_server_name": "tftp", "boot_file": "boot.bin", "tftp_servers": []string{"10.20.0.5"}, "capwap_controllers": []string{"10.20.0.8"}, "vendor_info": []map[string]any{{"identifier": "PXEClient", "information": "06:01:03"}}, "generic_options": []map[string]any{{"code": 150, "value": "0A:14:00:05"}}, "offer_delay_ms": 250, "ping_check": true, "ping_timeout_ms": 500, "ping_retries": 3, "block_local_mac": true, "ignore_client_id": true}

	dry := suite.Call(t, "dhcp_scope_set", withArg(more, "dry_run", true))
	if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != 1 || !strings.HasPrefix(got[0], "would have set the scope LAN on dock as asked") || len(dhcpWritten(p.dock)) != 0 {
		t.Errorf("a dry run = %q", got)
	}
	whole := scopeJSON("LAN", "10.20.0.100", "10.20.0.119", lanScopeOptions+`,"dnsTtl":600,"dnsOverwriteForDynamicLease":true,"domainSearchList":["lan.example","example.com"],"ntpServers":["10.20.0.7"],"ntpServerDomainNames":["pool.ntp.org"],"winsServers":["10.20.0.6"],"staticRoutes":[{"destination":"10.30.0.0","subnetMask":"255.255.0.0","router":"10.20.0.2"}],"serverAddress":"10.20.0.5","serverHostName":"tftp","bootFileName":"boot.bin","tftpServerAddresses":["10.20.0.5"],"capwapAcIpAddresses":["10.20.0.8"],"vendorInfo":[{"identifier":"PXEClient","information":"06:01:03"}],"genericOptions":[{"code":150,"value":"0A:14:00:05"}],"offerDelayTime":250,"pingCheckEnabled":true,"pingCheckTimeout":500,"pingCheckRetries":3,"blockLocallyAdministeredMacAddresses":true,"ignoreClientIdentifierOption":true`)
	p.dock.Then("dhcp/scopes/set", func(technitiumtest.Request) { p.dock.AnswerWhen("dhcp/scopes/get", "name", "LAN", whole) })
	out := suite.Call(t, "dhcp_scope_set", more)
	asked := p.dock.Last("dhcp/scopes/set")
	for param, want := range map[string]string{"dnsTtl": "600", "dnsOverwriteForDynamicLease": "true", "domainSearchList": "lan.example,example.com", "ntpServers": "10.20.0.7", "ntpServerDomainNames": "pool.ntp.org", "winsServers": "10.20.0.6", "staticRoutes": "10.30.0.0|255.255.0.0|10.20.0.2", "serverAddress": "10.20.0.5", "serverHostName": "tftp", "bootFileName": "boot.bin", "tftpServerAddresses": "10.20.0.5", "capwapAcIpAddresses": "10.20.0.8", "vendorInfo": "PXEClient|06:01:03", "genericOptions": "150|0A:14:00:05", "offerDelayTime": "250", "pingCheckEnabled": "true", "pingCheckTimeout": "500", "pingCheckRetries": "3", "blockLocallyAdministeredMacAddresses": "true", "ignoreClientIdentifierOption": "true"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the scope was set with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	// the reservations are not sent: left out, the scope keeps them
	if asked.Params.Has("reservedLeases") || asked.Params.Has("newName") {
		t.Errorf("the scope was set with %v", asked.Params)
	}
	got := acctest.Object(t, acctest.Object(t, out["after"], "after")["more"], "more")
	if !slices.Equal(acctest.Strs(t, got["static_routes"], "static_routes"), []string{"10.30.0.0/16 via 10.20.0.2"}) || got["boot_file"] != "boot.bin" || acctest.Num(t, got["ping_retries"], "ping_retries") != 3 || !acctest.BoolOf(got["block_local_mac"]) || acctest.Num(t, acctest.Rows(t, got["generic_options"], "generic_options")[0]["code"], "code") != 150 {
		t.Errorf("the scope read back = %v", got)
	}

	// as it is now: nothing is sent. Renamed: the new name goes with the rest
	sent := len(p.dock.Requests("dhcp/scopes/set"))
	if same := suite.Call(t, "dhcp_scope_set", more); acctest.BoolOf(same["changed"]) || len(p.dock.Requests("dhcp/scopes/set")) != sent {
		t.Errorf("set as it is = %v", same["changes"])
	}
	renamed := suite.Call(t, "dhcp_scope_set", map[string]any{"server": "dock", "scope": "LAN", "new_name": "Office", "dry_run": true})
	if got := acctest.Strs(t, renamed["changes"], "changes"); !slices.Equal(got, []string{"would have renamed the scope LAN to Office"}) {
		t.Errorf("a dry run of a rename = %q", got)
	}
	for msg, args := range map[string]map[string]any{
		"the route \"10.30.0.0 via there\" is not one":    {"server": "dock", "scope": "LAN", "static_routes": []string{"10.30.0.0 via there"}},
		"ntp_servers: \"pool.ntp.org\" is not an address": {"server": "dock", "scope": "LAN", "ntp_servers": []string{"pool.ntp.org"}},
		"boot_server \"tftp\" is not an address":          {"server": "dock", "scope": "LAN", "boot_server": "tftp"},
		"a DHCP option's number is 1 to 254":              {"server": "dock", "scope": "LAN", "generic_options": []map[string]any{{"code": 300, "value": "01"}}},
		"dock has a scope named Lab already":              {"server": "dock", "scope": "LAN", "new_name": "lab"},
		"dock has no scope named WAN to rename":           {"server": "dock", "scope": "WAN", "new_name": "Office", "first": "10.99.0.10", "last": "10.99.0.20", "mask": "24"},
	} {
		if got := suite.CallErr(t, "dhcp_scope_set", args); !strings.Contains(got, msg) {
			t.Errorf("dhcp_scope_set %v = %q, want %q in it", args, got, msg)
		}
	}
	if len(p.dock.Requests("dhcp/scopes/set")) != sent {
		t.Error("a scope that was refused, or a dry run, reached the server")
	}
}

// withArg is a tool's arguments with one more.
func withArg(args map[string]any, name string, value any) map[string]any {
	out := map[string]any{name: value}
	maps.Copy(out, args)

	return out
}

// The smaller things a tool passes on: a network to ask as if from, the class
// a query was asked in, how the clients are listed, and a list walked upward.
func TestTheRestOfWhatToolsPassOn(t *testing.T) {
	t.Parallel()

	p := opsPair(t)
	p.both("dnsClient/resolve", answerOf("", "10.0.0.4"))
	p.both("dashboard/stats/get", dockStats)
	p.both("dashboard/stats/getTop", `{"topClients":[{"name":"10.0.0.5","hits":463,"rateLimited":true}]}`)
	p.both("blocked/list", `{"domain":"example.net","zones":["ads"],"records":[]}`)
	p.both("allowed/list", `{"domain":"example.net","zones":[],"records":[]}`)
	suite := p.session(t, Options{})

	suite.Call(t, "dns_resolve", map[string]any{"server": "dock", "name": "www.example.com", "client_subnet": " 203.0.113.0/24 "})
	if asked := p.dock.Last("dnsClient/resolve"); asked.Params.Get("eDnsClientSubnet") != "203.0.113.0/24" {
		t.Errorf("asked as if from a network with %v", asked.Params)
	}
	if msg := suite.CallErr(t, "dns_resolve", map[string]any{"name": "www.example.com", "client_subnet": "somewhere"}); !strings.Contains(msg, `client_subnet "somewhere" is no network`) {
		t.Errorf("a network that is none = %q", msg)
	}

	suite.Call(t, "log_search", map[string]any{"server": "dock", "class": "ch"})
	suite.Call(t, "log_export", map[string]any{"server": "dock", "class": "ch"})
	if p.dock.Last("logs/query").Params.Get("qclass") != "CH" || p.dock.Last("logs/export").Params.Get("qclass") != "CH" {
		t.Errorf("the class was sent as %q and %q", p.dock.Last("logs/query").Params.Get("qclass"), p.dock.Last("logs/export").Params.Get("qclass"))
	}

	// the clients held back, by address: the list is asked for by itself, and every query type is counted
	suite.Call(t, "server_stats", map[string]any{"server": "dock", "window": "day", "every_type": true, "rate_limited": true, "by_address_only": true})
	if p.dock.Last("dashboard/stats/get").Params.Get("dontTrimQueryTypeData") != "true" {
		t.Errorf("the statistics were asked for with %v", p.dock.Last("dashboard/stats/get").Params)
	}
	if top := p.dock.Requests("dashboard/stats/getTop"); len(top) != 1 || top[0].Params.Get("statsType") != "TopClients" || top[0].Params.Get("onlyRateLimitedClients") != "true" || top[0].Params.Get("noReverseLookup") != "true" {
		t.Errorf("the clients were asked for with %v", top)
	}
	suite.Call(t, "server_stats", map[string]any{"server": "rpi"})
	if len(p.rpi.Requests("dashboard/stats/getTop")) != 0 || p.rpi.Last("dashboard/stats/get").Params.Has("dontTrimQueryTypeData") {
		t.Error("the statistics asked for plainly asked for a list by itself")
	}

	up := acctest.Rows(t, suite.Call(t, "block_tree", map[string]any{"server": "dock", "under": "a.b.example.net", "above": true})["servers"], "servers")[0]
	if asked := p.dock.Last("blocked/list"); up["at"] != "example.net" || asked.Params.Get("direction") != "up" || asked.Params.Get("domain") != "a.b.example.net" {
		t.Errorf("walked upward = %v, asked with %v", up, asked.Params)
	}
	suite.Call(t, "block_tree", map[string]any{"server": "dock", "list": "allowed", "under": "a.example.net", "above": true})
	if asked := p.dock.Last("allowed/list"); asked.Params.Get("direction") != "up" {
		t.Errorf("the allowed names walked upward with %v", asked.Params)
	}
	if msg := suite.CallErr(t, "block_tree", map[string]any{"above": true}); !strings.Contains(msg, "above looks upward from a name") {
		t.Errorf("upward from nothing = %q", msg)
	}
}

// A name's records are copied in from another name server: asked for first,
// so that nothing is written when there is nothing to copy, and a dry run
// says where they would go.
func TestDNSImport(t *testing.T) {
	t.Parallel()

	p := writePair(t)
	p.both("dnsClient/resolve", `{"result":{"Metadata":{"NameServer":"ns.elsewhere (192.0.2.53)"},"RCODE":"NoError","Answer":[{"Name":"www.example.com","Type":"A","TTL":"300 (5m)","RDATA":{"IPAddress":"192.0.2.10"}},{"Name":"www.example.com","Type":"A","TTL":"300 (5m)","RDATA":{"IPAddress":"192.0.2.11"}}]}}`)
	suite := p.session(t, everything)

	dry := suite.Call(t, "dns_import", map[string]any{"server": "dock", "name": "WWW.example.com.", "from": "192.0.2.53", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have copied 2 records for A www.example.com into example.com on dock, in place of the ones of that type it had there"}) || dry["zone"] != "example.com" || len(acctest.Strs(t, dry["records"], "records")) != 2 || dry["asked"] != "ns.elsewhere (192.0.2.53)" {
		t.Errorf("a dry run = %v", dry)
	}
	for _, asked := range p.dock.Requests("dnsClient/resolve") {
		if asked.Method != http.MethodGet || asked.Params.Has("import") {
			t.Errorf("a dry run asked with %s %v", asked.Method, asked.Params)
		}
	}

	// copied in: the question is put again as a change, and the records read back
	at(p.dock, "www.example.com", addr("www.example.com", "192.0.2.10"), addr("www.example.com", "192.0.2.11"))
	out := suite.Call(t, "dns_import", map[string]any{"server": "dock", "name": "www.example.com", "from": "192.0.2.53"})
	if asked := p.dock.Last("dnsClient/resolve"); asked.Method != http.MethodPost || asked.Params.Get("import") != "true" || asked.Params.Get("server") != "192.0.2.53" || asked.Params.Get("type") != "A" || len(acctest.Rows(t, out["after"], "after")) != 2 {
		t.Errorf("copied in = %v", out)
	}
	// with no name server named the server resolves from the root, and a name it holds no zone for gets one
	other := suite.Call(t, "dns_import", map[string]any{"server": "dock", "name": "www.other.example", "type": "a", "dry_run": true})
	if asked := p.dock.Last("dnsClient/resolve"); asked.Params.Get("server") != "recursive-resolver" || other["zone"] != "www.other.example" || !strings.Contains(acctest.Str(other["note"]), "a new primary zone named www.other.example is made") {
		t.Errorf("a name with no zone = %v", other)
	}

	imports := func() int {
		n := 0
		for _, server := range []*technitiumtest.Server{p.dock, p.rpi} {
			for _, asked := range server.Requests("dnsClient/resolve") {
				if asked.Params.Has("import") {
					n++
				}
			}
		}

		return n
	}
	before := imports()
	// a copy takes no records, and an answer with none copies none
	if msg := suite.CallErr(t, "dns_import", map[string]any{"server": "rpi", "name": "www.example.com"}); !strings.Contains(msg, "rpi holds example.com as a Secondary zone") {
		t.Errorf("into a copy = %q", msg)
	}
	p.dock.Answer("dnsClient/resolve", answerOf("", ""))
	if nothing := suite.Call(t, "dns_import", map[string]any{"server": "dock", "name": "gone.example.com"}); acctest.BoolOf(nothing["changed"]) || !strings.Contains(acctest.Str(nothing["note"]), "the answer was NxDomain with no A record for gone.example.com") {
		t.Errorf("an answer with nothing in it = %v", nothing)
	}
	if msg := suite.CallErr(t, "dns_import", map[string]any{"server": "dock", "name": "www.example.com", "from": "ns.elsewhere"}); !strings.Contains(msg, `from "ns.elsewhere" is not an address`) {
		t.Errorf("a name server by name = %q", msg)
	}
	if imports() != before {
		t.Error("an import that was refused, or had nothing to copy, was made")
	}
}
