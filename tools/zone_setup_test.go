package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

const (
	primaryOptions = `{"name":"example.com","type":"Primary","dnssecStatus":"Unsigned","notifyFailed":true,"notifyFailedFor":["10.0.0.3"],"disabled":false,"catalog":null,"queryAccess":"Allow","queryAccessNetworkACL":[],"zoneTransfer":"UseSpecifiedNetworkACL","zoneTransferNetworkACL":["10.0.0.3"],"zoneTransferTsigKeyNames":["home"],"notify":"ZoneNameServers","notifyNameServers":[],"update":"UseSpecifiedNetworkACL","updateNetworkACL":["10.0.0.0/24"],"updateSecurityPolicies":[{"tsigKeyName":"home","domain":"*.example.com","allowedTypes":["A","AAAA"]}]}`
	copyOptions    = `{"name":"example.com","type":"Secondary","disabled":false,"catalog":null,"primaryNameServerAddresses":["10.0.0.2"],"primaryZoneTransferProtocol":"Tls","primaryZoneTransferTsigKeyName":"home","queryAccess":"Allow","zoneTransfer":"Deny","notify":"None","update":"Deny"}`
	apexRecords    = `{"zone":{"name":"example.com"},"records":[{"name":"example.com","type":"SOA","ttl":900,"rData":{"primaryNameServer":"dock","responsiblePerson":"hostadmin@example.com","serial":7,"refresh":900,"retry":300,"expire":604800,"minimum":900}},{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"rpi"}},{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"dock"}},{"name":"example.com","type":"MX","ttl":3600,"rData":{"preference":10,"exchange":"mail.example.com"}}]}`
)

// setupPair is two servers of which dock holds a zone as its own and rpi a
// copy of it, and dock one more alone.
func setupPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"only.example","type":"Primary","soaSerial":1}]}`)
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Secondary","soaSerial":6}]}`)
	p.dock.Answer("zones/options/get", primaryOptions)
	p.rpi.Answer("zones/options/get", copyOptions)
	p.both("zones/records/get", apexRecords)
	p.dock.AnswerText("zones/export", "$ORIGIN example.com.\n@ 900 IN SOA dock. hostadmin 7 900 300 604800 900\n@ 14400 IN NS dock.\na 3600 IN A 10.0.0.4\t\t\t;the emby vm\nb 3600 IN A 10.0.0.5\n")
	p.rpi.AnswerText("zones/export", "$ORIGIN example.com.\n@ 900 IN SOA dock. hostadmin 6 900 300 604800 900\n")

	return p
}

// zone_get sets how each holder serves and copies a zone side by side.
func TestZoneGet(t *testing.T) {
	t.Parallel()

	p := setupPair(t)
	suite := p.session(t, Options{})

	out := suite.Call(t, "zone_get", map[string]any{"zone": "Example.com."})
	rows := acctest.Rows(t, out["servers"], "servers")
	if out["zone"] != "example.com" || len(rows) != 2 || out["missing_on"] != nil {
		t.Fatalf("the answer = %v", out)
	}
	d := rows[0]
	if d["server"] != "dock" || d["type"] != "Primary" || d["disabled"] != nil || d["catalog"] != nil || d["dnssec"] != nil || acctest.Num(t, d["serial"], "serial") != 7 || d["soa_primary"] != "dock" || d["soa_responsible"] != "hostadmin@example.com" || acctest.Num(t, d["refresh"], "refresh") != 900 || acctest.Num(t, d["retry"], "retry") != 300 || acctest.Num(t, d["expire"], "expire") != 604800 || acctest.Num(t, d["minimum"], "minimum") != 900 {
		t.Errorf("dock's zone = %v", d)
	}
	if !slices.Equal(acctest.Texts(d["name_servers"]), []string{"dock", "rpi"}) || d["query"] != "Allow" || d["transfer"] != "UseSpecifiedNetworkACL" || !slices.Equal(acctest.Texts(d["transfer_networks"]), []string{"10.0.0.3"}) || !slices.Equal(acctest.Texts(d["transfer_keys"]), []string{"home"}) || d["notify"] != "ZoneNameServers" || !slices.Equal(acctest.Texts(d["notify_failed_for"]), []string{"10.0.0.3"}) || d["update"] != "UseSpecifiedNetworkACL" || !slices.Equal(acctest.Texts(d["update_networks"]), []string{"10.0.0.0/24"}) || !slices.Equal(acctest.Texts(d["update_keys"]), []string{"home for *.example.com: A, AAAA"}) || d["primary_addresses"] != nil {
		t.Errorf("who may do what with dock's zone = %v", d)
	}
	if r := rows[1]; r["server"] != "rpi" || r["type"] != "Secondary" || acctest.Num(t, r["serial"], "serial") != 6 || !slices.Equal(acctest.Texts(r["primary_addresses"]), []string{"10.0.0.2"}) || r["primary_protocol"] != "Tls" || r["primary_key"] != "home" || r["transfer"] != "Deny" || r["notify"] != "None" || r["transfer_keys"] != nil {
		t.Errorf("rpi's copy = %v", r)
	}
	if !slices.Equal(acctest.Strs(t, out["differ"], "differ"), []string{"type", "serial", "transfer", "notify", "update"}) {
		t.Errorf("differ = %v", out["differ"])
	}
	if asked := p.dock.Last("zones/options/get"); asked.Params.Get("zone") != "example.com" {
		t.Errorf("the options were asked for with %v", asked.Params)
	}

	// a zone one server alone holds is said to be missing on the other
	alone := suite.Call(t, "zone_get", map[string]any{"zone": "only.example"})
	if got := acctest.Rows(t, alone["servers"], "servers"); len(got) != 1 || got[0]["server"] != "dock" || !slices.Equal(acctest.Strs(t, alone["missing_on"], "missing_on"), []string{"rpi"}) || alone["differ"] != nil {
		t.Errorf("a zone one server holds = %v", alone)
	}
	// a server that will not give the options is a row that says so
	p.rpi.Fail("zones/options/get", "error", "Access was denied.")
	if got := acctest.Rows(t, suite.Call(t, "zone_get", map[string]any{"zone": "example.com"})["servers"], "servers"); len(got) != 2 || got[1]["error"] != "zones/options/get: Access was denied." || got[0]["type"] != "Primary" {
		t.Errorf("with rpi refusing = %v", got)
	}

	if msg := suite.CallErr(t, "zone_get", map[string]any{"zone": "nope.example"}); !strings.Contains(msg, "no server asked holds a zone named nope.example") {
		t.Errorf("a zone nobody holds = %q", msg)
	}
	if msg := suite.CallErr(t, "zone_get", map[string]any{"zone": " "}); !strings.Contains(msg, "which zone") {
		t.Errorf("no zone = %q", msg)
	}
}

// zone_export gives a zone as a zone file, from the server that holds it as
// its own unless another is named.
func TestZoneExport(t *testing.T) {
	t.Parallel()

	p := setupPair(t)
	suite := p.session(t, Options{})

	out := suite.Call(t, "zone_export", map[string]any{"zone": "example.com"})
	if out["server"] != "dock" || acctest.Num(t, out["lines"], "lines") != 5 || !strings.HasPrefix(acctest.Str(out["text"]), "$ORIGIN example.com.\n") || !strings.Contains(acctest.Str(out["text"]), ";the emby vm") || !strings.HasSuffix(acctest.Str(out["text"]), "b 3600 IN A 10.0.0.5") || out["note"] != nil {
		t.Errorf("the export = %v", out)
	}
	if len(p.rpi.Requests("zones/export")) != 0 || p.dock.Last("zones/export").Params.Get("zone") != "example.com" {
		t.Errorf("the copy was exported, or the zone asked for was %v", p.dock.Last("zones/export").Params)
	}
	// the copy when it is asked for by name
	if from := suite.Call(t, "zone_export", map[string]any{"zone": "example.com", "server": "rpi"}); from["server"] != "rpi" || acctest.Num(t, from["lines"], "lines") != 2 {
		t.Errorf("the copy's export = %v", from)
	}
	// a few lines at a time
	paged := suite.Call(t, "zone_export", map[string]any{"zone": "example.com", "limit": 2, "offset": 1})
	if text := acctest.Str(paged["text"]); !strings.HasPrefix(text, "@ 900 IN SOA") || strings.Count(text, "\n") != 1 || !strings.Contains(acctest.Str(paged["note"]), "the file has 5 lines and 2 are given, starting at the 2nd: read on with offset 3") {
		t.Errorf("paged = %v", paged)
	}

	// two servers each holding it as their own: which is asked
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":6}]}`)
	if msg := suite.CallErr(t, "zone_export", map[string]any{"zone": "example.com"}); !strings.Contains(msg, "dock and rpi each hold example.com as a zone of their own: say which to export from with server") {
		t.Errorf("a zone two hold as their own = %q", msg)
	}
	if msg := suite.CallErr(t, "zone_export", map[string]any{"zone": "nope.example"}); !strings.Contains(msg, "no server holds a zone named nope.example") {
		t.Errorf("a zone nobody holds = %q", msg)
	}
	p.dock.Fail("zones/export", "error", "No such zone was found: gone.example")
	if msg := suite.CallErr(t, "zone_export", map[string]any{"zone": "gone.example", "server": "dock"}); !strings.Contains(msg, "dock: zones/export: No such zone was found") {
		t.Errorf("a zone the server named does not hold = %q", msg)
	}
}
