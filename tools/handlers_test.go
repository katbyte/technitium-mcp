package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/go-kt/version"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

const (
	okStatus       = `{"hasDefaultCredentials":false,"ssoEnabled":false,"server":"dock.example","status":"ok"}`
	adminSession   = `{"username":"admin","tokenName":"mcp","token":"5ecre75ecre7","info":{"version":"15.6","uptimestamp":"2026-10-09T22:35:01.5902233Z","dnsServerDomain":"dock.example","dnssecValidation":true,"clusterInitialized":false,"permissions":{"Zones":{"canView":true,"canModify":true,"canDelete":true},"Settings":{"canView":true,"canModify":true,"canDelete":true}}},"server":"dock.example","status":"ok"}`
	limitedSession = `{"username":"reader","tokenName":"ro","info":{"version":"15.5","uptimestamp":"2026-10-01T00:00:00Z","dnsServerDomain":"rpi.example","dnssecValidation":false,"clusterInitialized":true,"clusterDomain":"cluster.example","permissions":{"Zones":{"canView":true,"canModify":false,"canDelete":false},"Settings":{"canView":false,"canModify":false,"canDelete":false},"Cache":{"canView":true,"canModify":true,"canDelete":false}}},"server":"rpi.example","status":"ok"}`
	noUpdate       = `{"dnsServerEnableCheckForUpdate":true,"updateAvailable":false,"updateVersion":"15.6","currentVersion":"15.6"}`
)

// rowFor is the row for one server in a list of rows that each name theirs.
func rowFor(t *testing.T, rows []map[string]any, server string) map[string]any {
	t.Helper()

	for _, row := range rows {
		if row["server"] == server {
			return row
		}
	}
	t.Fatalf("no row for %s in %v", server, rows)

	return nil
}

// server_info describes every configured server side by side: what each is,
// who the token acts as on it and what that account may not do. The token
// the server sends back with a session is in none of it.
func TestServerInfo(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.AnswerWhole("status", okStatus)
	p.dock.AnswerWhole("user/session/get", adminSession)
	p.dock.Answer("user/checkForUpdate", noUpdate)
	p.rpi.AnswerWhole("status", `{"hasDefaultCredentials":true,"ssoEnabled":false,"server":"rpi.example","status":"ok"}`)
	p.rpi.AnswerWhole("user/session/get", limitedSession)
	p.rpi.Answer("user/checkForUpdate", `{"dnsServerEnableCheckForUpdate":true,"updateAvailable":true,"updateVersion":"15.6","currentVersion":"15.5"}`)
	p.rpi.Answer("admin/cluster/state", `{"clusterInitialized":true,"dnsServerDomain":"rpi.example","clusterDomain":"cluster.example","clusterNodes":[
		{"id":1,"name":"dock.example","type":"Primary","state":"Connected","lastSeen":"2026-10-09T23:00:00.5Z"},
		{"id":2,"name":"rpi.example","type":"Secondary","state":"Self","lastSeen":"0001-01-01T00:00:00"},
		{"id":3,"name":"gone.example","type":"Secondary","state":"Unreachable","lastSeen":"0001-01-01T00:00:00"}
	]}`)

	out := p.session(t, Options{}).Call(t, "server_info", nil)
	if out["technitium_mcp_version"] != version.Version || out["sdk_api_version"] != technitium.APIVersion {
		t.Errorf("the versions = %v and %v", out["technitium_mcp_version"], out["sdk_api_version"])
	}
	rows := acctest.Rows(t, out["servers"], "servers")
	if len(rows) != 2 || rows[0]["server"] != "dock" || rows[1]["server"] != "rpi" {
		t.Fatalf("servers = %v, want dock then rpi", rows)
	}

	dock := rows[0]
	if dock["url"] != p.dock.URL || dock["domain"] != "dock.example" || dock["version"] != "15.6" || dock["account"] != "admin" || dock["token_name"] != "mcp" || dock["started"] != "2026-10-09T22:35:01Z" || !acctest.BoolOf(dock["dnssec_validation"]) {
		t.Errorf("dock = %v", dock)
	}
	for _, absent := range []string{"error", "cluster", "cluster_role", "cluster_nodes", "update_available", "cannot_view", "cannot_modify", "cannot_delete", "default_credentials", "note"} {
		if _, there := dock[absent]; there {
			t.Errorf("dock has %s = %v, which an admin's token on a current server on its own has nothing to say for", absent, dock[absent])
		}
	}
	if acctest.Str(dock["uptime"]) == "" {
		t.Error("dock has no uptime")
	}

	rpi := rows[1]
	if rpi["cluster"] != "cluster.example" || !acctest.BoolOf(rpi["update_available"]) || rpi["update_version"] != "15.6" || !acctest.BoolOf(rpi["default_credentials"]) || !acctest.IsBool(rpi["dnssec_validation"], false) {
		t.Errorf("rpi = %v", rpi)
	}
	// its role in the cluster, and the other nodes as it sees them
	nodes := acctest.Rows(t, rpi["cluster_nodes"], "cluster_nodes")
	if rpi["cluster_role"] != "Secondary" || len(nodes) != 2 || nodes[0]["name"] != "dock.example" || nodes[0]["role"] != "Primary" || nodes[0]["state"] != "Connected" || nodes[0]["last_seen"] != "2026-10-09T23:00:00Z" {
		t.Errorf("rpi's cluster = %v with nodes %v", rpi["cluster_role"], nodes)
	}
	if gone := nodes[1]; gone["name"] != "gone.example" || gone["state"] != "Unreachable" || gone["last_seen"] != nil {
		t.Errorf("the node rpi cannot reach = %v", gone)
	}
	if got := acctest.Strs(t, rpi["cannot_view"], "cannot_view"); !slices.Equal(got, []string{"Settings"}) {
		t.Errorf("rpi cannot_view = %v", got)
	}
	if got := acctest.Strs(t, rpi["cannot_modify"], "cannot_modify"); !slices.Equal(got, []string{"Settings", "Zones"}) {
		t.Errorf("rpi cannot_modify = %v", got)
	}
	if got := acctest.Strs(t, rpi["cannot_delete"], "cannot_delete"); !slices.Equal(got, []string{"Cache", "Settings", "Zones"}) {
		t.Errorf("rpi cannot_delete = %v", got)
	}

	// one server named is that server alone
	one := acctest.Rows(t, p.session(t, Options{}).Call(t, "server_info", map[string]any{"server": "rpi"})["servers"], "servers")
	if len(one) != 1 || one[0]["server"] != "rpi" {
		t.Errorf("server_info for rpi = %v", one)
	}
	if msg := p.session(t, Options{}).CallErr(t, "server_info", map[string]any{"server": "pi"}); !strings.Contains(msg, "dock, rpi") {
		t.Errorf("a server that is not one = %q, want the ones there are", msg)
	}
}

// A server that cannot be asked is a row saying why, beside the ones that
// can: the connectivity check does not fail because one server is down, and
// says so when all are.
func TestServerInfoWhenAServerCannotBeAsked(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.AnswerWhole("status", okStatus)
	p.dock.AnswerWhole("user/session/get", adminSession)
	p.dock.Fail("user/checkForUpdate", "error", "The update server could not be reached.")
	p.rpi.AnswerWhole("status", okStatus)
	p.rpi.Fail("user/session/get", "invalid-token", "Invalid token or session expired.")

	out := p.session(t, Options{}).Call(t, "server_info", nil)
	rows := acctest.Rows(t, out["servers"], "servers")

	dock := rowFor(t, rows, "dock")
	if dock["version"] != "15.6" || !strings.Contains(acctest.Str(dock["note"]), "whether an update is out could not be asked") {
		t.Errorf("dock, whose update check failed = %v, want it described with a note", dock)
	}

	// a token that may not read the Administration section cannot list a
	// cluster's nodes: the server is described without them, and says both
	// things it could not learn
	p.dock.AnswerWhole("user/session/get", limitedSession)
	p.dock.Fail("admin/cluster/state", "error", "Access was denied.")
	clustered := rowFor(t, acctest.Rows(t, p.session(t, Options{}).Call(t, "server_info", nil)["servers"], "servers"), "dock")
	if said := acctest.Str(clustered["note"]); clustered["cluster"] != "cluster.example" || clustered["cluster_role"] != nil || !strings.Contains(said, "the cluster's nodes could not be read: admin/cluster/state: Access was denied.") || !strings.Contains(said, "; whether an update is out could not be asked") {
		t.Errorf("dock in a cluster whose nodes it may not list = %v", clustered)
	}
	p.dock.AnswerWhole("user/session/get", adminSession)
	rpi := rowFor(t, rows, "rpi")
	if msg := acctest.Str(rpi["error"]); !strings.Contains(msg, "the server answers, calling itself dock.example") || !strings.Contains(msg, "the API token was refused") {
		t.Errorf("rpi, which refused the token = %v", rpi)
	}
	if rpi["url"] != p.rpi.URL || rpi["version"] != nil {
		t.Errorf("rpi's row = %v, want its address and nothing it did not say", rpi)
	}
	if _, noted := out["note"]; noted {
		t.Errorf("one server answered, and the answer has the note for none: %v", out["note"])
	}

	p.dock.Fail("status", "error", "down")
	p.rpi.Fail("status", "error", "down")
	if out := p.session(t, Options{}).Call(t, "server_info", nil); !strings.Contains(acctest.Str(out["note"]), "no server could be asked") {
		t.Errorf("with no server answering, the note = %v", out["note"])
	}
}

const (
	dockZones = `{"zones":[
		{"name":"example.com","type":"Primary","lastModified":"2026-10-09T22:35:28.1319161Z","disabled":false,"soaSerial":7,"dnssecStatus":"Unsigned","notifyFailed":true,"notifyFailedFor":["10.0.0.3"]},
		{"name":"example.net","type":"Primary","lastModified":"2026-10-09T22:35:28Z","disabled":false,"soaSerial":3,"dnssecStatus":"SignedWithNSEC"},
		{"name":"van.example.com","type":"Primary","disabled":true,"soaSerial":1,"dnssecStatus":"Unsigned"},
		{"name":"localhost","type":"Primary","internal":true,"soaSerial":1,"dnssecStatus":"Unsigned"}
	]}`
	rpiZones = `{"zones":[
		{"name":"EXAMPLE.com","type":"Secondary","lastModified":"2026-10-08T00:00:00Z","disabled":false,"soaSerial":6,"dnssecStatus":"Unsigned","expiry":"2026-10-16T00:00:00Z","isExpired":false,"syncFailed":true},
		{"name":"example.net","type":"Primary","lastModified":"2026-10-09T22:35:28Z","disabled":false,"soaSerial":3,"dnssecStatus":"SignedWithNSEC"},
		{"name":"0.0.10.in-addr.arpa","type":"Primary","disabled":false,"soaSerial":2,"dnssecStatus":"Unsigned"}
	]}`
)

// zone_list sets the servers' zones side by side, one row a zone name: who
// holds it and how, who lacks it, and what differs between the copies.
func TestZoneList(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("zones/list", dockZones)
	p.rpi.Answer("zones/list", rpiZones)
	suite := p.session(t, Options{})

	out := suite.Call(t, "zone_list", nil)
	rows := acctest.Rows(t, out["zones"], "zones")
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, acctest.Str(row["zone"]))
	}
	// in the order a zone tree reads: by label from the right, a subdomain
	// straight after its parent, and the servers' own zones left out
	if want := []string{"0.0.10.in-addr.arpa", "example.com", "van.example.com", "example.net"}; !slices.Equal(names, want) {
		t.Fatalf("zones = %v, want %v", names, want)
	}
	if acctest.Num(t, out["total"], "total") != 4 || !slices.Equal(acctest.Strs(t, out["asked"], "asked"), []string{"dock", "rpi"}) {
		t.Errorf("total = %v, asked = %v", out["total"], out["asked"])
	}
	if _, failed := out["failed"]; failed {
		t.Errorf("both servers answered, and failed = %v", out["failed"])
	}

	// one zone under two spellings of its name is one zone, and a primary
	// with a secondary that is behind shows as both
	com := rows[1]
	on := acctest.Rows(t, com["on"], "on")
	if len(on) != 2 {
		t.Fatalf("example.com is on %v", on)
	}
	dock, rpi := rowFor(t, on, "dock"), rowFor(t, on, "rpi")
	if dock["type"] != "Primary" || acctest.Num(t, dock["serial"], "serial") != 7 || dock["modified"] != "2026-10-09T22:35:28Z" || !slices.Equal(acctest.Strs(t, dock["notify_failed"], "notify_failed"), []string{"10.0.0.3"}) {
		t.Errorf("example.com on dock = %v", dock)
	}
	if rpi["type"] != "Secondary" || acctest.Num(t, rpi["serial"], "serial") != 6 || !acctest.BoolOf(rpi["sync_failed"]) || rpi["expiry"] != "2026-10-16T00:00:00Z" {
		t.Errorf("example.com on rpi = %v", rpi)
	}
	if got := acctest.Strs(t, com["differs"], "differs"); !slices.Equal(got, []string{"type", "serial"}) {
		t.Errorf("example.com differs in %v", got)
	}
	// rpi holds a copy, so a change is made on dock
	if got := acctest.Strs(t, com["change_on"], "change_on"); !slices.Equal(got, []string{"dock"}) {
		t.Errorf("example.com can be changed on %v", got)
	}
	if _, missing := com["missing_on"]; missing {
		t.Errorf("example.com is on both, and missing_on = %v", com["missing_on"])
	}

	// held alike on both: nothing differs, and what is not so is not said
	net := rows[3]
	if _, differs := net["differs"]; differs {
		t.Errorf("example.net is the same on both, and differs = %v", net["differs"])
	}
	if _, said := net["change_on"]; said {
		t.Errorf("example.net is a primary on both, and change_on = %v", net["change_on"])
	}
	if signed := rowFor(t, acctest.Rows(t, net["on"], "on"), "dock"); signed["dnssec"] != "SignedWithNSEC" {
		t.Errorf("example.net on dock = %v", signed)
	}
	if unsigned := rowFor(t, on, "dock"); unsigned["dnssec"] != nil || unsigned["disabled"] != nil || unsigned["records"] != nil {
		t.Errorf("an unsigned, enabled zone not counted says %v", unsigned)
	}

	// on one server alone
	if got := acctest.Strs(t, rows[0]["missing_on"], "missing_on"); !slices.Equal(got, []string{"dock"}) {
		t.Errorf("the reverse zone is missing on %v", got)
	}
	van := rows[2]
	if got := acctest.Strs(t, van["missing_on"], "missing_on"); !slices.Equal(got, []string{"rpi"}) || !acctest.BoolOf(rowFor(t, acctest.Rows(t, van["on"], "on"), "dock")["disabled"]) {
		t.Errorf("van.example.com = %v", van)
	}

	// the filters: a name anywhere in the zone's, a pattern for the whole
	// of it, a type on either server, the servers' own zones on request
	for filter, want := range map[string][]string{
		"example":  {"example.com", "van.example.com", "example.net"},
		"*.com":    {"example.com", "van.example.com"},
		"*.arpa":   {"0.0.10.in-addr.arpa"},
		"e?ample*": {"example.com", "example.net"},
	} {
		got := []string{}
		for _, row := range acctest.Rows(t, suite.Call(t, "zone_list", map[string]any{"name": filter})["zones"], "zones") {
			got = append(got, acctest.Str(row["zone"]))
		}
		if !slices.Equal(got, want) {
			t.Errorf("zone_list name=%q = %v, want %v", filter, got, want)
		}
	}
	secondaries := acctest.Rows(t, suite.Call(t, "zone_list", map[string]any{"type": "secondary"})["zones"], "zones")
	if len(secondaries) != 1 || secondaries[0]["zone"] != "example.com" || len(acctest.Rows(t, secondaries[0]["on"], "on")) != 2 {
		t.Errorf("the zones a server holds as a secondary = %v, want example.com as both servers hold it", secondaries)
	}
	// asked of the server holding the copy alone, nowhere it can be changed
	// was asked: an empty list, which says so, where no list says nothing
	copyOnly := acctest.Rows(t, suite.Call(t, "zone_list", map[string]any{"server": "rpi", "name": "example.com"})["zones"], "zones")
	if got, said := copyOnly[0]["change_on"]; !said || len(acctest.Strs(t, got, "change_on")) != 0 {
		t.Errorf("a zone asked of its secondary alone can be changed on %v (said: %v), want an empty list", got, said)
	}
	if msg := suite.CallErr(t, "zone_list", map[string]any{"type": "slave"}); !strings.Contains(msg, "Primary, Secondary") {
		t.Errorf("a type that is none = %q, want the ones there are", msg)
	}
	if got := suite.Call(t, "zone_list", map[string]any{"internal": true}); acctest.Num(t, got["total"], "total") != 5 {
		t.Errorf("with the servers' own zones, total = %v", got["total"])
	}

	// one server named: its zones, and nothing called missing on a server
	// that was not asked
	alone := suite.Call(t, "zone_list", map[string]any{"server": "rpi"})
	if acctest.Num(t, alone["total"], "total") != 3 || !slices.Equal(acctest.Strs(t, alone["asked"], "asked"), []string{"rpi"}) {
		t.Errorf("rpi alone = %v", alone)
	}
	for _, row := range acctest.Rows(t, alone["zones"], "zones") {
		if row["missing_on"] != nil || row["differs"] != nil {
			t.Errorf("with one server asked, %v", row)
		}
	}

	// a limit says what it left out
	limited := suite.Call(t, "zone_list", map[string]any{"limit": 2})
	if len(acctest.Rows(t, limited["zones"], "zones")) != 2 || acctest.Num(t, limited["total"], "total") != 4 || !strings.Contains(acctest.Str(limited["note"]), "4 zones matched and the first 2 are listed") {
		t.Errorf("limited = %v", limited)
	}
}

// With counts, zone_list reads each zone on each server holding it, and a
// zone with a different number of records on each differs in that too. A
// zone that cannot be counted on one server says so there.
func TestZoneListCounts(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7,"dnssecStatus":"Unsigned"},{"name":"example.net","type":"Primary","soaSerial":1,"dnssecStatus":"Unsigned"}]}`)
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7,"dnssecStatus":"Unsigned"}]}`)
	p.dock.Answer("zones/records/get", `{"zone":{"name":"example.com"},"records":[{"name":"example.com","type":"NS","ttl":3600,"rData":{"nameServer":"ns1"}},{"name":"a.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.4"}}]}`)
	p.rpi.Fail("zones/records/get", "error", "Access was denied.")

	rows := acctest.Rows(t, p.session(t, Options{}).Call(t, "zone_list", map[string]any{"counts": true})["zones"], "zones")
	com := acctest.Rows(t, rows[0]["on"], "on")
	if dock := rowFor(t, com, "dock"); acctest.Num(t, dock["records"], "records") != 2 || dock["error"] != nil {
		t.Errorf("example.com on dock = %v", dock)
	}
	if rpi := rowFor(t, com, "rpi"); rpi["records"] != nil || !strings.Contains(acctest.Str(rpi["error"]), "Access was denied") {
		t.Errorf("example.com on rpi, which would not give its records = %v", rpi)
	}
	// each zone was read once on each server holding it, and asked for whole
	if n := len(p.dock.Requests("zones/records/get")); n != 2 {
		t.Errorf("dock was asked for records %d times, want once a zone", n)
	}
	if asked := p.dock.Last("zones/records/get"); asked.Params.Get("listZone") != "true" {
		t.Errorf("a zone was counted from %v", asked.Params)
	}
}

// When a server cannot be asked, the others' zones are listed and the
// failure is said beside them: a zone is not called missing on a server that
// did not answer. When none can be asked the call fails.
func TestZoneListWhenAServerCannotBeAsked(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("zones/list", dockZones)
	p.rpi.Fail("zones/list", "invalid-token", "Invalid token or session expired.")
	suite := p.session(t, Options{})

	out := suite.Call(t, "zone_list", nil)
	if !slices.Equal(acctest.Strs(t, out["asked"], "asked"), []string{"dock"}) || acctest.Num(t, out["total"], "total") != 3 {
		t.Errorf("asked = %v, total = %v", out["asked"], out["total"])
	}
	failed := acctest.Rows(t, out["failed"], "failed")
	if len(failed) != 1 || failed[0]["server"] != "rpi" || !strings.Contains(acctest.Str(failed[0]["error"]), "the API token was refused") {
		t.Errorf("failed = %v", failed)
	}
	for _, row := range acctest.Rows(t, out["zones"], "zones") {
		if row["missing_on"] != nil {
			t.Errorf("%v is called missing on a server that did not answer", row)
		}
	}

	p.dock.Fail("zones/list", "error", "boom")
	if msg := suite.CallErr(t, "zone_list", nil); !strings.Contains(msg, "dock: zones/list: boom") || !strings.Contains(msg, "rpi: zones/list: Invalid token") {
		t.Errorf("with no server answering = %q, want each server's reason", msg)
	}
}

const (
	comOnBoth = `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7,"dnssecStatus":"Unsigned"}]}`
	// dock's copy of the zone
	dockRecords = `{"zone":{"name":"example.com"},"records":[
		{"name":"example.com","type":"SOA","ttl":900,"rData":{"primaryNameServer":"dock","responsiblePerson":"hostadmin@example.com","serial":7,"refresh":900,"retry":300,"expire":604800,"minimum":900}},
		{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"dock"}},
		{"name":"emby.van.example.com","type":"A","ttl":3600,"comments":"the emby vm","rData":{"ipAddress":"10.0.0.4"},"lastUsedOn":"2026-10-09T23:00:00Z","lastModified":"2026-10-01T00:00:00Z"},
		{"name":"m.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"emby.van.example.com"}},
		{"name":"old.example.com","type":"A","ttl":3600,"disabled":true,"rData":{"ipAddress":"10.0.0.40"}},
		{"name":"dock.van.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.2"}},
		{"name":"example.com","type":"MX","ttl":3600,"rData":{"preference":10,"exchange":"mail.example.com"}}
	]}`
	// rpi's: the same SOA, NS, MX and CNAME; emby with another TTL and no
	// comment; no old, no dock; and a record of its own
	rpiRecords = `{"zone":{"name":"example.com"},"records":[
		{"name":"example.com","type":"SOA","ttl":900,"rData":{"primaryNameServer":"dock","responsiblePerson":"hostadmin@example.com","serial":7,"refresh":900,"retry":300,"expire":604800,"minimum":900}},
		{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"dock"}},
		{"name":"EMBY.van.example.com","type":"A","ttl":300,"rData":{"ipAddress":"10.0.0.4"}},
		{"name":"m.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"emby.van.example.com"}},
		{"name":"example.com","type":"MX","ttl":3600,"rData":{"preference":10,"exchange":"mail.example.com"}},
		{"name":"rpi.van.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.3"},"expiryTtl":86400}
	]}`
)

// rowLine is a record row as one line a test can compare: name, type,
// value, and who alone holds it.
func rowLine(t *testing.T, row map[string]any) string {
	t.Helper()

	line := acctest.Str(row["name"]) + " " + acctest.Str(row["type"]) + " " + acctest.Str(row["value"])
	if row["only_on"] != nil {
		line += " @" + strings.Join(acctest.Strs(t, row["only_on"], "only_on"), ",")
	}

	return line
}

// lines is every record row of an answer, each as one line.
func lines(t *testing.T, out map[string]any) []string {
	t.Helper()

	rows := acctest.Rows(t, out["records"], "records")
	got := make([]string, 0, len(rows))
	for _, row := range rows {
		got = append(got, rowLine(t, row))
	}

	return got
}

// zone_records reads a zone from every server holding it as one table: a
// record held alike is one row, and one only some hold - or hold with
// another TTL or comment - names who does.
func TestZoneRecords(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.both("zones/list", comOnBoth)
	p.dock.Answer("zones/records/get", dockRecords)
	p.rpi.Answer("zones/records/get", rpiRecords)
	suite := p.session(t, Options{})

	out := suite.Call(t, "zone_records", map[string]any{"zone": "Example.com."})
	if out["zone"] != "Example.com" || !slices.Equal(acctest.Strs(t, out["read"], "read"), []string{"dock", "rpi"}) || out["missing_on"] != nil || out["failed"] != nil {
		t.Errorf("the answer is for %v, read from %v (missing on %v, failed %v)", out["zone"], out["read"], out["missing_on"], out["failed"])
	}
	// the zone's own name first, then each name under it with its
	// subdomains together; a record with another TTL on each server is two
	// rows, each naming its server
	want := []string{
		"example.com MX 10 mail.example.com",
		"example.com NS dock",
		"example.com SOA dock hostadmin@example.com 7 900 300 604800 900",
		"m.example.com CNAME emby.van.example.com",
		"old.example.com A 10.0.0.40 @dock",
		"dock.van.example.com A 10.0.0.2 @dock",
		"EMBY.van.example.com A 10.0.0.4 @rpi",
		"emby.van.example.com A 10.0.0.4 @dock",
		"rpi.van.example.com A 10.0.0.3 @rpi",
	}
	if got := lines(t, out); !slices.Equal(got, want) {
		t.Errorf("records =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	if acctest.Num(t, out["total"], "total") != 9 {
		t.Errorf("total = %v", out["total"])
	}
	byType := acctest.Rows(t, out["by_type"], "by_type")
	if len(byType) != 5 || byType[0]["type"] != "A" || acctest.Num(t, byType[0]["count"], "count") != 5 || byType[1]["type"] != "CNAME" {
		t.Errorf("by_type = %v, want the most first and then by name", byType)
	}

	rows := acctest.Rows(t, out["records"], "records")
	if old := rows[4]; !acctest.BoolOf(old["disabled"]) || old["comment"] != nil || old["on"] != nil {
		t.Errorf("the disabled record = %v", old)
	}
	if embyOnDock := rows[7]; embyOnDock["comment"] != "the emby vm" || acctest.Num(t, embyOnDock["ttl"], "ttl") != 3600 {
		t.Errorf("emby as dock holds it = %v", embyOnDock)
	}
	if rpi := rows[8]; acctest.Num(t, rpi["expiry_ttl"], "expiry_ttl") != 86400 {
		t.Errorf("the record that expires = %v", rpi)
	}
	if rows[0]["disabled"] != nil || rows[0]["expiry_ttl"] != nil {
		t.Errorf("an enabled record that does not expire says %v", rows[0])
	}

	// every record of the zone is read before any is left out
	for name, tc := range map[string]struct {
		args map[string]any
		want []string
	}{
		"types":             {map[string]any{"types": []string{"cname", "MX"}}, []string{"example.com MX 10 mail.example.com", "m.example.com CNAME emby.van.example.com"}},
		"a name anywhere":   {map[string]any{"name": "emby"}, []string{"EMBY.van.example.com A 10.0.0.4 @rpi", "emby.van.example.com A 10.0.0.4 @dock"}},
		"a name pattern":    {map[string]any{"name": "*.van.example.com", "server": "dock"}, []string{"dock.van.example.com A 10.0.0.2", "emby.van.example.com A 10.0.0.4"}},
		"a value anywhere":  {map[string]any{"value": "10.0.0.4"}, []string{"old.example.com A 10.0.0.40 @dock", "EMBY.van.example.com A 10.0.0.4 @rpi", "emby.van.example.com A 10.0.0.4 @dock"}},
		"a value whole":     {map[string]any{"value": "10.0.0.4*", "types": []string{"A"}, "disabled": false}, []string{"EMBY.van.example.com A 10.0.0.4 @rpi", "emby.van.example.com A 10.0.0.4 @dock"}},
		"what points at it": {map[string]any{"value": "emby.van.example.com"}, []string{"m.example.com CNAME emby.van.example.com"}},
		"commented":         {map[string]any{"comment": "*"}, []string{"emby.van.example.com A 10.0.0.4 @dock"}},
		"a comment":         {map[string]any{"comment": "EMBY"}, []string{"emby.van.example.com A 10.0.0.4 @dock"}},
		"disabled":          {map[string]any{"disabled": true}, []string{"old.example.com A 10.0.0.40 @dock"}},
		"nothing":           {map[string]any{"name": "nope"}, []string{}},
	} {
		tc.args["zone"] = "example.com"
		if got := lines(t, suite.Call(t, "zone_records", tc.args)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v\n  = %v\n  want %v", name, tc.args, got, tc.want)
		}
	}

	// the counts alone
	summary := suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "summary": true})
	if acctest.Num(t, summary["total"], "total") != 9 || len(acctest.Rows(t, summary["by_type"], "by_type")) != 5 || len(acctest.Rows(t, summary["records"], "records")) != 0 {
		t.Errorf("summary = %v", summary)
	}

	// a limit says where to read on from, and offset reads on from there
	first := suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "limit": 4})
	if len(lines(t, first)) != 4 || acctest.Num(t, first["total"], "total") != 9 || !strings.Contains(acctest.Str(first["note"]), "9 records matched and 4 are given, starting at the 1st: read on with offset 4") {
		t.Errorf("the first four = %v", first)
	}
	rest := suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "limit": 4, "offset": 4})
	if got := lines(t, rest); !slices.Equal(got, want[4:8]) || !strings.Contains(acctest.Str(rest["note"]), "starting at the 5th: read on with offset 8") {
		t.Errorf("the next four = %v (%v)", got, rest["note"])
	}
	if last := suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "offset": 8}); !slices.Equal(lines(t, last), want[8:]) || last["note"] != nil {
		t.Errorf("the last = %v", last)
	}
	if past := suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "offset": 50}); len(lines(t, past)) != 0 || acctest.Num(t, past["total"], "total") != 9 {
		t.Errorf("past the end = %v", past)
	}

	// each server's own facts, on request
	details := acctest.Rows(t, suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "details": true, "name": "emby", "server": "dock"})["records"], "records")
	seen := acctest.Rows(t, details[0]["on"], "on")
	if len(seen) != 1 || seen[0]["server"] != "dock" || seen[0]["last_used"] != "2026-10-09T23:00:00Z" || seen[0]["modified"] != "2026-10-01T00:00:00Z" {
		t.Errorf("emby's own facts on dock = %v", seen)
	}
	shared := acctest.Rows(t, suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "details": true, "types": []string{"NS"}})["records"], "records")
	if on := acctest.Rows(t, shared[0]["on"], "on"); len(on) != 2 || on[0]["last_used"] != nil {
		t.Errorf("a record both hold, never used = %v", on)
	}
}

// A zone only some servers hold is read from those, and the others are named
// as lacking it; one no server holds is an error that says where the name
// does belong when it is a name inside a zone.
func TestZoneRecordsWhereTheZoneIs(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"van.example.com","type":"Primary","soaSerial":1}]}`)
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.net","type":"Primary","soaSerial":1}]}`)
	p.dock.Answer("zones/records/get", dockRecords)
	suite := p.session(t, Options{})

	out := suite.Call(t, "zone_records", map[string]any{"zone": "example.com"})
	if !slices.Equal(acctest.Strs(t, out["read"], "read"), []string{"dock"}) || !slices.Equal(acctest.Strs(t, out["missing_on"], "missing_on"), []string{"rpi"}) {
		t.Errorf("read from %v, missing on %v", out["read"], out["missing_on"])
	}
	// held by the one server read, a record is on every server read
	for _, row := range acctest.Rows(t, out["records"], "records") {
		if row["only_on"] != nil {
			t.Errorf("%v is marked as only on a server when one server was read", row)
		}
	}
	if n := len(p.rpi.Requests("zones/records/get")); n != 0 {
		t.Errorf("rpi was asked %d times for the records of a zone it does not hold", n)
	}

	if msg := suite.CallErr(t, "zone_records", map[string]any{"zone": "emby.van.example.com"}); !strings.Contains(msg, "it is a name inside the zone van.example.com, so read that zone with name set to emby.van.example.com") {
		t.Errorf("a host name given for a zone = %q, want the closest zone it is in", msg)
	}
	if msg := suite.CallErr(t, "zone_records", map[string]any{"zone": "nope.test"}); !strings.Contains(msg, "no server asked (dock, rpi) holds a zone named nope.test") {
		t.Errorf("a zone nobody holds = %q", msg)
	}
	if msg := suite.CallErr(t, "zone_records", map[string]any{"zone": " "}); !strings.Contains(msg, "which zone") {
		t.Errorf("no zone = %q", msg)
	}

	// a server that cannot be asked is said, and the rest is read
	p.rpi.Fail("zones/list", "error", "boom")
	out = suite.Call(t, "zone_records", map[string]any{"zone": "example.com"})
	if failed := acctest.Rows(t, out["failed"], "failed"); len(failed) != 1 || failed[0]["server"] != "rpi" || out["missing_on"] != nil {
		t.Errorf("failed = %v, missing_on = %v", out["failed"], out["missing_on"])
	}
	p.dock.Fail("zones/records/get", "error", "Access was denied.")
	if msg := suite.CallErr(t, "zone_records", map[string]any{"zone": "example.com"}); !strings.Contains(msg, "dock: zones/records/get: Access was denied.") || !strings.Contains(msg, "rpi: zones/list: boom") {
		t.Errorf("with no server able to give the zone = %q", msg)
	}
}

// A secondary's copy of a zone carries the records and nothing the primary
// keeps beside them: no comment, no expiry. Read with its primary, a record
// held alike but for those is one row with the primary's comment - and is
// still found by a filter on the comment - where two primaries that differ
// in a comment are two rows.
func TestZoneRecordsOfAPrimaryAndItsCopy(t *testing.T) {
	t.Parallel()

	const (
		primaryRecords = `{"zone":{"name":"example.com"},"records":[
			{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"dock"}},
			{"name":"emby.example.com","type":"A","ttl":3600,"comments":"the emby vm","rData":{"ipAddress":"10.0.0.4"},"expiryTtl":86400,"lastModified":"2026-10-01T00:00:00Z"},
			{"name":"old.example.com","type":"A","ttl":3600,"disabled":true,"rData":{"ipAddress":"10.0.0.40"}}
		]}`
		copyRecords = `{"zone":{"name":"example.com"},"records":[
			{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"dock"}},
			{"name":"emby.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.4"},"lastModified":"0001-01-01T00:00:00"}
		]}`
	)
	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7}]}`)
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Secondary","soaSerial":7}]}`)
	p.dock.Answer("zones/records/get", primaryRecords)
	p.rpi.Answer("zones/records/get", copyRecords)
	suite := p.session(t, Options{})

	out := suite.Call(t, "zone_records", map[string]any{"zone": "example.com"})
	// a record the primary has disabled is not in the copy at all, which is so
	if got, want := lines(t, out), []string{"example.com NS dock", "emby.example.com A 10.0.0.4", "old.example.com A 10.0.0.40 @dock"}; !slices.Equal(got, want) {
		t.Errorf("records = %v, want %v", got, want)
	}
	emby := acctest.Rows(t, out["records"], "records")[1]
	if emby["comment"] != "the emby vm" || acctest.Num(t, emby["expiry_ttl"], "expiry_ttl") != 86400 {
		t.Errorf("emby = %v, want the primary's comment and expiry", emby)
	}
	if said := acctest.Str(out["note"]); !strings.Contains(said, "rpi holds a copy of this zone") {
		t.Errorf("the note = %q, want it said that a copy carries no comment", said)
	}

	// found by its comment as one record both hold
	if got := lines(t, suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "comment": "emby"})); !slices.Equal(got, []string{"emby.example.com A 10.0.0.4"}) {
		t.Errorf("found by its comment = %v", got)
	}
	// the note is about reading two servers together: one alone has nothing to merge
	if alone := suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "server": "rpi"}); alone["note"] != nil || len(lines(t, alone)) != 2 {
		t.Errorf("the copy alone = %v", alone)
	}
	// and a page of a merged zone says both things
	paged := suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "limit": 1})
	if said := acctest.Str(paged["note"]); !strings.Contains(said, "holds a copy") || !strings.Contains(said, "; 3 records matched and 1 are given") {
		t.Errorf("a page of a merged zone says %q", said)
	}

	// two primaries that differ in a comment do differ
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7}]}`)
	apart := suite.Call(t, "zone_records", map[string]any{"zone": "example.com", "name": "emby"})
	if got := lines(t, apart); !slices.Equal(got, []string{"emby.example.com A 10.0.0.4 @dock", "emby.example.com A 10.0.0.4 @rpi"}) || apart["note"] != nil {
		t.Errorf("two primaries, one with a comment = %v (%v)", got, apart["note"])
	}
}

func TestNameOrderAndPatterns(t *testing.T) {
	t.Parallel()

	names := []string{"b.example.com", "example.com", "a.b.example.com", "A.example.com.", "example.net", "z.example.com"}
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(nameOrder(a), nameOrder(b)) })
	if want := []string{"example.com", "A.example.com.", "b.example.com", "a.b.example.com", "z.example.com", "example.net"}; !slices.Equal(names, want) {
		t.Errorf("sorted = %v, want %v", names, want)
	}

	for _, tc := range []struct {
		pattern, text string
		want          bool
	}{
		{"", "anything", true},
		{"emby", "EMBY.van.example.com", true},
		{"emby", "plex.van.example.com", false},
		{"*.van.example.com", "emby.van.example.com", true},
		{"*.van.example.com", "van.example.com", false},
		{"10.0.0.?", "10.0.0.4", true},
		{"10.0.0.?", "10.0.0.40", false},
		{"10.0.0.4", "10.0.0.40", true},
		{"a.b", "aXb", false},
		{" Emby ", "emby", true},
	} {
		if got := newPattern(tc.pattern).matches(tc.text); got != tc.want {
			t.Errorf("pattern %q matches %q = %v, want %v", tc.pattern, tc.text, got, tc.want)
		}
	}

	for n, want := range map[int]string{1: "1st", 2: "2nd", 3: "3rd", 4: "4th", 11: "11th", 12: "12th", 13: "13th", 21: "21st", 102: "102nd", 111: "111th", 201: "201st"} {
		if got := ordinal(n); got != want {
			t.Errorf("ordinal(%d) = %q, want %q", n, got, want)
		}
	}
}
