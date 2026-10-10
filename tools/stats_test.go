package tools

import (
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

const (
	dockStats = `{"stats":{"totalQueries":1000,"totalNoError":850,"totalServerFailure":25,"totalNxDomain":120,"totalRefused":5,"totalAuthoritative":300,"totalRecursive":200,"totalCached":420,"totalBlocked":80,"totalDropped":0,"totalClients":6,"zones":19,"cachedEntries":6330,"allowedZones":1,"blockedZones":4,"allowListZones":0,"blockListZones":307447},
		"queryTypeChartData":{"labels":["A","AAAA","HTTPS"],"datasets":[{"data":[700,250,50]}]},
		"protocolTypeChartData":{"labels":["Udp","Tcp"],"datasets":[{"data":[990,10]}]},
		"topClients":[{"name":"10.0.0.5","domain":"nas.van.example.com","hits":463,"rateLimited":false},{"name":"10.0.0.77","hits":90,"rateLimited":true},{"name":"10.0.0.8","domain":"tv.van.example.com","hits":12,"rateLimited":false}],
		"topDomains":[{"name":"emby.van.example.com","hits":104},{"name":"example.org","hits":9}],
		"topBlockedDomains":[{"name":"ads.example.net","hits":40}]}`
	idleStats = `{"stats":{"totalQueries":0,"totalClients":0,"zones":2,"cachedEntries":0},"queryTypeChartData":{"labels":[],"datasets":[{"data":[]}]},"protocolTypeChartData":{"labels":[],"datasets":[]},"topClients":[],"topDomains":[],"topBlockedDomains":[]}`
)

// server_stats sets what each server did over a window side by side: its
// counts, the parts that failed or were blocked, and who and what lead.
func TestServerStats(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("dashboard/stats/get", dockStats)
	p.rpi.Answer("dashboard/stats/get", idleStats)
	suite := p.session(t, Options{})

	out := suite.Call(t, "server_stats", nil)
	rows := acctest.Rows(t, out["servers"], "servers")
	if len(rows) != 2 || out["window"] != "hour" || !strings.Contains(acctest.Str(out["note"]), "the minute in progress is not in yet") {
		t.Fatalf("the answer = %v", out)
	}
	if asked := p.dock.Last("dashboard/stats/get"); asked.Params.Get("type") != "LastHour" || asked.Params.Has("start") || len(p.dock.Requests("dashboard/stats/getTop")) != 0 {
		t.Errorf("the hour was asked for with %v", asked.Params)
	}
	d := rows[0]
	for field, want := range map[string]int{"queries": 1000, "clients": 6, "no_error": 850, "nx_domain": 120, "server_failure": 25, "refused": 5, "authoritative": 300, "recursive": 200, "cached": 420, "blocked": 80, "dropped": 0, "zones": 19, "cached_entries": 6330} {
		if acctest.Num(t, d[field], field) != want {
			t.Errorf("dock's %s = %v, want %d", field, d[field], want)
		}
	}
	if acctest.Decimal(t, d["nx_domain_percent"], "nx_domain_percent") != 12 || acctest.Decimal(t, d["server_failure_percent"], "server_failure_percent") != 2.5 || acctest.Decimal(t, d["blocked_percent"], "blocked_percent") != 8 {
		t.Errorf("dock's parts = %v, %v, %v", d["nx_domain_percent"], d["server_failure_percent"], d["blocked_percent"])
	}
	clients := acctest.Rows(t, d["top_clients"], "top_clients")
	if len(clients) != 3 || clients[0]["address"] != "10.0.0.5" || clients[0]["name"] != "nas.van.example.com" || acctest.Num(t, clients[0]["queries"], "queries") != 463 || clients[0]["rate_limited"] != nil || clients[1]["name"] != nil || !acctest.BoolOf(clients[1]["rate_limited"]) {
		t.Errorf("dock's clients = %v", clients)
	}
	if names := acctest.Rows(t, d["top_domains"], "top_domains"); len(names) != 2 || names[0]["name"] != "emby.van.example.com" || acctest.Num(t, names[0]["queries"], "queries") != 104 {
		t.Errorf("dock's names = %v", names)
	}
	if blocked := acctest.Rows(t, d["top_blocked"], "top_blocked"); len(blocked) != 1 || blocked[0]["name"] != "ads.example.net" {
		t.Errorf("dock's blocked names = %v", blocked)
	}
	if types, protocols := acctest.Object(t, d["types"], "types"), acctest.Object(t, d["protocols"], "protocols"); acctest.NumOr0(types["AAAA"]) != 250 || acctest.NumOr0(protocols["Tcp"]) != 10 {
		t.Errorf("by type = %v, by protocol = %v", types, protocols)
	}
	// a server nothing asked has counts of nothing, and no parts of it
	if r := rows[1]; r["server"] != "rpi" || acctest.Num(t, r["queries"], "queries") != 0 || r["nx_domain_percent"] != nil || r["top_clients"] != nil || r["types"] != nil || acctest.Num(t, r["zones"], "zones") != 2 {
		t.Errorf("rpi = %v", r)
	}

	// fewer of each list is the first of what came; more is asked for list by list
	few := acctest.Rows(t, suite.Call(t, "server_stats", map[string]any{"top": 1, "server": "dock"})["servers"], "servers")
	if len(acctest.Rows(t, few[0]["top_clients"], "top_clients")) != 1 || len(acctest.Rows(t, few[0]["top_domains"], "top_domains")) != 1 {
		t.Errorf("the one that leads each list = %v", few[0])
	}
	p.dock.Answer("dashboard/stats/getTop", `{"topClients":[{"name":"10.0.0.5","hits":463}],"topDomains":[{"name":"a.example.org","hits":3},{"name":"b.example.org","hits":2}],"topBlockedDomains":[]}`)
	more := suite.Call(t, "server_stats", map[string]any{"top": 50, "server": "dock", "window": "Week"})
	if d = acctest.Rows(t, more["servers"], "servers")[0]; more["window"] != "week" || len(acctest.Rows(t, d["top_domains"], "top_domains")) != 2 || d["top_blocked"] != nil || !strings.Contains(acctest.Str(more["note"]), "the hour in progress is not in it") {
		t.Errorf("fifty of each over the week = %v", more)
	}
	asked := map[string]bool{}
	for _, req := range p.dock.Requests("dashboard/stats/getTop") {
		asked[req.Params.Get("statsType")] = req.Params.Get("type") == "LastWeek" && req.Params.Get("limit") == "50"
	}
	if len(asked) != 3 || !asked["TopClients"] || !asked["TopDomains"] || !asked["TopBlockedDomains"] {
		t.Errorf("the longer lists were asked for as %v", asked)
	}

	// a window of one's own, by time or by date
	own := suite.Call(t, "server_stats", map[string]any{"from": "2026-10-01", "to": "2026-10-03T12:00:00-07:00", "server": "dock"})
	if req := p.dock.Last("dashboard/stats/get"); req.Params.Get("type") != "Custom" || req.Params.Get("start") != "2026-10-01T00:00:00Z" || req.Params.Get("end") != "2026-10-03T19:00:00Z" || own["window"] != "2026-10-01T00:00:00Z to 2026-10-03T19:00:00Z" || !strings.Contains(acctest.Str(own["note"]), "whole days") {
		t.Errorf("a window of one's own = %v, asked for with %v", own["window"], req.Params)
	}

	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"a window there is none of": {map[string]any{"window": "decade"}, "it takes hour, day, week, month or year"},
		"both kinds of window":      {map[string]any{"window": "day", "from": "2026-10-01", "to": "2026-10-02"}, "not both"},
		"a start alone":             {map[string]any{"from": "2026-10-01"}, `to: "" is no time`},
		"no time":                   {map[string]any{"from": "last tuesday", "to": "2026-10-02"}, `from: "last tuesday" is no time: give it as 2026-10-09T14:00:00Z`},
		"an end before its start":   {map[string]any{"from": "2026-10-02", "to": "2026-10-01"}, "which is not after it starts"},
		"too long a list":           {map[string]any{"top": 5000}, "the most of each list is 1000"},
	} {
		if msg := suite.CallErr(t, "server_stats", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}

	// a server that will not give its statistics is a row that says so
	p.rpi.Fail("dashboard/stats/get", "error", "Access was denied.")
	if rows = acctest.Rows(t, suite.Call(t, "server_stats", nil)["servers"], "servers"); rows[1]["error"] != "dashboard/stats/get: Access was denied." || acctest.Num(t, rows[0]["queries"], "queries") != 1000 {
		t.Errorf("with rpi refusing = %v", rows)
	}
	p.dock.Fail("dashboard/stats/get", "error", "Access was denied.")
	if msg := suite.CallErr(t, "server_stats", nil); !strings.Contains(msg, "dock: dashboard/stats/get: Access was denied.") {
		t.Errorf("with both refusing = %q", msg)
	}
}
