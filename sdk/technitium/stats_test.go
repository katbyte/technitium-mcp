package technitium_test

import (
	"strings"
	"testing"
	"time"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

func TestStats(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("dashboard/stats/get", `{"stats":{"totalQueries":925,"totalNoError":834,"totalServerFailure":1,"totalNxDomain":90,"totalRefused":0,"totalAuthoritative":47,"totalRecursive":348,"totalCached":481,"totalBlocked":49,"totalDropped":0,"totalClients":6,"zones":19,"cachedEntries":6330,"allowedZones":10,"blockedZones":1,"allowListZones":0,"blockListZones":307447},
		"mainChartData":{"labelFormat":"HH:mm","labels":["2024-02-04T10:38:00.0000000Z"],"datasets":[{"label":"Total","backgroundColor":"rgba(102, 153, 255, 0.1)","data":[3]}]},
		"queryTypeChartData":{"labels":["A","HTTPS","AAAA"],"datasets":[{"data":[683,196,42],"backgroundColor":["rgba(102, 153, 255, 0.5)"]}]},
		"protocolTypeChartData":{"labels":["Udp","Tcp"],"datasets":[{"data":[920,5]}]},
		"topClients":[{"name":"192.168.10.5","domain":"server1.home","hits":463,"rateLimited":false},{"name":"162.158.180.45","hits":9,"rateLimited":true}],
		"topDomains":[{"name":"example.com","hits":104}],
		"topBlockedDomains":[{"name":"ads.example.net","hits":40}]}`)
	fake.Answer("dashboard/stats/getTop", `{"topDomains":[{"name":"example.com","hits":104},{"name":"example.org","hits":9}]}`)
	c := client(t, fake)

	got, err := c.Stats(t.Context(), technitium.StatsWindow{})
	if err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dashboard/stats/get"); asked.Params.Get("type") != "LastHour" || asked.Params.Get("utc") != "true" || asked.Params.Has("start") {
		t.Errorf("the stats were asked for with %v", asked.Params)
	}
	if got.Totals != (technitium.StatTotals{Queries: 925, NoError: 834, ServerFailure: 1, NxDomain: 90, Authoritative: 47, Recursive: 348, Cached: 481, Blocked: 49, Clients: 6, Zones: 19, CachedEntries: 6330, AllowedZones: 10, BlockedZones: 1, BlockListZones: 307447}) {
		t.Errorf("Totals = %+v", got.Totals)
	}
	if len(got.TopClients) != 2 || got.TopClients[0] != (technitium.TopClient{Name: "192.168.10.5", Domain: "server1.home", Hits: 463}) || !got.TopClients[1].RateLimited || got.TopClients[1].Domain != "" || len(got.TopDomains) != 1 || got.TopBlockedDomains[0] != (technitium.TopDomain{Name: "ads.example.net", Hits: 40}) {
		t.Errorf("the top lists = %+v, %+v, %+v", got.TopClients, got.TopDomains, got.TopBlockedDomains)
	}
	if types, protocols := got.QueryTypes(), got.Protocols(); len(types) != 3 || types["A"] != 683 || types["AAAA"] != 42 || len(protocols) != 2 || protocols["Tcp"] != 5 {
		t.Errorf("by type = %v, by protocol = %v", types, protocols)
	}

	// a window the server keeps, and one given by its ends
	if _, err := c.Stats(t.Context(), technitium.StatsWindow{Type: technitium.StatsLastWeek}); err != nil || fake.Last("dashboard/stats/get").Params.Get("type") != "LastWeek" {
		t.Errorf("the last week: %v, asked with %v", err, fake.Last("dashboard/stats/get").Params)
	}
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("west", -7*3600))
	if _, err := c.Stats(t.Context(), technitium.StatsWindow{Start: start, End: start.Add(48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dashboard/stats/get"); asked.Params.Get("type") != "Custom" || asked.Params.Get("start") != "2026-10-01T19:00:00Z" || asked.Params.Get("end") != "2026-10-03T19:00:00Z" {
		t.Errorf("a window of its own was asked for with %v", asked.Params)
	}

	top, err := c.TopStats(t.Context(), technitium.StatsWindow{Type: technitium.StatsLastDay}, technitium.TopDomains, 50)
	if err != nil || len(top.TopDomains) != 2 || top.TopDomains[1].Name != "example.org" {
		t.Errorf("TopStats = %+v, %v", top, err)
	}
	if asked := fake.Last("dashboard/stats/getTop"); asked.Params.Get("type") != "LastDay" || asked.Params.Get("statsType") != "TopDomains" || asked.Params.Get("limit") != "50" {
		t.Errorf("the top domains were asked for with %v", asked.Params)
	}

	// what makes no window, or names no list, is not sent
	sent := len(fake.Requests("dashboard/stats/get")) + len(fake.Requests("dashboard/stats/getTop"))
	if _, err := c.Stats(t.Context(), technitium.StatsWindow{Start: start}); err == nil || !strings.Contains(err.Error(), "both its start and its end") {
		t.Errorf("a window with no end = %v", err)
	}
	if _, err := c.Stats(t.Context(), technitium.StatsWindow{Start: start, End: start}); err == nil {
		t.Error("a window that ends as it starts was asked for")
	}
	if _, err := c.TopStats(t.Context(), technitium.StatsWindow{}, "TopOfThePops", 10); err == nil || !strings.Contains(err.Error(), "which list") {
		t.Errorf("a list there is none of = %v", err)
	}
	if _, err := c.TopStats(t.Context(), technitium.StatsWindow{End: start}, technitium.TopClients, 10); err == nil {
		t.Error("a top list for a window with no start was asked for")
	}
	if now := len(fake.Requests("dashboard/stats/get")) + len(fake.Requests("dashboard/stats/getTop")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}
