package technitium_test

import (
	"strings"
	"testing"
	"time"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

func TestQueryLog(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	// as a 15.6 server gave them: a chain answered from a zone, a name resolved, and a blocked one
	fake.Answer("logs/query", `{"pageNumber":2,"totalPages":3,"totalEntries":13,"entries":[
		{"rowNumber":6,"timestamp":"2026-10-10T02:49:29.5426895Z","clientIpAddress":"10.0.0.5","protocol":"Udp","responseType":"Authoritative","rcode":"NoError","qname":"c.example.com","qtype":"A","qclass":"IN","answer":"CNAME a.example.com., A 10.3.3.3"},
		{"rowNumber":7,"timestamp":"2026-10-10T02:49:28Z","clientIpAddress":"10.0.0.5","protocol":"Tcp","responseType":"Recursive","responseRtt":33.45,"rcode":"NoError","qname":"example.org","qtype":"AAAA","qclass":"IN","answer":"AAAA 2001:db8::1"},
		{"rowNumber":8,"timestamp":"2026-10-10T02:49:27Z","clientIpAddress":"fd00::9","protocol":"Udp","responseType":"Blocked","rcode":"NxDomain","qname":"ads.example.net","qtype":"A","qclass":"IN","answer":null}]}`)
	fake.Answer("apps/config/get", `{"config":"{\n  \"enableLogging\": true,\n  \"maxLogDays\": 7\n}"}`)
	c := client(t, fake)

	start := time.Date(2026, 10, 9, 20, 0, 0, 0, time.FixedZone("west", -7*3600))
	got, err := c.QueryLog(t.Context(), technitium.LogQuery{App: "Query Logs (Sqlite)", ClassPath: "QueryLogsSqlite.App", Name: "*.example.com", Client: "10.0.0.5", Type: "A", RCode: "NoError", ResponseType: "Authoritative", Protocol: "Udp", Start: start, End: start.Add(time.Hour), Page: 2, PerPage: 5})
	if err != nil {
		t.Fatal(err)
	}
	asked := fake.Last("logs/query")
	for param, want := range map[string]string{"name": "Query Logs (Sqlite)", "classPath": "QueryLogsSqlite.App", "qname": "*.example.com", "clientIpAddress": "10.0.0.5", "qtype": "A", "rcode": "NoError", "responseType": "Authoritative", "protocol": "Udp", "start": "2026-10-10T03:00:00Z", "end": "2026-10-10T04:00:00Z", "pageNumber": "2", "entriesPerPage": "5", "descendingOrder": "true"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the log was searched with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if got.PageNumber != 2 || got.TotalPages != 3 || got.TotalEntries != 13 || len(got.Entries) != 3 {
		t.Fatalf("QueryLog = %+v", got)
	}
	if e := got.Entries[0]; e.Timestamp != "2026-10-10T02:49:29.5426895Z" || e.Client != "10.0.0.5" || e.Protocol != "Udp" || e.ResponseType != "Authoritative" || e.RCode != "NoError" || e.Name != "c.example.com" || e.Type != "A" || e.Class != "IN" || e.Answer != "CNAME a.example.com., A 10.3.3.3" || e.ResponseRTT != nil {
		t.Errorf("an entry answered from a zone = %+v", e)
	}
	if e := got.Entries[1]; e.ResponseRTT == nil || *e.ResponseRTT != 33.45 || e.ResponseType != "Recursive" {
		t.Errorf("an entry that was resolved = %+v", e)
	}
	if e := got.Entries[2]; e.Answer != "" || e.ResponseType != "Blocked" || e.Client != "fd00::9" {
		t.Errorf("a blocked entry = %+v", e)
	}

	// with nothing asked for but the log, only whose log and the order are sent
	if _, err := c.QueryLog(t.Context(), technitium.LogQuery{App: "Query Logs (Sqlite)", ClassPath: "QueryLogsSqlite.App", OldestFirst: true}); err != nil {
		t.Fatal(err)
	}
	if asked = fake.Last("logs/query"); len(asked.Params) != 3 || asked.Params.Get("descendingOrder") != "false" {
		t.Errorf("the whole log was asked for with %v", asked.Params)
	}
	if _, err := c.QueryLog(t.Context(), technitium.LogQuery{App: "Query Logs (Sqlite)"}); err == nil || !strings.Contains(err.Error(), "whose log") || len(fake.Requests("logs/query")) != 2 {
		t.Errorf("a search of no app's log = %v", err)
	}

	config, err := c.AppConfig(t.Context(), "Query Logs (Sqlite)")
	if err != nil || !strings.Contains(config, `"maxLogDays": 7`) || fake.Last("apps/config/get").Params.Get("name") != "Query Logs (Sqlite)" {
		t.Errorf("AppConfig = %q, %v", config, err)
	}
	// an app with no configuration has none, which is not an error
	fake.Answer("apps/config/get", `{"config":null}`)
	if config, err = c.AppConfig(t.Context(), "Wild IP"); err != nil || config != "" {
		t.Errorf("the configuration of an app with none = %q, %v", config, err)
	}
	if _, err := c.AppConfig(t.Context(), ""); err == nil || len(fake.Requests("apps/config/get")) != 2 {
		t.Errorf("the configuration of no app = %v", err)
	}
}

// An app says which of its parts keeps a searchable log.
func TestAppQueryLog(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("apps/list", `{"apps":[{"name":"Wild IP","version":"1.0","dnsApps":[{"classPath":"WildIp.App","isQueryLogger":false,"isQueryLogs":false}]},{"name":"Query Logs (Sqlite)","version":"9.1.2","dnsApps":[{"classPath":"QueryLogsSqlite.App","isQueryLogger":true,"isQueryLogs":true}]}]}`)
	apps, err := client(t, fake).Apps(t.Context())
	if err != nil || len(apps) != 2 {
		t.Fatalf("Apps = %+v, %v", apps, err)
	}
	if class, ok := apps[0].QueryLog(); ok || class != "" || apps[0].LogsQueries() {
		t.Errorf("an app that keeps no log says it keeps one at %q", class)
	}
	if class, ok := apps[1].QueryLog(); !ok || class != "QueryLogsSqlite.App" || !apps[1].LogsQueries() {
		t.Errorf("the log app's log = %q, %v", class, ok)
	}
}
