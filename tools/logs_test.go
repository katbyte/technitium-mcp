package tools

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

const (
	logApp       = `{"apps":[{"name":"Wild IP","version":"1.0","dnsApps":[{"classPath":"WildIp.App","isQueryLogger":false,"isQueryLogs":false}]},{"name":"Query Logs (Sqlite)","version":"9.1.2","dnsApps":[{"classPath":"QueryLogsSqlite.App","isQueryLogger":true,"isQueryLogs":true}]}]}`
	logAppConfig = `{"config":"{\"enableLogging\": true, \"maxLogDays\": 7, \"maxLogRecords\": 10000}"}`
)

// logged is an entry of a log as a canned server gives one, for a query
// answered from the server's own zone.
func logged(at, client, name, recordType, rcode, answer string) string {
	text := "null"
	if answer != "" {
		text = `"` + answer + `"`
	}

	return `{"timestamp":"` + at + `","clientIpAddress":"` + client + `","protocol":"Udp","responseType":"Authoritative","rcode":"` + rcode + `","qname":"` + name + `","qtype":"` + recordType + `","qclass":"IN","answer":` + text + `}`
}

func logPage(total int, entries ...string) string {
	return `{"pageNumber":1,"totalPages":1,"totalEntries":` + strconv.Itoa(total) + `,"entries":[` + strings.Join(entries, ",") + `]}`
}

// logPair is two servers that each keep a log, with queries in them.
func logPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.both("apps/list", logApp)
	p.both("apps/config/get", logAppConfig)
	p.dock.Answer("logs/query", logPage(3,
		logged("2026-10-10T02:49:31.5Z", "10.0.0.5", "emby.example.com", "A", "NoError", "A 10.0.0.4"),
		logged("2026-10-10T02:49:29.5Z", "10.0.0.8", "Old.example.com", "A", "NxDomain", ""),
		logged("2026-10-10T02:49:27Z", "10.0.0.5", "old.example.com", "AAAA", "NxDomain", ""),
	))
	p.rpi.Answer("logs/query", logPage(2,
		logged("2026-10-10T02:49:30Z", "10.0.0.8", "old.example.com", "A", "NxDomain", ""),
		`{"timestamp":"2026-10-10T02:49:28Z","clientIpAddress":"10.0.0.9","protocol":"Tcp","responseType":"Recursive","responseRtt":33.45,"rcode":"NoError","qname":"example.org","qtype":"A","qclass":"IN","answer":"A 203.0.113.9"}`,
	))

	return p
}

// log_search lists the servers' queries together in the order of their
// times, or counts them by who asked or what for, and says of each server's
// log what keeps it and how far back it goes.
func TestLogSearch(t *testing.T) {
	t.Parallel()

	p := logPair(t)
	suite := p.session(t, Options{})

	out := suite.Call(t, "log_search", nil)
	rows := acctest.Rows(t, out["queries"], "queries")
	if len(rows) != 5 || acctest.Num(t, out["total"], "total") != 5 || out["note"] != nil || out["counts"] != nil {
		t.Fatalf("the queries = %v", out)
	}
	// the two servers' together, the newest first
	order := make([]string, 0, len(rows))
	for _, row := range rows {
		order = append(order, acctest.Str(row["server"])+" "+acctest.Str(row["time"]))
	}
	if want := []string{"dock 2026-10-10T02:49:31Z", "rpi 2026-10-10T02:49:30Z", "dock 2026-10-10T02:49:29Z", "rpi 2026-10-10T02:49:28Z", "dock 2026-10-10T02:49:27Z"}; !slices.Equal(order, want) {
		t.Errorf("the order = %v, want %v", order, want)
	}
	if r := rows[0]; r["client"] != "10.0.0.5" || r["name"] != "emby.example.com" || r["type"] != "A" || r["result"] != "NoError" || r["source"] != "Authoritative" || r["protocol"] != "Udp" || r["answer"] != "A 10.0.0.4" || r["took_ms"] != nil {
		t.Errorf("a query answered from a zone = %v", r)
	}
	if r := rows[3]; r["protocol"] != "Tcp" || r["source"] != "Recursive" || acctest.Decimal(t, r["took_ms"], "took_ms") != 33.45 {
		t.Errorf("a query that was resolved = %v", r)
	}
	if rows[2]["answer"] != nil {
		t.Errorf("a query answered with no records = %v", rows[2])
	}
	logs := acctest.Rows(t, out["logs"], "logs")
	if len(logs) != 2 || logs[0]["server"] != "dock" || logs[0]["app"] != "Query Logs (Sqlite) 9.1.2" || logs[0]["keeps"] != "the last 7 days, at most 10000 queries" || acctest.Num(t, logs[0]["matched"], "matched") != 3 || acctest.Num(t, logs[1]["matched"], "matched") != 2 || logs[0]["note"] != nil {
		t.Errorf("the logs = %v", logs)
	}
	// with nothing asked for, the log is asked for whole: whose it is, the newest first, and enough for the page
	if asked := p.dock.Last("logs/query"); len(asked.Params) != 5 || asked.Params.Get("name") != "Query Logs (Sqlite)" || asked.Params.Get("classPath") != "QueryLogsSqlite.App" || asked.Params.Get("descendingOrder") != "true" || asked.Params.Get("pageNumber") != "1" || asked.Params.Get("entriesPerPage") != "100" {
		t.Errorf("the whole log was asked for with %v", asked.Params)
	}

	// every filter is sent as the server takes it: a name with no * may be anywhere, and what is typed in any case is found
	suite.Call(t, "log_search", map[string]any{"server": "dock", "name": "Old.Example.com.", "client": " 10.0.0.8 ", "type": "a", "result": "nxdomain", "source": "AUTHORITATIVE", "protocol": "udp", "since": "2026-10-09", "until": "2026-10-10T12:00:00-07:00", "oldest_first": true, "limit": 20, "offset": 40})
	asked := p.dock.Last("logs/query")
	for param, want := range map[string]string{"qname": "*Old.Example.com*", "clientIpAddress": "10.0.0.8", "qtype": "A", "rcode": "NxDomain", "responseType": "Authoritative", "protocol": "Udp", "start": "2026-10-09T00:00:00Z", "end": "2026-10-10T19:00:00Z", "descendingOrder": "false", "entriesPerPage": "60"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the log was searched with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	suite.Call(t, "log_search", map[string]any{"server": "dock", "name": "*.example.com", "last": "7d"})
	if asked = p.dock.Last("logs/query"); asked.Params.Get("qname") != "*.example.com" || !strings.HasPrefix(asked.Params.Get("start"), "20") || asked.Params.Has("end") {
		t.Errorf("a name with a * over the last week was searched with %v", asked.Params)
	}

	// a few at a time: read on from where it stopped
	paged := suite.Call(t, "log_search", map[string]any{"limit": 2, "offset": 1})
	if got := acctest.Rows(t, paged["queries"], "queries"); len(got) != 2 || got[0]["server"] != "rpi" || got[1]["time"] != "2026-10-10T02:49:29Z" || !strings.Contains(acctest.Str(paged["note"]), "5 queries matched and 2 are given, starting at the 2nd: read on with offset 3") {
		t.Errorf("paged = %v", paged)
	}
	oldest := acctest.Rows(t, suite.Call(t, "log_search", map[string]any{"oldest_first": true, "limit": 1})["queries"], "queries")
	if len(oldest) != 1 || oldest[0]["time"] != "2026-10-10T02:49:27Z" {
		t.Errorf("the oldest = %v", oldest)
	}

	// counted: who asks, the most first, and how many of each on each server; names without their case
	counted := suite.Call(t, "log_search", map[string]any{"count_by": "Name"})
	counts := acctest.Rows(t, counted["counts"], "counts")
	if len(counts) != 3 || counts[0]["value"] != "old.example.com" || acctest.Num(t, counts[0]["queries"], "queries") != 3 || counted["queries"] != nil || acctest.Num(t, counted["total"], "total") != 5 {
		t.Fatalf("counted by name = %v", counted)
	}
	if on := acctest.Object(t, counts[0]["on"], "on"); acctest.NumOr0(on["dock"]) != 2 || acctest.NumOr0(on["rpi"]) != 1 {
		t.Errorf("the name asked for most, by server = %v", on)
	}
	if asked = p.dock.Last("logs/query"); asked.Params.Get("entriesPerPage") != "50000" {
		t.Errorf("to count them, every match was asked for with %v", asked.Params)
	}
	byClient := acctest.Rows(t, suite.Call(t, "log_search", map[string]any{"count_by": "client", "server": "dock", "limit": 1})["counts"], "counts")
	if len(byClient) != 1 || byClient[0]["value"] != "10.0.0.5" || acctest.Num(t, byClient[0]["queries"], "queries") != 2 || byClient[0]["on"] != nil {
		t.Errorf("counted by client on one server = %v", byClient)
	}
	// more matches than are read to be counted is said
	p.rpi.Answer("logs/query", `{"pageNumber":1,"totalPages":2,"totalEntries":70000,"entries":[`+logged("2026-10-10T02:49:30Z", "10.0.0.8", "old.example.com", "A", "NxDomain", "")+`]}`)
	if said := acctest.Str(suite.Call(t, "log_search", map[string]any{"count_by": "result"})["note"]); !strings.Contains(said, "70000 queries matched on rpi and the first 1 were counted") {
		t.Errorf("more than is counted = %q", said)
	}

	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"a result there is none of":   {map[string]any{"result": "missing"}, `result "missing": it takes FormatError, NoError, NotImplemented, NxDomain, Refused, ServerFailure`},
		"a source there is none of":   {map[string]any{"source": "local"}, `source "local": it takes Authoritative, Blocked`},
		"a protocol there is none of": {map[string]any{"protocol": "smoke"}, `protocol "smoke": it takes Https, Quic, Tcp, Tls, Udp`},
		"a network for a client":      {map[string]any{"client": "10.0.0.0/24"}, "the log is searched by one client's address, exactly"},
		"both kinds of time":          {map[string]any{"last": "1h", "since": "2026-10-09"}, "not both"},
		"no length of time":           {map[string]any{"last": "a while"}, `last: "a while" is no length of time: give it as 30m, 6h or 7d`},
		"no time":                     {map[string]any{"since": "yesterday"}, `since: "yesterday" is no time`},
		"an end before its start":     {map[string]any{"since": "2026-10-10", "until": "2026-10-09"}, "is not after since"},
		"nothing to count by":         {map[string]any{"count_by": "colour"}, "it takes client, name, type, result or source"},
		"too far into the matches":    {map[string]any{"offset": 20000}, "reach past the first 10000 matches"},
	} {
		if msg := suite.CallErr(t, "log_search", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
}

// A server with no app that keeps a log says so, and how to have one; and
// what the app's configuration says of the log is passed on.
func TestLogSearchWithoutALog(t *testing.T) {
	t.Parallel()

	p := logPair(t)
	p.rpi.Answer("apps/list", `{"apps":[{"name":"Wild IP","version":"1.0","dnsApps":[{"classPath":"WildIp.App","isQueryLogger":false}]}]}`)
	p.dock.Answer("apps/config/get", `{"config":"{\"enableLogging\": false, \"maxLogDays\": 0, \"maxLogRecords\": 500}"}`)
	suite := p.session(t, Options{})

	out := suite.Call(t, "log_search", nil)
	logs := acctest.Rows(t, out["logs"], "logs")
	if len(acctest.Rows(t, out["queries"], "queries")) != 3 || logs[1]["server"] != "rpi" || !strings.Contains(acctest.Str(logs[1]["error"]), "rpi has no app that keeps a searchable log of queries: install Query Logs (Sqlite) from the Apps section of its web console") {
		t.Errorf("with no log on rpi = %v", out)
	}
	if logs[0]["keeps"] != "at most 500 queries" || !strings.Contains(acctest.Str(logs[0]["note"]), "the app's logging is switched off in its configuration") {
		t.Errorf("dock's log, switched off = %v", logs[0])
	}

	// a configuration that will not be read, or is not what this knows, is passed over
	p.dock.Fail("apps/config/get", "error", "Access was denied.")
	if logs = acctest.Rows(t, suite.Call(t, "log_search", map[string]any{"server": "dock"})["logs"], "logs"); logs[0]["keeps"] != nil || !strings.Contains(acctest.Str(logs[0]["note"]), "how much the log keeps could not be read: apps/config/get: Access was denied.") {
		t.Errorf("with the app's configuration refused = %v", logs[0])
	}
	p.dock.Answer("apps/config/get", `{"config":"not json at all"}`)
	if logs = acctest.Rows(t, suite.Call(t, "log_search", map[string]any{"server": "dock"})["logs"], "logs"); logs[0]["keeps"] != nil || logs[0]["note"] != nil || logs[0]["error"] != nil {
		t.Errorf("with a configuration of another kind = %v", logs[0])
	}

	// no server with a log is an error that says how to have one
	p.dock.Answer("apps/list", `{"apps":[]}`)
	if msg := suite.CallErr(t, "log_search", nil); !strings.Contains(msg, "dock has no app that keeps a searchable log of queries") || !strings.Contains(msg, "rpi has no app") {
		t.Errorf("with no log anywhere = %q", msg)
	}
}
