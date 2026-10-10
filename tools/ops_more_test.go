package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// The log a canned server keeps for a day, and its queries as it exports
// them: with the mark a Windows program puts at the start of a text file.
const (
	dayLog    = "[2026-10-09 10:00:00 UTC] DNS Server was started\r\n[2026-10-09 10:00:05 UTC] [10.0.0.9:51000] [admin] Primary zone was created: example.com\r\n\r\n[2026-10-09 10:01:00 UTC] DNS Server failed to transfer zone: other.example\r\n[2026-10-09 10:02:00 UTC] Block list could not be fetched: ERROR timed out\n"
	exported  = "\xef\xbb\xbfRowNumber,Timestamp,ClientIpAddress,Protocol,ResponseType,ResponseRtt,RCODE,Domain,Type,Class,Answer\n1,2026-10-09T10:00:03Z,10.0.0.5,Udp,Authoritative,,NoError,www.example.com,A,IN,\"A 10.0.0.9\"\n2,2026-10-09T10:00:02Z,10.0.0.5,Udp,Authoritative,,NxDomain,old.example.com,A,IN,\n3,2026-10-09T10:00:01Z,10.0.0.8,Tcp,Recursive,12.5,NoError,example.org,A,IN,\"A 203.0.113.9\"\n"
	dockCount = `{"uptimestamp":"2026-10-01T12:00:00.5Z","uptimeSeconds":777600,"lifetimeCounters":{"totalQueries":120,"totalNoError":100,"totalServerFailure":1,"totalNxDomain":19,"totalRefused":0,"totalAuthoritative":40,"totalRecursive":50,"totalCached":20,"totalBlocked":10,"totalDropped":2,"totalClients":3}}`
)

// opsPair is the pair with dock's own log files and both servers' counters.
func opsPair(t *testing.T) *pair {
	t.Helper()

	p := logPair(t)
	p.dock.Answer("logs/list", `{"logFiles":[{"fileName":"2026-10-09","size":"8.14 KB"},{"fileName":"2026-10-08","size":"5.6 KB"}]}`)
	p.rpi.Answer("logs/list", `{"logFiles":[]}`)
	p.both("logs/delete", `{}`)
	p.both("logs/deleteAll", `{}`)
	p.dock.AnswerText("logs/download", dayLog)
	p.dock.AnswerText("logs/export", exported)
	p.rpi.Fail("logs/export", "error", "The app does not export.")
	p.both("dashboard/metrics/json", dockCount)
	p.dock.AnswerText("dashboard/metrics/text", "# TYPE queries_total counter\nqueries_total 120\n")
	p.dock.AnswerWhole("dnsClient/healthCheck", `{"server":"dock.example","status":"ok"}`)
	p.rpi.Fail("dnsClient/healthCheck", "error", "DNS Server failed to resolve the domain: no response from name servers.")
	p.dock.Answer("dashboard/stats/get", dockStats)
	p.both("dashboard/stats/deleteAll", `{}`)

	return p
}

// A server's own log is read from its end, a line an entry, or only its
// lines with some text in them; a server with no files says so by itself.
func TestLogFilesAndRead(t *testing.T) {
	t.Parallel()

	p := opsPair(t)
	suite := p.session(t, Options{})

	rows := acctest.Rows(t, suite.Call(t, "log_files", nil)["servers"], "servers")
	files := acctest.Rows(t, rows[0]["files"], "files")
	if len(rows) != 2 || len(files) != 2 || files[0]["file"] != "2026-10-09" || files[0]["size"] != "8.14 KB" || len(acctest.Rows(t, rows[1]["files"], "files")) != 0 {
		t.Errorf("log_files = %v", rows)
	}

	// with no file named each server reads its newest, and the one with none says so beside the other's lines
	read := acctest.Rows(t, suite.Call(t, "log_read", nil)["servers"], "servers")
	if lines := acctest.Strs(t, read[0]["lines"], "lines"); read[0]["file"] != "2026-10-09" || len(lines) != 4 || lines[0] != "[2026-10-09 10:00:00 UTC] DNS Server was started" || strings.ContainsAny(lines[1], "\r\n") || acctest.Num(t, read[0]["of"], "of") != 4 || acctest.Num(t, read[0]["matched"], "matched") != 4 || p.dock.Last("logs/download").Params.Get("fileName") != "2026-10-09" {
		t.Errorf("log_read on dock = %v", read[0])
	}
	if !strings.Contains(acctest.Str(read[1]["error"]), "the server has no log files") || len(acctest.Strs(t, read[1]["lines"], "lines")) != 0 {
		t.Errorf("log_read on rpi = %v", read[1])
	}

	// only the lines with the text, whatever its case, and of those the last asked for
	found := acctest.Rows(t, suite.Call(t, "log_read", map[string]any{"server": "dock", "file": " 2026-10-08 ", "contains": "dns server", "lines": 1})["servers"], "servers")[0]
	if lines := acctest.Strs(t, found["lines"], "lines"); !slices.Equal(lines, []string{"[2026-10-09 10:01:00 UTC] DNS Server failed to transfer zone: other.example"}) || acctest.Num(t, found["matched"], "matched") != 2 || acctest.Num(t, found["of"], "of") != 4 || p.dock.Last("logs/download").Params.Get("fileName") != "2026-10-08" {
		t.Errorf("the lines with the text = %v", found)
	}
	if none := acctest.Rows(t, suite.Call(t, "log_read", map[string]any{"server": "dock", "contains": "nothing like it"})["servers"], "servers")[0]; len(acctest.Strs(t, none["lines"], "lines")) != 0 || acctest.Num(t, none["matched"], "matched") != 0 {
		t.Errorf("no line with the text = %v", none)
	}

	// the only server asked failing is the call failing
	p.dock.Fail("logs/download", "error", "Log file was not found.")
	if msg := suite.CallErr(t, "log_read", map[string]any{"server": "dock", "file": "1999-01-01"}); !strings.Contains(msg, "Log file was not found") {
		t.Errorf("a file that is not there = %q", msg)
	}
}

// A log file is deleted by name or all are, never both and never neither,
// and a file the server does not have is said not to be there rather than
// asked for: the server would say ok to it.
func TestLogDelete(t *testing.T) {
	t.Parallel()

	p := opsPair(t)
	suite := p.session(t, everything)

	for _, args := range []map[string]any{{"server": "dock"}, {"server": "dock", "file": "2026-10-09", "all": true}} {
		if msg := suite.CallErr(t, "log_delete", args); !strings.Contains(msg, "one of the two") {
			t.Errorf("log_delete %v = %q", args, msg)
		}
	}
	if nothing := suite.Call(t, "log_delete", map[string]any{"server": "dock", "file": "1999-01-01"}); acctest.BoolOf(nothing["changed"]) || !strings.Contains(acctest.Str(nothing["note"]), "no log file by that name") || acctest.Num(t, nothing["left"], "left") != 2 {
		t.Errorf("a file that is not there, deleted = %v", nothing)
	}
	if nothing := suite.Call(t, "log_delete", map[string]any{"server": "rpi", "all": true}); acctest.BoolOf(nothing["changed"]) || !strings.Contains(acctest.Str(nothing["note"]), "nothing to delete") {
		t.Errorf("every file of a server with none, deleted = %v", nothing)
	}
	dry := suite.Call(t, "log_delete", map[string]any{"server": "dock", "all": true, "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have deleted all 2 log files of dock"}) || acctest.Num(t, dry["left"], "left") != 2 {
		t.Errorf("a dry run of deleting every file = %v", dry)
	}
	if n := len(p.dock.Requests("logs/delete")) + len(p.dock.Requests("logs/deleteAll")) + len(p.rpi.Requests("logs/deleteAll")); n != 0 {
		t.Errorf("%d deletions reached a server before one was asked for", n)
	}

	p.dock.Then("logs/delete", func(technitiumtest.Request) {
		p.dock.Answer("logs/list", `{"logFiles":[{"fileName":"2026-10-09","size":"8.2 KB"}]}`)
	})
	one := suite.Call(t, "log_delete", map[string]any{"server": "dock", "file": "2026-10-08"})
	if !slices.Equal(acctest.Strs(t, one["changes"], "changes"), []string{"deleted the log file 2026-10-08 of dock"}) || acctest.Num(t, one["left"], "left") != 1 || p.dock.Last("logs/delete").Params.Get("log") != "2026-10-08" {
		t.Errorf("one file deleted = %v, asked with %v", one, p.dock.Last("logs/delete").Params)
	}
	all := suite.Call(t, "log_delete", map[string]any{"server": "dock", "all": true})
	if !slices.Equal(acctest.Strs(t, all["changes"], "changes"), []string{"deleted all 1 log files of dock"}) || len(p.dock.Requests("logs/deleteAll")) != 1 {
		t.Errorf("every file deleted = %v", all)
	}
}

// The queries are handed on as the CSV the server writes, without the mark
// at its start, cut to the rows asked for with the count of all that matched.
func TestLogExportTool(t *testing.T) {
	t.Parallel()

	p := opsPair(t)
	suite := p.session(t, Options{})

	rows := acctest.Rows(t, suite.Call(t, "log_export", map[string]any{"name": "example.com.", "client": "10.0.0.5", "type": "a", "result": "nxdomain", "source": "authoritative", "protocol": "udp", "since": "2026-10-09", "until": "2026-10-10T00:00:00Z", "limit": 2})["servers"], "servers")
	csv := acctest.Str(rows[0]["csv"])
	if lines := strings.Split(csv, "\n"); len(lines) != 3 || !strings.HasPrefix(csv, "RowNumber,Timestamp,") || !strings.HasPrefix(lines[2], "2,") || acctest.Num(t, rows[0]["rows"], "rows") != 2 || acctest.Num(t, rows[0]["of"], "of") != 3 {
		t.Errorf("log_export on dock = %v", rows[0])
	}
	if !strings.Contains(acctest.Str(rows[1]["error"]), "The app does not export") || rows[1]["csv"] != nil {
		t.Errorf("log_export on rpi = %v", rows[1])
	}
	asked := p.dock.Last("logs/export")
	for param, want := range map[string]string{"name": "Query Logs (Sqlite)", "classPath": "QueryLogsSqlite.App", "qname": "*example.com*", "clientIpAddress": "10.0.0.5", "qtype": "A", "rcode": "NxDomain", "responseType": "Authoritative", "protocol": "Udp", "start": "2026-10-09T00:00:00Z", "end": "2026-10-10T00:00:00Z"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the export was asked for with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}

	// everything that matched, when the limit is not reached; and a pattern is passed as it is given
	whole := acctest.Rows(t, suite.Call(t, "log_export", map[string]any{"server": "dock", "name": "*.example.com", "last": "6h"})["servers"], "servers")[0]
	if asked = p.dock.Last("logs/export"); acctest.Num(t, whole["rows"], "rows") != 3 || asked.Params.Get("qname") != "*.example.com" || asked.Params.Get("start") == "" || asked.Params.Has("end") {
		t.Errorf("the whole export = %v, asked with %v", whole["rows"], asked.Params)
	}
	p.dock.AnswerText("logs/export", "\xef\xbb\xbfRowNumber,Timestamp,ClientIpAddress,Protocol,ResponseType,ResponseRtt,RCODE,Domain,Type,Class,Answer\n")
	if empty := acctest.Rows(t, suite.Call(t, "log_export", map[string]any{"server": "dock"})["servers"], "servers")[0]; acctest.Num(t, empty["rows"], "rows") != 0 || acctest.Num(t, empty["of"], "of") != 0 || !strings.HasPrefix(acctest.Str(empty["csv"]), "RowNumber,") {
		t.Errorf("an export of nothing = %v", empty)
	}

	sent := len(p.dock.Requests("logs/export"))
	for msg, args := range map[string]map[string]any{
		`client "10.0.0.0/24"`: {"client": "10.0.0.0/24"},
		"not both":             {"last": "6h", "since": "2026-10-09"},
		"last:":                {"last": "soon"},
		"since:":               {"since": "yesterday-ish"},
		"result":               {"result": "Fine"},
	} {
		if got := suite.CallErr(t, "log_export", args); !strings.Contains(got, msg) {
			t.Errorf("log_export %v = %q, want %q in it", args, got, msg)
		}
	}
	if len(p.dock.Requests("logs/export")) != sent {
		t.Error("an export that was refused was asked of a server")
	}
}

// A server's counters since it started are given beside whether it can
// resolve a name now, and a check that fails is the answer, not an error.
func TestServerMetrics(t *testing.T) {
	t.Parallel()

	p := opsPair(t)
	suite := p.session(t, Options{})

	rows := acctest.Rows(t, suite.Call(t, "server_metrics", nil)["servers"], "servers")
	dock, rpi := rows[0], rows[1]
	for field, want := range map[string]int{"queries": 120, "no_error": 100, "server_failure": 1, "nx_domain": 19, "refused": 0, "authoritative": 40, "recursive": 50, "cached": 20, "blocked": 10, "dropped": 2, "clients": 3, "uptime_seconds": 777600} {
		if got := acctest.Num(t, dock[field], field); got != want {
			t.Errorf("%s = %d, want %d", field, got, want)
		}
	}
	if !acctest.BoolOf(dock["healthy"]) || dock["up_since"] != "2026-10-01T12:00:00Z" || dock["prometheus"] != nil || len(p.dock.Last("dnsClient/healthCheck").Params) != 0 || len(p.dock.Requests("dashboard/metrics/text")) != 0 {
		t.Errorf("dock = %v", dock)
	}
	if acctest.BoolOf(rpi["healthy"]) || !strings.Contains(acctest.Str(rpi["unhealthy"]), "failed to resolve the domain") || rpi["error"] != nil || acctest.Num(t, rpi["queries"], "queries") != 120 {
		t.Errorf("rpi = %v", rpi)
	}

	with := acctest.Rows(t, suite.Call(t, "server_metrics", map[string]any{"server": "dock", "prometheus": true, "check": "Example.org."})["servers"], "servers")[0]
	if !strings.Contains(acctest.Str(with["prometheus"]), "queries_total 120") || p.dock.Last("dnsClient/healthCheck").Params.Get("domain") != "example.org" {
		t.Errorf("with the text and a name to check = %v", with)
	}
}

func TestStatsDelete(t *testing.T) {
	t.Parallel()

	p := opsPair(t)
	suite := p.session(t, everything)

	dry := suite.Call(t, "stats_delete", map[string]any{"server": "dock", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have deleted every statistic dock kept, which counted 1000 queries over the last year"}) || len(p.dock.Requests("dashboard/stats/deleteAll")) != 0 || p.dock.Last("dashboard/stats/get").Params.Get("type") != "LastYear" {
		t.Errorf("a dry run = %v", dry)
	}
	if out := suite.Call(t, "stats_delete", map[string]any{"server": "dock"}); acctest.Num(t, out["queries"], "queries") != 1000 || !acctest.BoolOf(out["changed"]) || len(p.dock.Requests("dashboard/stats/deleteAll")) != 1 {
		t.Errorf("stats_delete = %v", out)
	}
	if msg := suite.CallErr(t, "stats_delete", nil); !strings.Contains(msg, "server") {
		t.Errorf("no server named = %q", msg)
	}
}
