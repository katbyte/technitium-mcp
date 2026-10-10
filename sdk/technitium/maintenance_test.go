package technitium_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// The server's own log is a file a day, listed, read and deleted by its
// name; and a search of the log of queries can be had whole, as CSV.
func TestLogFiles(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("logs/list", `{"logFiles":[{"fileName":"2020-09-19","size":"8.14 KB"},{"fileName":"2020-09-15","size":"5.6 KB"}]}`)
	fake.AnswerText("logs/download", "[2020-09-19 10:00:00 UTC] DNS Server was started\n")
	fake.Answer("logs/delete", `{}`)
	fake.Answer("logs/deleteAll", `{}`)
	// as a 15.6 server gives it: a byte order mark first, which is no part of the first heading
	fake.AnswerText("logs/export", "\ufeffRowNumber,Timestamp,ClientIpAddress,Protocol,ResponseType,ResponseRtt,RCODE,Domain,Type,Class,Answer\n1,2026-10-09T10:00:00Z,192.0.2.7,Udp,Authoritative,,NoError,www.example.com,A,IN,\"A 192.0.2.10\"\n")
	c := client(t, fake)

	files, err := c.LogFiles(t.Context())
	if err != nil || len(files) != 2 || files[0].FileName != "2020-09-19" || files[0].Size != "8.14 KB" {
		t.Errorf("LogFiles = %+v, %v", files, err)
	}
	text, err := c.DownloadLog(t.Context(), "2020-09-19", 2)
	if asked := fake.Last("logs/download"); err != nil || !strings.Contains(text, "DNS Server was started") || asked.Method != http.MethodGet || len(asked.Params) != 2 || asked.Params.Get("fileName") != "2020-09-19" || asked.Params.Get("limit") != "2" {
		t.Errorf("DownloadLog = %q, %v, asked with %v", text, err, asked.Params)
	}
	if _, err := c.DownloadLog(t.Context(), "2020-09-19", 0); err != nil || fake.Last("logs/download").Params.Has("limit") {
		t.Errorf("the whole log was asked for with %v, %v", fake.Last("logs/download").Params, err)
	}
	if err := c.DeleteLog(t.Context(), "2020-09-19"); err != nil || fake.Last("logs/delete").Method != http.MethodPost || fake.Last("logs/delete").Params.Get("log") != "2020-09-19" {
		t.Errorf("DeleteLog = %v, sent %v", err, fake.Last("logs/delete").Params)
	}
	if err := c.DeleteAllLogs(t.Context()); err != nil || fake.Last("logs/deleteAll").Method != http.MethodPost || len(fake.Last("logs/deleteAll").Params) != 0 {
		t.Errorf("DeleteAllLogs = %v", err)
	}

	start := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	csv, err := c.ExportQueryLog(t.Context(), technitium.LogQuery{App: "Query Logs (Sqlite)", ClassPath: "QueryLogsSqlite.App", Name: "*.example.com", Client: "192.0.2.7", Type: "A", Start: start, Page: 3, PerPage: 50})
	if err != nil || !strings.HasPrefix(csv, "RowNumber,") || strings.Count(csv, "\n") != 2 {
		t.Fatalf("ExportQueryLog = %q, %v", csv, err)
	}
	asked := fake.Last("logs/export")
	for param, want := range map[string]string{"name": "Query Logs (Sqlite)", "classPath": "QueryLogsSqlite.App", "qname": "*.example.com", "clientIpAddress": "192.0.2.7", "qtype": "A", "start": "2026-10-09T00:00:00Z"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the log was exported with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	// an export is every entry that matched: it has no pages and no order to ask for
	if len(asked.Params) != 6 {
		t.Errorf("the log was exported with %v", asked.Params)
	}

	refused := map[string]error{"no log deleted": c.DeleteLog(t.Context(), "")}
	_, refused["no log read"] = c.DownloadLog(t.Context(), "", 0)
	_, refused["nobody's log exported"] = c.ExportQueryLog(t.Context(), technitium.LogQuery{Name: "example.com"})
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	if len(fake.Requests("logs/delete")) != 1 || len(fake.Requests("logs/download")) != 2 || len(fake.Requests("logs/export")) != 1 {
		t.Error("a refused call reached the server")
	}
}

// The server's own two lists are read as a tree, added to many names at a
// time, and emptied.
func TestListsBrowsedImportedAndFlushed(t *testing.T) {
	t.Parallel()

	// as a 15.6 server gives it: the names below written whole, and a TTL that is a number where the document shows text
	const under = `{"domain":"example.com","zones":["ads.example.com","track.example.com"],"records":[{"name":"example.com","type":"NS","ttl":60,"rData":{"nameServer":"ns1.example"}},{"name":"example.com","type":"SOA","ttl":60,"rData":{"primaryNameServer":"ns1.example","responsiblePerson":"hostadmin.ns1.example","serial":1,"refresh":14400,"retry":3600,"expire":604800,"minimum":900}}]}`
	fake := technitiumtest.New(t)
	fake.Answer("blocked/list", under)
	fake.Answer("allowed/list", `{"domain":"","zones":["com"],"records":[]}`)
	for _, path := range []string{"blocked/import", "allowed/import", "blocked/flush", "allowed/flush", "dhcp/leases/convertToReserved", "dhcp/leases/convertToDynamic"} {
		fake.Answer(path, `{}`)
	}
	c := client(t, fake)

	blocked, err := c.BlockedUnder(t.Context(), "example.com")
	if err != nil || blocked.Domain != "example.com" || len(blocked.Zones) != 2 || len(blocked.Records) != 2 || blocked.Zones[0] != "ads.example.com" || blocked.Records[0].Type != "NS" || blocked.Records[0].TTL != 60 || blocked.Records[1].SOA().Primary != "ns1.example" || fake.Last("blocked/list").Params.Get("domain") != "example.com" {
		t.Errorf("BlockedUnder = %+v, %v", blocked, err)
	}
	allowed, err := c.AllowedUnder(t.Context(), "")
	if err != nil || len(allowed.Zones) != 1 || allowed.Zones[0] != "com" || len(fake.Last("allowed/list").Params) != 0 {
		t.Errorf("AllowedUnder = %+v, %v, asked with %v", allowed, err, fake.Last("allowed/list").Params)
	}

	if err := c.ImportBlocked(t.Context(), []string{"ads.example", "track.example"}); err != nil || fake.Last("blocked/import").Method != http.MethodPost || len(fake.Last("blocked/import").Params) != 1 || fake.Last("blocked/import").Params.Get("blockedZones") != "ads.example,track.example" {
		t.Errorf("ImportBlocked = %v, sent %v", err, fake.Last("blocked/import").Params)
	}
	if err := c.ImportAllowed(t.Context(), []string{"good.example"}); err != nil || fake.Last("allowed/import").Method != http.MethodPost || fake.Last("allowed/import").Params.Get("allowedZones") != "good.example" {
		t.Errorf("ImportAllowed = %v, sent %v", err, fake.Last("allowed/import").Params)
	}
	if err := c.FlushBlocked(t.Context()); err != nil || fake.Last("blocked/flush").Method != http.MethodPost || len(fake.Last("blocked/flush").Params) != 0 {
		t.Errorf("FlushBlocked = %v", err)
	}
	if err := c.FlushAllowed(t.Context()); err != nil || fake.Last("allowed/flush").Method != http.MethodPost {
		t.Errorf("FlushAllowed = %v", err)
	}

	// a lease is made a reservation, and a reservation an ordinary lease again
	if err := c.ReserveLease(t.Context(), "Default", "00-11-22-33-44-55"); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dhcp/leases/convertToReserved"); asked.Method != http.MethodPost || len(asked.Params) != 2 || asked.Params.Get("name") != "Default" || asked.Params.Get("hardwareAddress") != "00-11-22-33-44-55" {
		t.Errorf("the lease was reserved with %v", asked.Params)
	}
	if err := c.UnreserveLease(t.Context(), "Default", "00-11-22-33-44-55"); err != nil || fake.Last("dhcp/leases/convertToDynamic").Method != http.MethodPost || fake.Last("dhcp/leases/convertToDynamic").Params.Get("hardwareAddress") != "00-11-22-33-44-55" {
		t.Errorf("UnreserveLease = %v, sent %v", err, fake.Last("dhcp/leases/convertToDynamic").Params)
	}

	refused := map[string]error{
		"no names blocked":       c.ImportBlocked(t.Context(), nil),
		"no names allowed":       c.ImportAllowed(t.Context(), nil),
		"no lease reserved":      c.ReserveLease(t.Context(), "Default", ""),
		"a lease of no scope":    c.ReserveLease(t.Context(), "", "00-11-22-33-44-55"),
		"no lease made ordinary": c.UnreserveLease(t.Context(), "Default", ""),
	}
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	if len(fake.Requests("blocked/import")) != 1 || len(fake.Requests("allowed/import")) != 1 || len(fake.Requests("dhcp/leases/convertToReserved")) != 1 || len(fake.Requests("dhcp/leases/convertToDynamic")) != 1 {
		t.Error("a refused call reached the server")
	}
}

// A client's calls are passed on to another node of the cluster where the
// API passes them on, and refused without being sent where it does not.
func TestOnNode(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/list", `{"zones":[]}`)
	fake.Answer("zones/enable", `{}`)
	fake.Answer("cache/flush", `{}`)
	c := client(t, fake)
	other := c.OnNode("ns2.cluster.example")

	if c.Node() != "" || other.Node() != "ns2.cluster.example" || other.BaseURL() != c.BaseURL() {
		t.Errorf("the client is on %q and the one made from it on %q at %s", c.Node(), other.Node(), other.BaseURL())
	}
	if _, err := other.Zones(t.Context(), technitium.ZoneFilter{}); err != nil || fake.Last("zones/list").Params.Get("node") != "ns2.cluster.example" {
		t.Errorf("a read for another node was asked with %v, %v", fake.Last("zones/list").Params, err)
	}
	if err := other.EnableZone(t.Context(), "example.com"); err != nil || fake.Last("zones/enable").Params.Get("node") != "ns2.cluster.example" || fake.Last("zones/enable").Params.Get("zone") != "example.com" || fake.Last("zones/enable").Method != http.MethodPost {
		t.Errorf("a write for another node was sent %v, %v", fake.Last("zones/enable").Params, err)
	}
	// the client it was made from still asks the server itself
	if _, err := c.Zones(t.Context(), technitium.ZoneFilter{}); err != nil || fake.Last("zones/list").Params.Has("node") {
		t.Errorf("the server itself was asked with %v, %v", fake.Last("zones/list").Params, err)
	}
	// a call the API does not pass on would be answered by the wrong server
	if err := other.FlushCache(t.Context()); err == nil || !strings.Contains(err.Error(), "does not pass this call on") || len(fake.Requests("cache/flush")) != 0 {
		t.Errorf("a call that is not passed on = %v, and %d reached the server", err, len(fake.Requests("cache/flush")))
	}
	if err := other.OnNode("").FlushCache(t.Context()); err != nil || len(fake.Requests("cache/flush")) != 1 {
		t.Errorf("the server itself again = %v", err)
	}
}
