package technitium_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// The answers below are a Technitium 15.6 server's own, taken from one and
// cut down. The canned server holds every request against the API document,
// so each test here also proves its call and parameters are ones the server
// takes; the SDK suite proves the answers against a server running.

const sessionAnswer = `{"displayName":"Administrator","username":"admin","tokenName":"mcp","token":"5ecre75ecre75ecre7","info":{"version":"15.6","uptimestamp":"2026-10-09T22:35:01.5902233Z","dnsServerDomain":"ns1","defaultRecordTtl":3600,"defaultNsRecordTtl":14400,"defaultSoaRecordTtl":900,"useSoaSerialDateScheme":false,"dnssecValidation":true,"clusterInitialized":true,"clusterDomain":"example.com","permissions":{"Zones":{"canView":true,"canModify":true,"canDelete":false},"Settings":{"canView":false,"canModify":false,"canDelete":false}}},"server":"ns1","status":"ok"}`

func TestStatus(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.AnswerWhole("status", `{"hasDefaultCredentials":true,"ssoEnabled":false,"server":"ns1","status":"ok"}`)

	got, err := client(t, fake).Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.Server != "ns1" || !got.HasDefaultCredentials || got.SSOEnabled {
		t.Errorf("Status = %+v", got)
	}
}

// A session says who the token acts as, what that account may do and what
// the server is. The server sends the token back with it, which the client
// does not keep: nothing that prints a session can print a credential.
func TestSession(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.AnswerWhole("user/session/get", sessionAnswer)

	got, err := client(t, fake).Session(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	info := got.Info
	if got.Username != "admin" || got.TokenName != "mcp" || info.Version != "15.6" || info.Domain != "ns1" || !info.DNSSECValidation || !info.ClusterInitialized || info.ClusterDomain != "example.com" || info.DefaultRecordTTL != 3600 {
		t.Errorf("Session = %+v", got)
	}
	if zones := info.Permissions["Zones"]; !zones.CanView || !zones.CanModify || zones.CanDelete {
		t.Errorf("the Zones permission = %+v", zones)
	}
	if started, ok := info.Started(); !ok || !started.Equal(time.Date(2026, 10, 9, 22, 35, 1, 590223300, time.UTC)) {
		t.Errorf("Started = %v, %v", started, ok)
	}

	printed, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(printed), "5ecre7") {
		t.Errorf("the session carries the token the server sent back: %s", printed)
	}
}

func TestCheckForUpdate(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("user/checkForUpdate", `{"dnsServerEnableCheckForUpdate":true,"updateAvailable":true,"updateVersion":"15.7","currentVersion":"15.6","updateTitle":"New Update Available!"}`)

	got, err := client(t, fake).CheckForUpdate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !got.CheckEnabled || !got.Available || got.UpdateVersion != "15.7" || got.CurrentVersion != "15.6" {
		t.Errorf("CheckForUpdate = %+v", got)
	}
}

// The server writes times in UTC with a Z, and "never" as the zero time with
// no zone at all, which is no time.
func TestParseTime(t *testing.T) {
	t.Parallel()

	for text, want := range map[string]string{
		"2026-10-09T22:35:28.050422Z": "2026-10-09T22:35:28Z",
		"2026-10-09T22:35:28Z":        "2026-10-09T22:35:28Z",
		"2026-10-09T22:35:28.1319161": "2026-10-09T22:35:28Z",
		"0001-01-01T00:00:00":         "",
		"0001-01-01T00:00:00Z":        "",
		"":                            "",
		"yesterday":                   "",
	} {
		got, ok := technitium.ParseTime(text)
		if (want == "") == ok || (ok && got.UTC().Format(time.RFC3339) != want) {
			t.Errorf("ParseTime(%q) = %v, %v; want %q", text, got, ok, want)
		}
	}
}

const zonesAnswer = `{"zones":[
	{"name":"example.com","type":"Primary","lastModified":"2026-10-09T22:35:28.1319161Z","disabled":false,"soaSerial":7,"catalog":null,"dnssecStatus":"SignedWithNSEC3","hasDnssecPrivateKeys":true,"notifyFailed":true,"notifyFailedFor":["10.0.0.3"]},
	{"name":"example.net","type":"Secondary","lastModified":"2026-10-09T22:35:28Z","disabled":true,"soaSerial":4,"catalog":"cat.example","dnssecStatus":"Unsigned","expiry":"2026-10-16T22:35:28Z","isExpired":false,"syncFailed":true},
	{"name":"localhost","type":"Primary","internal":true,"dnssecStatus":"Unsigned","soaSerial":1,"disabled":false}
]}`

func TestZones(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/list", zonesAnswer)
	c := client(t, fake)

	zones, err := c.Zones(t.Context(), technitium.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 3 {
		t.Fatalf("Zones = %d zones, want 3", len(zones))
	}
	if asked := fake.Last("zones/list"); asked.Method != http.MethodGet || len(asked.Params) != 0 {
		t.Errorf("every zone was asked for with %s %v, want a GET with no filter and no paging", asked.Method, asked.Params)
	}

	primary, secondary, internal := zones[0], zones[1], zones[2]
	if primary.Name != "example.com" || primary.Type != technitium.ZonePrimary || primary.SOASerial != 7 || !primary.Signed() || !primary.NotifyFailed || len(primary.NotifyFailedFor) != 1 || primary.Catalog != "" {
		t.Errorf("the primary = %+v", primary)
	}
	if modified, ok := primary.Modified(); !ok || modified.Year() != 2026 {
		t.Errorf("the primary's Modified = %v, %v", modified, ok)
	}
	if secondary.Type != technitium.ZoneSecondary || !secondary.Disabled || !secondary.SyncFailed || secondary.IsExpired || secondary.Catalog != "cat.example" || secondary.Signed() || secondary.Expiry == "" {
		t.Errorf("the secondary = %+v", secondary)
	}
	if _, ok := internal.Modified(); !internal.Internal || ok {
		t.Errorf("the internal zone = %+v, and a zone with no modified time read as having one: %v", internal, ok)
	}

	if _, err := c.Zones(t.Context(), technitium.ZoneFilter{Name: "*.com", Type: technitium.ZonePrimary}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/list"); asked.Params.Get("filterName") != "*.com" || asked.Params.Get("filterType") != "Primary" {
		t.Errorf("a filtered listing was asked for with %v", asked.Params)
	}
}

func TestCreateAndDeleteZone(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/create", `{"domain":"0.0.10.in-addr.arpa"}`)
	fake.Answer("zones/delete", `{}`)
	c := client(t, fake)

	name, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "10.0.0.0/24", Type: technitium.ZoneSecondary, PrimaryNameServerAddresses: []string{"10.0.0.2", "10.0.0.3"}})
	if err != nil {
		t.Fatal(err)
	}
	if name != "0.0.10.in-addr.arpa" {
		t.Errorf("CreateZone = %q, want the name the server gave the zone", name)
	}
	asked := fake.Last("zones/create")
	if asked.Method != http.MethodPost || asked.Params.Get("zone") != "10.0.0.0/24" || asked.Params.Get("type") != "Secondary" || asked.Params.Get("primaryNameServerAddresses") != "10.0.0.2,10.0.0.3" {
		t.Errorf("the zone was created with %s %v", asked.Method, asked.Params)
	}

	if err := c.DeleteZone(t.Context(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/delete"); asked.Method != http.MethodPost || asked.Params.Get("zone") != "example.com" {
		t.Errorf("the zone was deleted with %s %v", asked.Method, asked.Params)
	}

	// nothing is asked of the server for a call that names nothing
	if _, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "example.com"}); err == nil {
		t.Error("a zone with no type was sent")
	}
	if err := c.DeleteZone(t.Context(), ""); err == nil {
		t.Error("a delete naming no zone was sent")
	}
	if n := len(fake.Requests("zones/create")) + len(fake.Requests("zones/delete")); n != 2 {
		t.Errorf("%d writes reached the server, want the 2 that named something", n)
	}
}

const recordsAnswer = `{"zone":{"name":"example.com","type":"Primary","disabled":false,"soaSerial":7,"dnssecStatus":"Unsigned"},"records":[
	{"name":"example.com","type":"NS","ttl":14400,"disabled":false,"rData":{"nameServer":"ns1"},"lastUsedOn":"0001-01-01T00:00:00","lastModified":"2026-10-09T22:35:28.0274525Z","expiryTtl":0},
	{"name":"example.com","type":"SOA","ttl":900,"disabled":false,"rData":{"primaryNameServer":"ns1","responsiblePerson":"hostadmin@example.com","serial":7,"refresh":900,"retry":300,"expire":604800,"minimum":900,"useSerialDateScheme":false},"lastUsedOn":"0001-01-01T00:00:00","expiryTtl":0},
	{"name":"example.com","type":"MX","ttl":3600,"disabled":false,"rData":{"preference":10,"exchange":"mail.example.com"},"expiryTtl":0},
	{"name":"example.com","type":"TXT","ttl":3600,"disabled":false,"rData":{"text":"v=spf1 -all","splitText":false,"characterStrings":["v=spf1 -all"]},"expiryTtl":0},
	{"name":"_sip._tcp.example.com","type":"SRV","ttl":3600,"disabled":false,"rData":{"priority":1,"weight":2,"port":5060,"target":"a.example.com"},"expiryTtl":0},
	{"name":"a.example.com","type":"A","ttl":300,"disabled":true,"comments":"the emby vm","rData":{"ipAddress":"10.0.0.4"},"lastUsedOn":"2026-10-09T23:00:00Z","lastModified":"2026-10-09T22:35:28.0498583Z","expiryTtl":0},
	{"name":"a.example.com","type":"AAAA","ttl":3600,"disabled":false,"rData":{"ipAddress":"fd00::4"},"expiryTtl":86400},
	{"name":"c.example.com","type":"CNAME","ttl":3600,"disabled":false,"rData":{"cname":"a.example.com"},"expiryTtl":0},
	{"name":"k.example.com","type":"SSHFP","ttl":3600,"disabled":false,"rData":{"algorithm":"Ed25519","fingerprintType":"SHA256","fingerprint":"AB12"},"expiryTtl":0}
]}`

// A record's data comes in fields that depend on its type; Value writes it
// on one line as a zone file would, Target is the name it points at and
// Address the address of the two types that have one.
func TestZoneRecords(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/records/get", recordsAnswer)
	c := client(t, fake)

	got, err := c.ZoneRecords(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/records/get"); asked.Method != http.MethodGet || asked.Params.Get("domain") != "example.com" || asked.Params.Get("zone") != "example.com" || asked.Params.Get("listZone") != "true" {
		t.Errorf("the whole zone was asked for with %s %v", asked.Method, asked.Params)
	}
	if got.Zone.Name != "example.com" || len(got.Records) != 9 {
		t.Fatalf("ZoneRecords = zone %q with %d records", got.Zone.Name, len(got.Records))
	}

	want := []struct{ recordType, value, target string }{
		{"NS", "ns1", "ns1"},
		{"SOA", "ns1 hostadmin@example.com 7 900 300 604800 900", ""},
		{"MX", "10 mail.example.com", "mail.example.com"},
		{"TXT", "v=spf1 -all", ""},
		{"SRV", "1 2 5060 a.example.com", "a.example.com"},
		{"A", "10.0.0.4", ""},
		{"AAAA", "fd00::4", ""},
		{"CNAME", "a.example.com", "a.example.com"},
		{"SSHFP", "Ed25519 SHA256 AB12", ""},
	}
	for i, w := range want {
		rec := &got.Records[i]
		if rec.Type != w.recordType || rec.Value() != w.value || rec.Target() != w.target {
			t.Errorf("record %d = %s %q -> %q, want %s %q -> %q", i, rec.Type, rec.Value(), rec.Target(), w.recordType, w.value, w.target)
		}
	}

	a := &got.Records[5]
	if addr, ok := a.Address(); !ok || addr.String() != "10.0.0.4" || !a.Disabled || a.Comments != "the emby vm" || a.TTL != 300 {
		t.Errorf("the A record = %+v", a)
	}
	if used, ok := a.Used(); !ok || used.Hour() != 23 {
		t.Errorf("the A record's Used = %v, %v", used, ok)
	}
	if _, ok := got.Records[0].Used(); ok {
		t.Error("a record that never answered a query reads as used")
	}
	if _, ok := got.Records[0].Modified(); !ok {
		t.Error("a record with a modified time reads as having none")
	}
	if _, ok := got.Records[7].Address(); ok {
		t.Error("a CNAME has an address")
	}
	if got.Records[6].ExpiryTTL != 86400 {
		t.Errorf("the AAAA record's expiry = %d", got.Records[6].ExpiryTTL)
	}

	if _, err := c.RecordsAt(t.Context(), "a.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/records/get"); asked.Params.Get("domain") != "a.example.com" || asked.Params.Has("zone") || asked.Params.Has("listZone") {
		t.Errorf("one name's records were asked for with %v", asked.Params)
	}
	if _, err := c.RecordsAt(t.Context(), "a.example.com", "example.com"); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/records/get"); asked.Params.Get("zone") != "example.com" {
		t.Errorf("one name's records in a named zone were asked for with %v", asked.Params)
	}
	if _, err := c.ZoneRecords(t.Context(), ""); err == nil {
		t.Error("a zone with no name was asked for")
	}
	if _, err := c.RecordsAt(t.Context(), "", ""); err == nil {
		t.Error("a name that is none was asked for")
	}
}

// A record is added and deleted with its data sent as the parameters its
// type takes: an MX's preference and exchange, a CNAME's name - and nothing
// at all to delete a CNAME by, since a name holds one.
func TestAddAndDeleteRecord(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/records/add", `{"zone":{"name":"example.com","type":"Primary"},"addedRecord":{"name":"example.com","type":"MX","ttl":300,"disabled":false,"comments":"mail","rData":{"preference":10,"exchange":"mail.example.com"},"expiryTtl":0}}`)
	fake.Answer("zones/records/delete", `{}`)
	c := client(t, fake)

	added, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: "example.com", Name: "example.com", Type: "MX", TTL: 300, Comments: "mail", Overwrite: true, Data: technitium.RData{"preference": 10, "exchange": "mail.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if added.Value() != "10 mail.example.com" || added.TTL != 300 || added.Comments != "mail" {
		t.Errorf("AddRecord = %+v, want the record as the server now holds it", added)
	}
	asked := fake.Last("zones/records/add")
	for param, want := range map[string]string{"domain": "example.com", "zone": "example.com", "type": "MX", "ttl": "300", "comments": "mail", "overwrite": "true", "preference": "10", "exchange": "mail.example.com"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the record was added with %s=%q, want %q (%v)", param, asked.Params.Get(param), want, asked.Params)
		}
	}
	if asked.Method != http.MethodPost {
		t.Errorf("the record was added with a %s", asked.Method)
	}

	// what is left out is left to the server: its default TTL, the closest zone
	if _, err := c.AddRecord(t.Context(), technitium.NewRecord{Name: "a.example.com", Type: "A", Data: technitium.RData{"ipAddress": "10.0.0.4"}}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/records/add"); asked.Params.Has("ttl") || asked.Params.Has("zone") || asked.Params.Has("comments") || asked.Params.Has("overwrite") || asked.Params.Get("ipAddress") != "10.0.0.4" {
		t.Errorf("a bare record was added with %v", asked.Params)
	}

	if err := c.DeleteRecord(t.Context(), "example.com", &technitium.Record{Name: "c.example.com", Type: "CNAME", Data: technitium.RData{"cname": "a.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/records/delete"); asked.Params.Get("domain") != "c.example.com" || asked.Params.Get("type") != "CNAME" || asked.Params.Get("zone") != "example.com" || len(asked.Params) != 3 {
		t.Errorf("the CNAME was deleted with %v, want its name, type and zone alone", asked.Params)
	}
	if err := c.DeleteRecord(t.Context(), "", &technitium.Record{Name: "_sip._tcp.example.com", Type: "SRV", Data: technitium.RData{"priority": float64(1), "weight": float64(2), "port": float64(5060), "target": "a.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/records/delete"); asked.Params.Get("priority") != "1" || asked.Params.Get("port") != "5060" || asked.Params.Get("target") != "a.example.com" || asked.Params.Has("zone") {
		t.Errorf("the SRV was deleted with %v", asked.Params)
	}

	// what cannot be sent whole is not sent
	sent := len(fake.Requests("zones/records/add")) + len(fake.Requests("zones/records/delete"))
	if _, err := c.AddRecord(t.Context(), technitium.NewRecord{Name: "example.com", Type: "SOA", Data: technitium.RData{"primaryNameServer": "ns1"}}); err == nil || !strings.Contains(err.Error(), "a SOA record is not added, changed or deleted as other records are") {
		t.Errorf("a type that is not written as a record is = %v", err)
	}
	if _, err := c.AddRecord(t.Context(), technitium.NewRecord{Name: "k.example.com", Type: "SSHFP", Data: technitium.RData{"fingerprint": "AB12"}}); err == nil || !strings.Contains(err.Error(), "record type SSHFP needs algorithm, fingerprintType, fingerprint, and algorithm is not given") {
		t.Errorf("a record with a field missing = %v", err)
	}
	if _, err := c.AddRecord(t.Context(), technitium.NewRecord{Name: "example.com", Type: "MX", Data: technitium.RData{"exchange": "mail.example.com"}}); err == nil || !strings.Contains(err.Error(), "record type MX needs preference, exchange, and preference is not given") {
		t.Errorf("an MX with no preference = %v", err)
	}
	if _, err := c.AddRecord(t.Context(), technitium.NewRecord{Type: "A"}); err == nil {
		t.Error("a record with no name was sent")
	}
	if err := c.DeleteRecord(t.Context(), "", &technitium.Record{Name: "a.example.com", Type: "A"}); err == nil {
		t.Error("an A record was deleted without saying which address")
	}
	if err := c.DeleteRecord(t.Context(), "", &technitium.Record{Type: "A"}); err == nil {
		t.Error("a record with no name was deleted")
	}
	if now := len(fake.Requests("zones/records/add")) + len(fake.Requests("zones/records/delete")); now != sent {
		t.Errorf("%d refused writes reached the server", now-sent)
	}
}
