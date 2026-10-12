//go:build acceptance

package technitium_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// A server says who it is with no token, and what the token is with one.
func TestStatusAndSession(t *testing.T) {
	t.Parallel()

	ready(t)
	for _, name := range world.Names() {
		c := server(t, name)
		domain := world.Domain(name)

		status, err := c.Status(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		// the script names each server after itself, a cluster renames it
		// under its own domain, and the script sets a password
		if status.Server != domain || status.HasDefaultCredentials {
			t.Errorf("%s: Status = %+v, want it to call itself %s", name, status, domain)
		}

		session, err := c.Session(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		info := session.Info
		if session.Username != "admin" || session.TokenName == "" || info.Domain != domain || info.Version == "" || info.DefaultRecordTTL == 0 {
			t.Errorf("%s: Session = %+v", name, session)
		}
		if clustered := world.Topology == testenv.Cluster; info.ClusterInitialized != clustered || (clustered && info.ClusterDomain != testenv.ClusterDomain) || (!clustered && info.ClusterDomain != "") {
			t.Errorf("%s: the session says clustered %v in %q, in the %s topology", name, info.ClusterInitialized, info.ClusterDomain, world.Topology)
		}
		if started, ok := info.Started(); !ok || time.Since(started) < 0 || time.Since(started) > 24*time.Hour {
			t.Errorf("%s: started %v (%v), want a time in the last day", name, started, ok)
		}
		// an administrator may do everything, in every section the server has
		if len(info.Permissions) < 10 {
			t.Errorf("%s: %d sections of permissions, want the server's eleven or so: %v", name, len(info.Permissions), info.Permissions)
		}
		for section, may := range info.Permissions {
			if !may.CanView || !may.CanModify || !may.CanDelete {
				t.Errorf("%s: the administrator may not do everything in %s: %+v", name, section, may)
			}
		}
	}
}

// The update check answers whether or not the server can reach its maker's
// site, which a test container may not.
func TestCheckForUpdate(t *testing.T) {
	t.Parallel()

	c := first(t)
	update, err := c.CheckForUpdate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.Session(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if update.CurrentVersion != "" && update.CurrentVersion != session.Info.Version {
		t.Errorf("the update check says the server runs %s and its session says %s", update.CurrentVersion, session.Info.Version)
	}
}

// A token the server does not know is refused in the body of a 200, which
// the client turns into the error that says so.
func TestARefusedToken(t *testing.T) {
	t.Parallel()

	good := first(t)
	bad, err := technitium.New(good.BaseURL(), "not-a-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Zones(t.Context(), technitium.ZoneFilter{}); !technitium.IsInvalidToken(err) {
		t.Errorf("Zones with a made-up token = %v, want the token refused", err)
	}
	// who the server is needs no token
	if _, err := bad.Status(t.Context()); err != nil {
		t.Errorf("Status with a made-up token = %v", err)
	}
}

// Zones are made, listed with what the listing says of them, filtered on the
// server's side, and deleted.
func TestZones(t *testing.T) {
	t.Parallel()

	c := first(t)
	zone(t, c, "sdk-zones.test")
	zone(t, c, "other.sdk-zones.test")

	find := func(zones []technitium.Zone, name string) *technitium.Zone {
		for i := range zones {
			if zones[i].Name == name {
				return &zones[i]
			}
		}

		return nil
	}

	all, err := c.Zones(t.Context(), technitium.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}
	made := find(all, "sdk-zones.test")
	if made == nil {
		t.Fatalf("the zone just made is not listed: %+v", all)
	}
	if made.Type != technitium.ZonePrimary || made.Disabled || made.Internal || made.Signed() || made.SOASerial == 0 || made.Catalog != "" {
		t.Errorf("the zone = %+v", made)
	}
	if modified, ok := made.Modified(); !ok || time.Since(modified) > time.Hour {
		t.Errorf("the zone was last modified %v (%v), want just now", modified, ok)
	}

	// the server's own filter: a pattern for the whole name, and a type
	sub, err := c.Zones(t.Context(), technitium.ZoneFilter{Name: "*.sdk-zones.test"})
	if err != nil {
		t.Fatal(err)
	}
	if find(sub, "other.sdk-zones.test") == nil || find(sub, "sdk-zones.test") != nil {
		t.Errorf("filtered by *.sdk-zones.test = %+v", sub)
	}
	secondaries, err := c.Zones(t.Context(), technitium.ZoneFilter{Type: technitium.ZoneSecondary})
	if err != nil {
		t.Fatal(err)
	}
	if find(secondaries, "sdk-zones.test") != nil {
		t.Errorf("a primary is listed among the secondaries: %+v", secondaries)
	}

	// an address makes the reverse zone for it, under the name the server gives
	_ = c.DeleteZone(t.Context(), "7.168.192.in-addr.arpa")
	name, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "192.168.7.0/24", Type: technitium.ZonePrimary})
	if err != nil {
		t.Fatal(err)
	}
	if name != "7.168.192.in-addr.arpa" {
		t.Errorf("the reverse zone for 192.168.7.0/24 is named %q", name)
	}
	if err := c.DeleteZone(t.Context(), name); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteZone(t.Context(), name); err == nil {
		t.Error("a zone that is gone was deleted again without a word")
	}

	// a zone made twice is refused in the server's words
	if _, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "sdk-zones.test", Type: technitium.ZonePrimary}); err == nil {
		t.Error("a zone that exists was made again")
	} else if _, ok := errors.AsType[*technitium.APIError](err); !ok {
		t.Errorf("making a zone twice = %v, want the server's refusal", err)
	}
}

// Every type of record the client writes goes in, reads back with the value
// it was given, and comes out again.
func TestRecords(t *testing.T) {
	t.Parallel()

	const z = "sdk-records.test"
	c := first(t)
	zone(t, c, z)

	want := []struct {
		name, recordType, value, target string
		data                            technitium.RData
	}{
		{"a." + z, "A", "10.0.0.4", "", technitium.RData{"ipAddress": "10.0.0.4"}},
		{"a." + z, "AAAA", "fd00::4", "", technitium.RData{"ipAddress": "fd00::4"}},
		{"c." + z, "CNAME", "a." + z, "a." + z, technitium.RData{"cname": "a." + z}},
		{"sub." + z, "NS", "ns.elsewhere.test", "ns.elsewhere.test", technitium.RData{"nameServer": "ns.elsewhere.test"}},
		{"4.0.0.10.in-addr." + z, "PTR", "a." + z, "a." + z, technitium.RData{"ptrName": "a." + z}},
		{z, "MX", "10 mail." + z, "mail." + z, technitium.RData{"preference": 10, "exchange": "mail." + z}},
		{z, "TXT", "v=spf1 -all", "", technitium.RData{"text": "v=spf1 -all"}},
		{"_sip._tcp." + z, "SRV", "1 2 5060 a." + z, "a." + z, technitium.RData{"priority": 1, "weight": 2, "port": 5060, "target": "a." + z}},
		{"d." + z, "DNAME", "elsewhere.test", "elsewhere.test", technitium.RData{"dname": "elsewhere.test"}},
		{"an." + z, "ANAME", "a." + z, "a." + z, technitium.RData{"aname": "a." + z}},
		{z, "CAA", "0 issue letsencrypt.org", "", technitium.RData{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}},
	}
	for _, w := range want {
		added, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: w.name, Type: w.recordType, TTL: 300, Comments: "made by the SDK suite", Data: w.data})
		if err != nil {
			t.Errorf("adding the %s: %v", w.recordType, err)

			continue
		}
		if added.Name != w.name || added.Type != w.recordType || added.TTL != 300 || added.Comments != "made by the SDK suite" || added.Value() != w.value || added.Target() != w.target || added.Disabled {
			t.Errorf("the %s as added = %+v (value %q, target %q), want value %q and target %q", w.recordType, added, added.Value(), added.Target(), w.value, w.target)
		}
	}

	whole, err := c.ZoneRecords(t.Context(), z)
	if err != nil {
		t.Fatal(err)
	}
	if whole.Zone.Name != z || whole.Zone.Type != technitium.ZonePrimary {
		t.Errorf("the zone read with its records = %+v", whole.Zone)
	}
	find := func(name, recordType string) *technitium.Record {
		for i := range whole.Records {
			if whole.Records[i].Name == name && whole.Records[i].Type == recordType {
				return &whole.Records[i]
			}
		}

		return nil
	}
	// what the server made with the zone, in the client's own layout
	if soa := find(z, "SOA"); soa == nil || !strings.HasPrefix(soa.Value(), world.Domain(world.First)+" ") || len(strings.Fields(soa.Value())) != 7 {
		t.Errorf("the zone's SOA = %+v", soa)
	}
	if ns := find(z, "NS"); ns == nil || ns.Target() != world.Domain(world.First) {
		t.Errorf("the zone's own NS = %+v", ns)
	}
	for _, w := range want {
		rec := find(w.name, w.recordType)
		if rec == nil {
			t.Errorf("the %s at %s was added and is not in the zone", w.recordType, w.name)

			continue
		}
		if rec.Value() != w.value || rec.TTL != 300 {
			t.Errorf("the %s read back = %q with ttl %d, want %q with 300", w.recordType, rec.Value(), rec.TTL, w.value)
		}
		if _, ok := rec.Modified(); !ok {
			t.Errorf("the %s has no modified time: %q", w.recordType, rec.LastModified)
		}
		if used, ok := rec.Used(); ok {
			t.Errorf("the %s, never asked for, was last used %v", w.recordType, used)
		}
	}
	if a := find("a."+z, "A"); a != nil {
		if addr, ok := a.Address(); !ok || addr.String() != "10.0.0.4" {
			t.Errorf("the A record's address = %v, %v", addr, ok)
		}
	}

	// one name's records, with the zone named and with it left to the server
	for _, zoneArg := range []string{z, ""} {
		here, readErr := c.RecordsAt(t.Context(), "a."+z, zoneArg)
		if readErr != nil {
			t.Fatal(readErr)
		}
		types := make([]string, 0, len(here.Records))
		for i := range here.Records {
			types = append(types, here.Records[i].Type)
		}
		slices.Sort(types)
		if !slices.Equal(types, []string{"A", "AAAA"}) || here.Zone.Name != z {
			t.Errorf("the records at a.%s (zone %q) = %v in %s", z, zoneArg, types, here.Zone.Name)
		}
	}

	// the server's own rules come back in its words
	if _, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "a." + z, Type: "CNAME", Data: technitium.RData{"cname": "x." + z}}); err == nil || !strings.Contains(err.Error(), "CNAME") {
		t.Errorf("a CNAME beside an A = %v, want the server's refusal", err)
	}

	// overwrite replaces what was there, where the default adds beside it
	if _, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "a." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.0.0.5"}}); err != nil {
		t.Fatal(err)
	}
	at, err := c.RecordsAt(t.Context(), "a."+z, z)
	if err != nil || countA(at.Records) != 2 {
		t.Fatalf("a second A added beside the first: %d A records, %v", countA(at.Records), err)
	}
	if _, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "a." + z, Type: "A", Overwrite: true, Data: technitium.RData{"ipAddress": "10.0.0.6"}}); err != nil {
		t.Fatal(err)
	}
	at, err = c.RecordsAt(t.Context(), "a."+z, z)
	if err != nil || countA(at.Records) != 1 {
		t.Fatalf("an A written over the others: %d A records, %v", countA(at.Records), err)
	}
	// with no TTL given, the server's default for the type
	session, err := c.Session(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for i := range at.Records {
		if at.Records[i].Type == "A" && (at.Records[i].Value() != "10.0.0.6" || at.Records[i].TTL != session.Info.DefaultRecordTTL) {
			t.Errorf("the A written over = %q with ttl %d, want 10.0.0.6 with the server's default %d", at.Records[i].Value(), at.Records[i].TTL, session.Info.DefaultRecordTTL)
		}
	}

	// every record comes out again, each by what the server read back
	whole, err = c.ZoneRecords(t.Context(), z)
	if err != nil {
		t.Fatal(err)
	}
	for i := range whole.Records {
		rec := &whole.Records[i]
		if rec.Name == z && (rec.Type == "SOA" || rec.Type == "NS") {
			continue
		}
		if err := c.DeleteRecord(t.Context(), z, rec); err != nil {
			t.Errorf("deleting the %s at %s: %v", rec.Type, rec.Name, err)
		}
	}
	left, err := c.ZoneRecords(t.Context(), z)
	if err != nil {
		t.Fatal(err)
	}
	if len(left.Records) != 2 {
		t.Errorf("with every record deleted the zone holds %d, want its SOA and NS: %+v", len(left.Records), left.Records)
	}
}

// countA is how many of the records are A records.
func countA(records []technitium.Record) int {
	n := 0
	for i := range records {
		if records[i].Type == "A" {
			n++
		}
	}

	return n
}

// A server resolves a name as it would for a client: through the CNAMEs in
// its own zone to the address, saying the name is not there when it is not,
// and answering nothing for a type the name has no record of. Asked to put
// the question to a name server by its address, it gets the same.
func TestResolve(t *testing.T) {
	t.Parallel()

	const z = "sdk-resolve.test"
	c := first(t)
	zone(t, c, z)
	for _, rec := range []technitium.NewRecord{
		{Zone: z, Name: "emby." + z, Type: "A", TTL: 300, Data: technitium.RData{"ipAddress": "10.0.0.4"}},
		{Zone: z, Name: "m." + z, Type: "CNAME", Data: technitium.RData{"cname": "emby." + z}},
	} {
		if _, err := c.AddRecord(t.Context(), rec); err != nil {
			t.Fatal(err)
		}
	}

	for _, via := range []string{"", technitium.ResolveThisServer, world.Address(world.First)} {
		got, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "m." + z, Via: via})
		if err != nil {
			t.Fatalf("asked of %q: %v", via, err)
		}
		if got.RCode != "NoError" || !got.Authoritative || len(got.Answer) != 2 || got.Metadata.NameServer == "" || got.Metadata.RoundTripTime == "" {
			t.Fatalf("asked of %q: Resolve = %+v", via, got)
		}
		alias, address := &got.Answer[0], &got.Answer[1]
		if alias.Name != "m."+z || alias.Type != "CNAME" || alias.Target() != "emby."+z || alias.TTL() == 0 {
			t.Errorf("asked of %q: the CNAME = %+v", via, alias)
		}
		if addr, ok := address.Address(); !ok || addr.String() != "10.0.0.4" || address.Name != "emby."+z || address.TTL() != 300 || address.Value() != "10.0.0.4" {
			t.Errorf("asked of %q: the address = %+v", via, address)
		}
	}

	missing, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "nope." + z})
	if err != nil || missing.RCode != "NxDomain" || !missing.Authoritative || len(missing.Answer) != 0 {
		t.Errorf("a name that is not there = %+v, %v", missing, err)
	}
	// the zone's SOA comes with it, in the layout the client reads
	if len(missing.Authority) != 1 || missing.Authority[0].Type != "SOA" || len(strings.Fields(missing.Authority[0].Value())) != 7 {
		t.Errorf("the authority of a name that is not there = %+v", missing.Authority)
	}

	none, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "emby." + z, Type: "TXT"})
	if err != nil || none.RCode != "NoError" || len(none.Answer) != 0 {
		t.Errorf("a type the name has no record of = %+v, %v", none, err)
	}

	// every type the client lays out, as a server answers with it
	for _, rec := range []technitium.NewRecord{
		{Zone: z, Name: z, Type: "MX", Data: technitium.RData{"preference": 10, "exchange": "mail." + z}},
		{Zone: z, Name: z, Type: "TXT", Data: technitium.RData{"text": "v=spf1 -all"}},
		{Zone: z, Name: "_sip._tcp." + z, Type: "SRV", Data: technitium.RData{"priority": 1, "weight": 2, "port": 5060, "target": "emby." + z}},
		{Zone: z, Name: "emby." + z, Type: "AAAA", Data: technitium.RData{"ipAddress": "fd00::4"}},
		{Zone: z, Name: z, Type: "CAA", Data: technitium.RData{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}},
	} {
		if _, err := c.AddRecord(t.Context(), rec); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ name, recordType, value, target string }{
		{z, "MX", "10 mail." + z, "mail." + z},
		{z, "TXT", "v=spf1 -all", ""},
		{"_sip._tcp." + z, "SRV", "1 2 5060 emby." + z, "emby." + z},
		{"emby." + z, "AAAA", "fd00::4", ""},
		{z, "CAA", "0 issue letsencrypt.org", ""},
		{z, "NS", world.Domain(world.First), world.Domain(world.First)},
	} {
		got, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: tc.name, Type: tc.recordType})
		if err != nil || len(got.Answer) != 1 {
			t.Errorf("the %s of %s = %+v, %v", tc.recordType, tc.name, got, err)

			continue
		}
		if rec := &got.Answer[0]; rec.Type != tc.recordType || rec.Value() != tc.value || rec.Target() != tc.target {
			t.Errorf("the %s of %s = %q -> %q, want %q -> %q", tc.recordType, tc.name, rec.Value(), rec.Target(), tc.value, tc.target)
		}
	}

	// a name server that is not there is the server's own error, in its words
	if _, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "m." + z, Type: "NOPE"}); err == nil {
		t.Error("a type that is none was resolved")
	}
}

// A record is changed in place and keeps what the change says it keeps: the
// server resets whatever an update leaves out, so the client sends it all.
// Every type the client writes is changed and read back.
func TestUpdateRecord(t *testing.T) {
	t.Parallel()

	const z = "sdk-update.test"
	c := first(t)
	zone(t, c, z)
	const reverse = "6.7.10.in-addr.arpa"
	zone(t, c, reverse)

	// added with its PTR, and a time to delete itself after
	added, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "a." + z, Type: "A", TTL: 300, Comments: "kept", ExpiryTTL: 86400, PTR: true, Data: technitium.RData{"ipAddress": "10.7.6.4"}})
	if err != nil || added.ExpiryTTL != 86400 {
		t.Fatalf("AddRecord = %+v, %v", added, err)
	}
	ptr, err := c.RecordsAt(t.Context(), "4."+reverse, reverse)
	if err != nil || len(ptr.Records) != 1 || ptr.Records[0].Target() != "a."+z {
		t.Fatalf("the PTR the server was asked to add = %+v, %v", ptr, err)
	}

	// its value alone changed: the TTL, the comment and the expiry are what they were
	want := technitium.UpdateOf(added)
	want.Data["ipAddress"] = "10.7.6.5"
	updated, err := c.UpdateRecord(t.Context(), z, added, want)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Value() != "10.7.6.5" || updated.TTL != 300 || updated.Comments != "kept" || updated.ExpiryTTL != 86400 || updated.Disabled {
		t.Errorf("after a change of value = %+v", updated)
	}

	// disabled, renamed and given another TTL and comment at once
	want = technitium.UpdateOf(updated)
	want.Name, want.TTL, want.Comments, want.Disabled, want.ExpiryTTL = "b."+z, 600, "moved", true, 0
	moved, err := c.UpdateRecord(t.Context(), z, updated, want)
	if err != nil {
		t.Fatal(err)
	}
	if moved.Name != "b."+z || moved.TTL != 600 || moved.Comments != "moved" || !moved.Disabled || moved.ExpiryTTL != 0 || moved.Value() != "10.7.6.5" {
		t.Errorf("after a rename = %+v", moved)
	}
	if at, err := c.RecordsAt(t.Context(), "b."+z, z); err != nil || len(at.Records) != 1 || !at.Records[0].Disabled {
		t.Errorf("the record read back under its new name = %+v, %v", at, err)
	}

	// a record that is not there is refused
	if _, err := c.UpdateRecord(t.Context(), z, &technitium.Record{Name: "nope." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.7.6.9"}}, technitium.RecordUpdate{TTL: 60, Data: technitium.RData{"ipAddress": "10.7.6.8"}}); err == nil {
		t.Error("a record that is not there was updated")
	}

	// each type's data changed and read back, in the parameters the API names for it
	for _, tc := range []struct {
		name, recordType string
		before, after    string
	}{
		{"six." + z, "AAAA", "fd00::4", "fd00::5"},
		{"c." + z, "CNAME", "a." + z, "b." + z},
		{"sub." + z, "NS", "ns1.elsewhere.test", "ns2.elsewhere.test"},
		{"9." + reverse, "PTR", "a." + z, "b." + z},
		{z, "MX", "10 mail." + z, "20 mx." + z},
		{z, "TXT", "one text", "another text"},
		{"_sip._tcp." + z, "SRV", "1 2 5060 a." + z, "3 4 5061 b." + z},
		{"d." + z, "DNAME", "one.test", "two.test"},
		{"an." + z, "ANAME", "a." + z, "b." + z},
		{z, "CAA", "0 issue letsencrypt.org", "0 issuewild example.org"},
	} {
		zoneOf := z
		if tc.recordType == "PTR" {
			zoneOf = reverse
		}
		before, err := technitium.ParseValue(tc.recordType, tc.before)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: zoneOf, Name: tc.name, Type: tc.recordType, TTL: 120, Comments: "kept", Data: before})
		if err != nil {
			t.Errorf("adding the %s: %v", tc.recordType, err)

			continue
		}
		change := technitium.UpdateOf(rec)
		if change.Data, err = technitium.ParseValue(tc.recordType, tc.after); err != nil {
			t.Fatal(err)
		}
		got, err := c.UpdateRecord(t.Context(), zoneOf, rec, change)
		if err != nil {
			t.Errorf("updating the %s: %v", tc.recordType, err)

			continue
		}
		if got.Value() != tc.after || got.TTL != 120 || got.Comments != "kept" {
			t.Errorf("the %s changed to %q reads back as %q with ttl %d and comment %q", tc.recordType, tc.after, got.Value(), got.TTL, got.Comments)
		}
	}
}

// What the server does to the other records of a type at a name, which the
// tools that write work around: they share one TTL, and a write that changes
// it rewrites them all without their comments. And an address deleted takes
// the PTR naming its name with it.
func TestWhatAWriteDoesToTheRecordsBesideIt(t *testing.T) {
	t.Parallel()

	const z = "sdk-siblings.test"
	c := first(t)
	zone(t, c, z)
	const reverse = "5.7.10.in-addr.arpa"
	zone(t, c, reverse)

	at := func() map[string]technitium.Record {
		t.Helper()
		read, err := c.RecordsAt(t.Context(), "s."+z, z)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]technitium.Record{}
		for _, rec := range read.Records {
			out[rec.Value()] = rec
		}

		return out
	}
	add := func(address string, ttl int, comment string) {
		t.Helper()
		if _, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "s." + z, Type: "A", TTL: ttl, Comments: comment, PTR: address == "10.7.5.1", Data: technitium.RData{"ipAddress": address}}); err != nil {
			t.Fatal(err)
		}
	}

	// added at the TTL the others have, a record leaves them as they are
	add("10.7.5.1", 300, "one")
	add("10.7.5.2", 300, "two")
	if got := at(); got["10.7.5.1"].Comments != "one" || got["10.7.5.1"].TTL != 300 {
		t.Errorf("after a record added at the same TTL, the first = %+v", got["10.7.5.1"])
	}
	// added at another, it sets that TTL on them all and their comments are gone
	add("10.7.5.3", 900, "three")
	if got := at(); got["10.7.5.1"].TTL != 900 || got["10.7.5.2"].TTL != 900 || got["10.7.5.1"].Comments != "" || got["10.7.5.3"].Comments != "three" {
		t.Errorf("after a record added at another TTL = %+v: the server no longer shares the TTL and drops the others' comments, and record_set need not put them back", got)
	}

	// deleted, the address takes its PTR with it
	one := at()["10.7.5.1"]
	if ptr, err := c.RecordsAt(t.Context(), "1."+reverse, reverse); err != nil || len(ptr.Records) != 1 {
		t.Fatalf("the PTR before the delete = %+v, %v", ptr, err)
	}
	if err := c.DeleteRecord(t.Context(), z, &one); err != nil {
		t.Fatal(err)
	}
	whole, err := c.ZoneRecords(t.Context(), reverse)
	if err != nil {
		t.Fatal(err)
	}
	for i := range whole.Records {
		if whole.Records[i].Type == "PTR" {
			t.Errorf("the PTR is still there after its address was deleted: %+v: the server no longer removes it, and record_delete's answer is wrong to say it does", whole.Records[i])
		}
	}
}

// A server's cache is read, has a name dropped from it, and is flushed. On
// its own a server has nothing in it that came from elsewhere; with a second
// to forward a zone to, it keeps what it resolved there.
//
//nolint:paralleltest // a test beside it that makes a reverse zone empties the cache it reads (TestWhatEmptiesTheCache)
func TestCache(t *testing.T) {
	const z = "sdk-cache.test"
	c := first(t)

	empty, err := c.Cache(t.Context(), "never."+z)
	if err != nil || len(empty.Records) != 0 {
		t.Fatalf("a name never resolved = %+v, %v", empty, err)
	}
	if err := c.DeleteCached(t.Context(), "never."+z); err != nil {
		t.Errorf("dropping a name that is not kept: %v", err)
	}
	if world.Topology == testenv.Single {
		if err := c.FlushCache(t.Context()); err != nil {
			t.Errorf("FlushCache: %v", err)
		}

		return
	}

	second := server(t, world.Second)
	zone(t, second, z)
	if _, err := second.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "a." + z, Type: "A", TTL: 600, Data: technitium.RData{"ipAddress": "10.5.5.6"}}); err != nil {
		t.Fatal(err)
	}
	makeZone(t, c, technitium.NewZone{Name: z, Type: technitium.ZoneForwarder, Forwarder: world.Address(world.Second)})
	// resolved through the forwarder until it answers: a server that has
	// just joined a cluster does not answer its neighbour for a moment, and
	// the failure is what the first server would then keep
	for name, want := range map[string]string{"a." + z: "NoError", "nope." + z: "NxDomain"} {
		var last string
		if !acctest.EventuallyWithin(time.Minute, func() bool {
			res, resolveErr := c.Resolve(t.Context(), technitium.ResolveQuery{Name: name})
			if resolveErr != nil {
				last = resolveErr.Error()

				return false
			}
			last = res.RCode

			return res.RCode == want
		}) {
			t.Fatalf("%s resolved through the forwarder never came to %s: %s", name, want, last)
		}
	}

	held, err := c.Cache(t.Context(), "a."+z)
	if err != nil || held.Domain != "a."+z || len(held.Records) != 1 {
		t.Fatalf("the address kept = %+v, %v", held, err)
	}
	if rec := &held.Records[0]; rec.Value() != "10.5.5.6" || rec.Type != "A" || rec.TTL() <= 0 || rec.TTL() > 600 || rec.Source.NameServer != world.Address(world.Second) {
		t.Errorf("the address kept = %+v", rec)
	} else if _, negative := rec.Negative(); negative {
		t.Error("an answer reads as a negative one")
	}
	missing, err := c.Cache(t.Context(), "nope."+z)
	if err != nil || len(missing.Records) != 1 {
		t.Fatalf("the name that is not there, kept = %+v, %v", missing, err)
	}
	if said, negative := missing.Records[0].Negative(); !negative || said != "NxDomain" {
		t.Errorf("the negative answer says %q (%v): %+v", said, negative, missing.Records[0])
	}
	// from above, the names under it
	above, err := c.Cache(t.Context(), z)
	if err != nil || above.Domain != z || !slices.Contains(above.Zones, "a."+z) || !slices.Contains(above.Zones, "nope."+z) {
		t.Errorf("the names under the zone = %+v, %v", above, err)
	}

	// a name dropped takes what is under it, and leaves the rest
	if err := c.DeleteCached(t.Context(), "nope."+z); err != nil {
		t.Fatal(err)
	}
	if gone, err := c.Cache(t.Context(), "nope."+z); err != nil || len(gone.Records) != 0 {
		t.Errorf("after the drop = %+v, %v", gone, err)
	}
	if kept, err := c.Cache(t.Context(), "a."+z); err != nil || len(kept.Records) != 1 {
		t.Errorf("the name beside it after the drop = %+v, %v", kept, err)
	}
	if err := c.DeleteCached(t.Context(), z); err != nil {
		t.Fatal(err)
	}
	if gone, err := c.Cache(t.Context(), "a."+z); err != nil || len(gone.Records) != 0 {
		t.Errorf("after the drop of the zone = %+v, %v", gone, err)
	}
	// FlushCache drops every name, which would take what the tests beside
	// this one keep: it is called on the second server, which keeps nothing
	if err := second.FlushCache(t.Context()); err != nil {
		t.Errorf("FlushCache: %v", err)
	}
}

// A server's settings read into the client's own, and its apps: the one
// the suites' servers are started with. A cluster's node serves its console
// over HTTPS as well, which is how the nodes reach each other.
func TestSettingsAndApps(t *testing.T) {
	t.Parallel()

	ready(t)
	for _, name := range world.Names() {
		c := server(t, name)
		got, err := c.Settings(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if got.Domain != world.Domain(name) || got.Version == "" || len(got.LocalEndPoints) == 0 || got.Recursion == "" || got.DefaultRecordTTL != 3600 || got.DefaultNSRecordTTL == 0 || got.WebServiceHTTPPort != 5380 || got.BlockingType == "" || got.LoggingType == "" || got.CacheNegativeRecordTTL == 0 || got.CacheMaximumEntries == 0 {
			t.Errorf("%s: Settings = %+v", name, got)
		}
		if !got.DNSSECValidation || !got.EnableBlocking || !got.CheckForUpdate || len(got.Forwarders) != 0 || got.Proxy != nil {
			t.Errorf("%s: a new server's settings = %+v", name, got)
		}
		clustered := world.Topology == testenv.Cluster
		if got.WebServiceEnableTLS != clustered || (clustered && (got.WebServiceTLSPort != 53443 || !got.WebServiceUseSelfSignedCert)) {
			t.Errorf("%s: the console over TLS = %v on %d (signed for itself: %v), in the %s topology", name, got.WebServiceEnableTLS, got.WebServiceTLSPort, got.WebServiceUseSelfSignedCert, world.Topology)
		}
		// a cluster makes itself the key its nodes transfer its catalog with,
		// named for the catalog, and every node has it; a key another test
		// made and took away again may still be on a node until it next
		// fetches the configuration
		if !clustered && len(got.TSIGKeys) != 0 {
			t.Errorf("%s: a new server's transfer keys = %+v", name, got.TSIGKeys)
		}
		if i := slices.IndexFunc(got.TSIGKeys, func(k technitium.TSIGKey) bool { return k.Name == testenv.ClusterCatalog }); clustered && (i < 0 || got.TSIGKeys[i].Algorithm == "") {
			t.Errorf("%s: a cluster node's transfer keys = %+v, want the one named for the catalog among them", name, got.TSIGKeys)
		}

		// the one app the servers are started with: the one that keeps a log of queries to search
		apps, err := c.Apps(t.Context())
		if err != nil || len(apps) != 1 || apps[0].Name != logApp || apps[0].Version == "" || !apps[0].LogsQueries() {
			t.Errorf("%s: Apps = %+v, %v, want the log app .scripts/testenv.sh installs", name, apps, err)
		}
	}
}

// A server says how it stands in a cluster: on its own it is in none and
// lists the addresses it has; in one, every node gives the same two nodes,
// itself as Self, and comes to see the other as connected.
func TestClusterState(t *testing.T) {
	t.Parallel()

	ready(t)
	for _, name := range world.Names() {
		c := server(t, name)
		state, err := c.ClusterState(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if state.ServerDomain != world.Domain(name) || state.Version == "" || len(state.ServerIPAddresses) == 0 {
			t.Errorf("%s: ClusterState = %+v", name, state)
		}

		if world.Topology != testenv.Cluster {
			if state.Initialized || state.Domain != "" || len(state.Nodes) != 0 || state.Self() != nil || state.Primary() != nil {
				t.Errorf("%s is in no cluster, and says %+v", name, state)
			}

			continue
		}

		if !state.Initialized || state.Domain != testenv.ClusterDomain || len(state.Nodes) != 2 {
			t.Fatalf("%s: ClusterState = %+v, want two nodes of %s", name, state, testenv.ClusterDomain)
		}
		self, primary := state.Self(), state.Primary()
		if self == nil || self.Name != world.Domain(name) || len(self.IPAddresses) == 0 || !strings.HasPrefix(self.URL, "https://"+self.Name+":") {
			t.Errorf("%s as it sees itself = %+v", name, self)
		}
		// the first server made the cluster, so it is the primary
		if primary == nil || primary.Name != world.Domain(world.First) || (name == world.First) != (self != nil && self.Type == technitium.NodePrimary) {
			t.Errorf("%s: the primary = %+v and itself = %+v", name, primary, self)
		}
		// a node hears from the other within a heartbeat or two
		if !acctest.EventuallyWithin(2*time.Minute, func() bool {
			now, err := c.ClusterState(t.Context())
			if err != nil {
				return false
			}
			for i := range now.Nodes {
				if now.Nodes[i].State != technitium.NodeSelf && now.Nodes[i].State != technitium.NodeConnected {
					return false
				}
			}

			return true
		}) {
			t.Errorf("%s never came to see the other node as connected", name)
		}
	}
}

// In a cluster, a zone made a member of the cluster's catalog on the primary
// is given to the other node as a secondary, its records follow, and the
// copy there takes no changes. Deleted on the primary, it goes from both.
func TestAClustersZones(t *testing.T) {
	t.Parallel()

	ready(t)
	if world.Topology != testenv.Cluster {
		t.Skipf("the %s topology has no cluster", world.Topology)
	}
	const z = "sdk-shared.test"
	primary, secondary := first(t), server(t, world.Second)

	// the cluster's own zones, as each node holds them
	held := func(c *technitium.Client, name string) *technitium.Zone {
		zones, err := c.Zones(t.Context(), technitium.ZoneFilter{})
		if err != nil {
			t.Fatal(err)
		}
		for i := range zones {
			if zones[i].Name == name {
				return &zones[i]
			}
		}

		return nil
	}
	if catalog := held(primary, testenv.ClusterCatalog); catalog == nil || catalog.Type != technitium.ZoneCatalog {
		t.Errorf("the cluster's catalog on the primary = %+v", catalog)
	}
	if catalog := held(secondary, testenv.ClusterCatalog); catalog == nil || catalog.Type != technitium.ZoneSecondaryCatalog || catalog.IsExpired || catalog.Expiry == "" {
		t.Errorf("the cluster's catalog on the secondary = %+v", catalog)
	}
	if own := held(secondary, testenv.ClusterDomain); own == nil || own.Type != technitium.ZoneSecondary || own.Catalog != testenv.ClusterCatalog {
		t.Errorf("the cluster's own zone on the secondary = %+v", own)
	}

	makeZone(t, primary, technitium.NewZone{Name: z, Type: technitium.ZonePrimary, Catalog: testenv.ClusterCatalog})
	if _, err := primary.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "a." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.0.0.4"}}); err != nil {
		t.Fatal(err)
	}
	if made := held(primary, z); made == nil || made.Type != technitium.ZonePrimary || made.Catalog != testenv.ClusterCatalog {
		t.Fatalf("the zone on the primary = %+v", made)
	}

	// the other node makes itself a secondary of it, and takes its records
	if !acctest.EventuallyWithin(2*time.Minute, func() bool {
		copied := held(secondary, z)
		if copied == nil || copied.Type != technitium.ZoneSecondary || copied.SyncFailed || copied.SOASerial != held(primary, z).SOASerial {
			return false
		}
		records, err := secondary.ZoneRecords(t.Context(), z)

		return err == nil && slices.ContainsFunc(records.Records, func(r technitium.Record) bool { return r.Name == "a."+z && r.Value() == "10.0.0.4" })
	}) {
		t.Fatalf("the zone never reached the secondary whole: there it is %+v", held(secondary, z))
	}
	// each node is one of the zone's name servers
	records, err := secondary.ZoneRecords(t.Context(), z)
	if err != nil {
		t.Fatal(err)
	}
	var nameServers []string
	for i := range records.Records {
		if records.Records[i].Type == "NS" {
			nameServers = append(nameServers, records.Records[i].Target())
		}
	}
	slices.Sort(nameServers)
	if !slices.Equal(nameServers, []string{world.Domain(world.First), world.Domain(world.Second)}) {
		t.Errorf("the zone's name servers = %v, want both nodes", nameServers)
	}

	// the copy takes no changes: they are made on the primary
	_, err = secondary.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "b." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.0.0.5"}})
	if apiErr, ok := errors.AsType[*technitium.APIError](err); !ok || !strings.Contains(apiErr.Message, "Secondary zone") {
		t.Errorf("a record added to the secondary's copy = %v, want the server's refusal", err)
	}

	// deleted on the primary, it goes from the other node too
	if err := primary.DeleteZone(t.Context(), z); err != nil {
		t.Fatal(err)
	}
	if !acctest.EventuallyWithin(2*time.Minute, func() bool { return held(secondary, z) == nil }) {
		t.Errorf("the zone was deleted on the primary and the secondary still holds it: %+v", held(secondary, z))
	}
	// the clean-up deletes it again: put one back for it to find
	if _, err := primary.CreateZone(t.Context(), technitium.NewZone{Name: z, Type: technitium.ZonePrimary}); err != nil {
		t.Fatal(err)
	}
}

// Every method the client offers is called by a test in this suite: the unit
// tests prove a call is the one the document describes, and only a call made
// here proves it is one a server takes.
func TestEveryMethodHasALiveTest(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	sdk, err := filepath.Glob("../../sdk/technitium/*.go")
	if err != nil || len(sdk) == 0 {
		t.Fatalf("the client's source was not found: %v", err)
	}
	var methods []string
	for _, file := range sdk {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, parseErr := parser.ParseFile(fset, file, nil, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() || len(fn.Recv.List) != 1 {
				continue
			}
			if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
				if recv, ok := star.X.(*ast.Ident); ok && recv.Name == "Client" {
					methods = append(methods, fn.Name.Name)
				}
			}
		}
	}
	if len(methods) == 0 {
		t.Fatal("the client has no methods: has its type been renamed?")
	}

	// the suites' shared setup is part of what a run calls: it is where a
	// cluster is made
	tests, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	setup, err := filepath.Glob("../../lib/testenv/*.go")
	if err != nil || len(setup) == 0 {
		t.Fatalf("the suites' shared setup was not found: %v", err)
	}
	var source strings.Builder
	for _, file := range append(tests, setup...) {
		raw, err := os.ReadFile(file) //nolint:gosec // G304: this suite's own files, found by the patterns above
		if err != nil {
			t.Fatal(err)
		}
		source.Write(raw)
	}
	for _, m := range methods {
		if !strings.Contains(source.String(), "."+m+"(") {
			t.Errorf("Client.%s is called by no test in this suite, nor by its setup", m)
		}
	}
}
