package technitium_test

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// An update sends which record it is, by its data as it is, and everything
// it is to be afterwards: the server resets a TTL, a comment or a disabled
// state an update leaves out, so none is ever left out.
func TestUpdateRecord(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/records/update", `{"zone":{"name":"example.com"},"updatedRecord":{"name":"b.example.com","type":"A","ttl":300,"disabled":true,"comments":"the emby vm","rData":{"ipAddress":"10.0.0.7"},"expiryTtl":0}}`)
	c := client(t, fake)

	current := &technitium.Record{Name: "a.example.com", Type: "A", TTL: 300, Comments: "the emby vm", Data: technitium.RData{"ipAddress": "10.0.0.4"}}
	want := technitium.UpdateOf(current)
	want.Data["ipAddress"], want.Name, want.Disabled = "10.0.0.7", "b.example.com", true
	if current.Data["ipAddress"] != "10.0.0.4" {
		t.Fatal("changing what UpdateOf returned changed the record it was made from")
	}

	updated, err := c.UpdateRecord(t.Context(), "example.com", current, want)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "b.example.com" || updated.Value() != "10.0.0.7" || !updated.Disabled || updated.Comments != "the emby vm" {
		t.Errorf("UpdateRecord = %+v, want the record as the server now holds it", updated)
	}
	asked := fake.Last("zones/records/update")
	for param, value := range map[string]string{"zone": "example.com", "domain": "a.example.com", "newDomain": "b.example.com", "type": "A", "ipAddress": "10.0.0.4", "newIpAddress": "10.0.0.7", "ttl": "300", "disable": "true", "comments": "the emby vm", "expiryTtl": "0"} {
		if asked.Params.Get(param) != value {
			t.Errorf("the record was updated with %s=%q, want %q (%v)", param, asked.Params.Get(param), value, asked.Params)
		}
	}
	if asked.Method != http.MethodPost {
		t.Errorf("the record was updated with a %s", asked.Method)
	}

	// a record changed in nothing but its TTL still says what it keeps, and
	// is not renamed to the name it has
	same := technitium.UpdateOf(current)
	same.TTL = 600
	if _, err := c.UpdateRecord(t.Context(), "", current, same); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/records/update"); asked.Params.Has("newDomain") || asked.Params.Has("zone") || asked.Params.Get("ttl") != "600" || asked.Params.Get("comments") != "the emby vm" || asked.Params.Get("disable") != "false" || asked.Params.Get("newIpAddress") != "10.0.0.4" {
		t.Errorf("a TTL alone was changed with %v", asked.Params)
	}

	// each type's new data goes in the parameters the API names for it
	for name, tc := range map[string]struct {
		current, want technitium.RData
		params        map[string]string
	}{
		"MX":    {technitium.RData{"preference": 10, "exchange": "old.example.com"}, technitium.RData{"preference": 20, "exchange": "new.example.com"}, map[string]string{"preference": "10", "exchange": "old.example.com", "newPreference": "20", "newExchange": "new.example.com"}},
		"SRV":   {technitium.RData{"priority": 1, "weight": 2, "port": 80, "target": "a.example.com"}, technitium.RData{"priority": 3, "weight": 4, "port": 443, "target": "b.example.com"}, map[string]string{"newPriority": "3", "newWeight": "4", "newPort": "443", "newTarget": "b.example.com", "target": "a.example.com"}},
		"TXT":   {technitium.RData{"text": "old"}, technitium.RData{"text": "new text"}, map[string]string{"text": "old", "newText": "new text"}},
		"NS":    {technitium.RData{"nameServer": "ns1"}, technitium.RData{"nameServer": "ns2"}, map[string]string{"nameServer": "ns1", "newNameServer": "ns2"}},
		"PTR":   {technitium.RData{"ptrName": "a.example.com"}, technitium.RData{"ptrName": "b.example.com"}, map[string]string{"ptrName": "a.example.com", "newPtrName": "b.example.com"}},
		"ANAME": {technitium.RData{"aname": "a.example.com"}, technitium.RData{"aname": "b.example.com"}, map[string]string{"aname": "a.example.com", "newAName": "b.example.com"}},
		"CAA":   {technitium.RData{"flags": 0, "tag": "issue", "value": "a.org"}, technitium.RData{"flags": 0, "tag": "issue", "value": "b.org"}, map[string]string{"value": "a.org", "newValue": "b.org", "newTag": "issue", "newFlags": "0"}},
		// a name's one CNAME, or DNAME, is named by nothing but the name
		"CNAME": {technitium.RData{"cname": "a.example.com"}, technitium.RData{"cname": "b.example.com"}, map[string]string{"cname": "b.example.com"}},
		"DNAME": {technitium.RData{"dname": "a.example.com"}, technitium.RData{"dname": "b.example.com"}, map[string]string{"dname": "b.example.com"}},
	} {
		rec := &technitium.Record{Name: "x.example.com", Type: name, TTL: 60, Data: tc.current}
		change := technitium.UpdateOf(rec)
		change.Data = tc.want
		if _, err := c.UpdateRecord(t.Context(), "", rec, change); err != nil {
			t.Errorf("%s: %v", name, err)

			continue
		}
		asked := fake.Last("zones/records/update")
		for param, value := range tc.params {
			if asked.Params.Get(param) != value {
				t.Errorf("%s was updated with %s=%q, want %q (%v)", name, param, asked.Params.Get(param), value, asked.Params)
			}
		}
	}

	// what cannot be sent whole is not sent
	sent := len(fake.Requests("zones/records/update"))
	for name, tc := range map[string]struct {
		current *technitium.Record
		want    technitium.RData
	}{
		"no name":                {&technitium.Record{Type: "A", Data: technitium.RData{"ipAddress": "10.0.0.4"}}, technitium.RData{"ipAddress": "10.0.0.7"}},
		"which record is unsaid": {&technitium.Record{Name: "a.example.com", Type: "A"}, technitium.RData{"ipAddress": "10.0.0.7"}},
		"no new data":            {&technitium.Record{Name: "a.example.com", Type: "A", Data: technitium.RData{"ipAddress": "10.0.0.4"}}, technitium.RData{}},
		"a type it cannot write": {&technitium.Record{Name: "a.example.com", Type: "SSHFP", Data: technitium.RData{"fingerprint": "AB"}}, technitium.RData{"fingerprint": "CD"}},
	} {
		if _, err := c.UpdateRecord(t.Context(), "", tc.current, technitium.RecordUpdate{Data: tc.want}); err == nil {
			t.Errorf("%s: the update was sent", name)
		}
	}
	if now := len(fake.Requests("zones/records/update")); now != sent {
		t.Errorf("%d refused updates reached the server", now-sent)
	}
}

// A record is added with its PTR, and with a time after which the server
// deletes it, when asked.
func TestAddRecordWithItsPTR(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/records/add", `{"addedRecord":{"name":"a.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.4"},"expiryTtl":86400}}`)

	added, err := client(t, fake).AddRecord(t.Context(), technitium.NewRecord{Name: "a.example.com", Type: "A", PTR: true, ExpiryTTL: 86400, Data: technitium.RData{"ipAddress": "10.0.0.4"}})
	if err != nil || added.ExpiryTTL != 86400 {
		t.Fatalf("AddRecord = %+v, %v", added, err)
	}
	if asked := fake.Last("zones/records/add"); asked.Params.Get("ptr") != "true" || asked.Params.Get("expiryTtl") != "86400" {
		t.Errorf("the record was added with %v", asked.Params)
	}
}

// A value on one line reads back into the data it was written from.
func TestParseValue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		recordType, value string
		want              map[string]string
	}{
		{"A", " 10.0.0.4 ", map[string]string{"ipAddress": "10.0.0.4"}},
		{"AAAA", "fd00::4", map[string]string{"ipAddress": "fd00::4"}},
		{"CNAME", "emby.example.com", map[string]string{"cname": "emby.example.com"}},
		{"MX", "10 mail.example.com", map[string]string{"preference": "10", "exchange": "mail.example.com"}},
		{"SRV", "1 2 5060 a.example.com", map[string]string{"priority": "1", "weight": "2", "port": "5060", "target": "a.example.com"}},
		{"TXT", "v=spf1 include:example.com -all", map[string]string{"text": "v=spf1 include:example.com -all"}},
		{"CAA", "0 issue letsencrypt.org; validationmethods=dns-01", map[string]string{"flags": "0", "tag": "issue", "value": "letsencrypt.org; validationmethods=dns-01"}},
		{"PTR", "emby.example.com", map[string]string{"ptrName": "emby.example.com"}},
		{"NS", "ns1.example.com", map[string]string{"nameServer": "ns1.example.com"}},
	} {
		got, err := technitium.ParseValue(tc.recordType, tc.value)
		if err != nil {
			t.Errorf("%s %q: %v", tc.recordType, tc.value, err)

			continue
		}
		text := map[string]string{}
		for field, v := range got {
			text[field] = fmt.Sprint(v)
		}
		if !maps.Equal(text, tc.want) {
			t.Errorf("ParseValue(%s, %q) = %v, want %v", tc.recordType, tc.value, got, tc.want)
		}
		// and written again it is the value it was read from
		if again := (&technitium.Record{Type: tc.recordType, Data: got}).Value(); again != strings.TrimSpace(tc.value) {
			t.Errorf("%s %q written again = %q", tc.recordType, tc.value, again)
		}
	}

	for name, tc := range map[string]struct{ recordType, value, want string }{
		"no value":           {"A", " ", "none was given"},
		"too few":            {"MX", "mail.example.com", "is 1 of those"},
		"too many":           {"A", "10.0.0.4 10.0.0.5", "is 2 words"},
		"a type not written": {"SSHFP", "1 2 AB", "cannot write record type SSHFP"},
	} {
		if _, err := technitium.ParseValue(tc.recordType, tc.value); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ParseValue(%s, %q) = %v, want an error saying %q", name, tc.recordType, tc.value, err, tc.want)
		}
	}

	if types := technitium.WritableTypes(); !slices.IsSorted(types) || !slices.Contains(types, "A") || !slices.Contains(types, "CNAME") || slices.Contains(types, "SOA") {
		t.Errorf("WritableTypes = %v", types)
	}
}
