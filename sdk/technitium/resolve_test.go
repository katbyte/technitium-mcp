package technitium_test

import (
	"net/http"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// A 15.6 server's answers: a name followed through two CNAMEs in its own
// zone, and a name that is not there.
const (
	chainAnswer = `{"result":{"Metadata":{"NameServer":"ns1 (127.0.0.1)","Protocol":"Udp","DatagramSize":"89 bytes","RoundTripTime":"16.24 ms"},"AuthoritativeAnswer":true,"Truncation":false,"AuthenticData":false,"RCODE":"NoError","Answer":[
		{"Name":"jf.r.test","Type":"CNAME","Class":"IN","TTL":"3600 (1h)","RDATA":{"Domain":"m.r.test"}},
		{"Name":"m.r.test","Type":"CNAME","Class":"IN","TTL":"3600 (1h)","RDATA":{"Domain":"emby.r.test"}},
		{"Name":"emby.r.test","Type":"A","Class":"IN","TTL":"300 (5m)","RDATA":{"IPAddress":"10.0.0.4"}}
	],"Authority":[],"Additional":[{"Name":"","Type":"OPT","TTL":"0 (0 sec)","RDATA":{"Options":[]}}]},"rawResponses":[]}`
	missingAnswer = `{"result":{"Metadata":{"NameServer":"ns1 (127.0.0.1)","Protocol":"Udp","RoundTripTime":"1.1 ms"},"AuthoritativeAnswer":true,"RCODE":"NxDomain","Answer":[],"Authority":[
		{"Name":"r.test","Type":"SOA","TTL":"900 (15m)","RDATA":{"PrimaryNameServer":"ns1","ResponsiblePerson":"hostadmin@r.test","Serial":10,"Refresh":"900 (15m)","Retry":"300 (5m)","Expire":"604800 (1w)","Minimum":"900 (15m)"}}
	]}}`
)

func TestResolve(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("dnsClient/resolve", chainAnswer)
	c := client(t, fake)

	// left to its defaults, the server is asked itself, for an address
	got, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "jf.r.test"})
	if err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dnsClient/resolve"); asked.Method != http.MethodGet || asked.Params.Get("domain") != "jf.r.test" || asked.Params.Get("server") != "this-server" || asked.Params.Get("type") != "A" || asked.Params.Has("protocol") || asked.Params.Has("dnssec") {
		t.Errorf("the query was put with %s %v", asked.Method, asked.Params)
	}
	if got.RCode != "NoError" || !got.Authoritative || got.Truncated || got.Metadata.NameServer != "ns1 (127.0.0.1)" || got.Metadata.RoundTripTime != "16.24 ms" || len(got.Answer) != 3 || len(got.Additional) != 1 {
		t.Fatalf("Resolve = %+v", got)
	}
	want := []struct {
		name, recordType, value, target string
		ttl                             int
	}{
		{"jf.r.test", "CNAME", "m.r.test", "m.r.test", 3600},
		{"m.r.test", "CNAME", "emby.r.test", "emby.r.test", 3600},
		{"emby.r.test", "A", "10.0.0.4", "", 300},
	}
	for i, w := range want {
		rec := &got.Answer[i]
		if rec.Name != w.name || rec.Type != w.recordType || rec.Value() != w.value || rec.Target() != w.target || rec.TTL() != w.ttl {
			t.Errorf("answer %d = %s %s %q -> %q for %d, want %+v", i, rec.Name, rec.Type, rec.Value(), rec.Target(), rec.TTL(), w)
		}
	}
	if addr, ok := got.Answer[2].Address(); !ok || addr.String() != "10.0.0.4" {
		t.Errorf("the address at the end = %v, %v", addr, ok)
	}
	if _, ok := got.Answer[0].Address(); ok {
		t.Error("a CNAME has an address")
	}

	// everything that can be asked for
	if _, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "r.test", Type: "MX", Via: "1.1.1.1", Protocol: "Tcp", DNSSEC: true}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dnsClient/resolve"); asked.Params.Get("server") != "1.1.1.1" || asked.Params.Get("type") != "MX" || asked.Params.Get("protocol") != "Tcp" || asked.Params.Get("dnssec") != "true" {
		t.Errorf("a full query was put with %v", asked.Params)
	}

	// a name that is not there is an answer, not an error
	fake.Answer("dnsClient/resolve", missingAnswer)
	missing, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "nope.r.test", Via: technitium.ResolveRecursively})
	if err != nil || missing.RCode != "NxDomain" || len(missing.Answer) != 0 || len(missing.Authority) != 1 {
		t.Fatalf("a name that is not there = %+v, %v", missing, err)
	}
	// an SOA's times are written with their length in words, which its value leaves out
	if soa := &missing.Authority[0]; soa.Value() != "ns1 hostadmin@r.test 10 900 300 604800 900" || soa.TTL() != 900 {
		t.Errorf("the SOA = %q for %d", soa.Value(), soa.TTL())
	}

	if _, err := c.Resolve(t.Context(), technitium.ResolveQuery{}); err == nil {
		t.Error("a query for no name was put")
	}
}

// Each type's data is laid out as a DNS message carries it.
func TestResolvedRecordValues(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		rec           technitium.ResolvedRecord
		value, target string
	}{
		{technitium.ResolvedRecord{Type: "MX", Data: technitium.RData{"Preference": float64(10), "Exchange": "mail.r.test"}}, "10 mail.r.test", "mail.r.test"},
		{technitium.ResolvedRecord{Type: "TXT", Data: technitium.RData{"Text": "v=spf1 -all", "CharacterStrings": []any{"v=spf1 -all"}}}, "v=spf1 -all", ""},
		{technitium.ResolvedRecord{Type: "SRV", Data: technitium.RData{"Priority": float64(1), "Weight": float64(2), "Port": float64(5060), "Target": "emby.r.test"}}, "1 2 5060 emby.r.test", "emby.r.test"},
		{technitium.ResolvedRecord{Type: "AAAA", Data: technitium.RData{"IPAddress": "fd00::4"}}, "fd00::4", ""},
		{technitium.ResolvedRecord{Type: "PTR", Data: technitium.RData{"Domain": "emby.r.test"}}, "emby.r.test", "emby.r.test"},
		{technitium.ResolvedRecord{Type: "NS", Data: technitium.RData{"NameServer": "ns1"}}, "ns1", "ns1"},
		{technitium.ResolvedRecord{Type: "CAA", Data: technitium.RData{"Flags": float64(0), "Tag": "issue", "Value": "letsencrypt.org"}}, "0 issue letsencrypt.org", ""},
		{technitium.ResolvedRecord{Type: "TLSA", Data: technitium.RData{"Selector": "Cert", "Usage": "DANE-EE"}}, "Selector=Cert Usage=DANE-EE", ""},
	} {
		if got := tc.rec.Value(); got != tc.value || tc.rec.Target() != tc.target {
			t.Errorf("%s = %q -> %q, want %q -> %q", tc.rec.Type, got, tc.rec.Target(), tc.value, tc.target)
		}
	}
	if (&technitium.ResolvedRecord{TTLText: "0 (0 sec)"}).TTL() != 0 || (&technitium.ResolvedRecord{TTLText: ""}).TTL() != 0 || (&technitium.ResolvedRecord{TTLText: "86400 (1 day)"}).TTL() != 86400 {
		t.Error("a TTL is not read from its text")
	}
}
