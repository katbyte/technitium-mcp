package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

const (
	// a name followed through a CNAME in the server's own zone
	ownChain = `{"result":{"Metadata":{"NameServer":"dock (127.0.0.1)","Protocol":"Udp","RoundTripTime":"1.2 ms"},"AuthoritativeAnswer":true,"AuthenticData":false,"RCODE":"NoError","Answer":[
		{"Name":"m.example.com","Type":"CNAME","TTL":"3600 (1h)","RDATA":{"Domain":"emby.van.example.com"}},
		{"Name":"emby.van.example.com","Type":"A","TTL":"300 (5m)","RDATA":{"IPAddress":"10.0.0.4"}},
		{"Name":"emby.van.example.com","Type":"A","TTL":"300 (5m)","RDATA":{"IPAddress":"10.0.0.14"}}
	],"Authority":[],"Additional":[]}}`
	// what a public resolver is told for the same name
	publicAnswer = `{"result":{"Metadata":{"NameServer":"1.1.1.1","Protocol":"Udp","RoundTripTime":"21 ms"},"AuthoritativeAnswer":false,"AuthenticData":true,"RCODE":"NoError","Answer":[
		{"Name":"m.example.com","Type":"A","TTL":"60 (1m)","RDATA":{"IPAddress":"203.0.113.9"}},
		{"Name":"m.example.com","Type":"RRSIG","TTL":"60 (1m)","RDATA":{"TypeCovered":"A"}}
	]}}`
	noSuchName = `{"result":{"Metadata":{"NameServer":"rpi (127.0.0.1)","Protocol":"Udp","RoundTripTime":"0.9 ms"},"AuthoritativeAnswer":true,"RCODE":"NxDomain","Answer":[],"Authority":[{"Name":"example.com","Type":"SOA","TTL":"900 (15m)","RDATA":{"PrimaryNameServer":"rpi"}}]}}`
)

// dns_resolve asks each server what it would answer a client, side by side,
// and says when they do not agree; a resolver named beside them is asked the
// same from each server.
func TestDNSResolve(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("dnsClient/resolve", ownChain)
	p.dock.AnswerWhen("dnsClient/resolve", "server", "1.1.1.1", publicAnswer)
	p.rpi.Answer("dnsClient/resolve", noSuchName)
	p.rpi.FailWhen("dnsClient/resolve", "server", "1.1.1.1", "error", "DnsClient failed to resolve the request 'm.example.com. A IN': request timed out for name server [1.1.1.1].")
	suite := p.session(t, Options{})

	out := suite.Call(t, "dns_resolve", map[string]any{"name": "m.example.com.", "resolvers": []string{"1.1.1.1", " 1.1.1.1 ", ""}})
	if out["name"] != "m.example.com" || out["type"] != "A" || !acctest.BoolOf(out["differ"]) || out["note"] != nil {
		t.Errorf("the answer = %v", out)
	}
	rows := acctest.Rows(t, out["answers"], "answers")
	if len(rows) != 4 {
		t.Fatalf("answers = %v, want each server's own and then each's from the resolver, asked once", rows)
	}

	dock := rows[0]
	if dock["server"] != "dock" || dock["asked"] != "itself" || dock["result"] != "NoError" || !slices.Equal(acctest.Strs(t, dock["answers"], "answers"), []string{"10.0.0.14", "10.0.0.4"}) || acctest.Num(t, dock["ttl"], "ttl") != 300 || !acctest.BoolOf(dock["own_zone"]) || dock["validated"] != nil || dock["answered_by"] != "dock (127.0.0.1)" || dock["took"] != "1.2 ms" {
		t.Errorf("dock's own answer = %v", dock)
	}
	if got := acctest.Strs(t, dock["chain"], "chain"); !slices.Equal(got, []string{"m.example.com CNAME emby.van.example.com", "emby.van.example.com A 10.0.0.4", "emby.van.example.com A 10.0.0.14"}) {
		t.Errorf("dock's chain = %v", got)
	}
	if asked := p.dock.Requests("dnsClient/resolve")[0]; asked.Params.Get("server") != "this-server" || asked.Params.Get("domain") != "m.example.com" || asked.Params.Get("type") != "A" {
		t.Errorf("dock was asked with %v", asked.Params)
	}

	if rpi := rows[1]; rpi["server"] != "rpi" || rpi["result"] != "NxDomain" || rpi["answers"] != nil || rpi["chain"] != nil || rpi["ttl"] != nil || !acctest.BoolOf(rpi["own_zone"]) {
		t.Errorf("rpi's own answer = %v", rpi)
	}

	// what the outside is told: no chain for a name that is no CNAME there,
	// the signature beside the answer left out, and that it was validated
	public := rows[2]
	if public["server"] != "dock" || public["asked"] != "1.1.1.1" || !slices.Equal(acctest.Strs(t, public["answers"], "answers"), []string{"203.0.113.9"}) || public["chain"] != nil || public["own_zone"] != nil || !acctest.BoolOf(public["validated"]) || acctest.Num(t, public["ttl"], "ttl") != 60 {
		t.Errorf("what 1.1.1.1 told dock = %v", public)
	}
	if unreached := rows[3]; unreached["server"] != "rpi" || unreached["asked"] != "1.1.1.1" || !strings.Contains(acctest.Str(unreached["error"]), "request timed out for name server") || unreached["result"] != nil {
		t.Errorf("rpi, which could not reach 1.1.1.1 = %v", unreached)
	}

	// the server's own recursion, and validation, by their names
	suite.Call(t, "dns_resolve", map[string]any{"name": "m.example.com", "type": "aaaa", "resolvers": []string{"recursive"}, "dnssec": true, "server": "dock"})
	if asked := p.dock.Last("dnsClient/resolve"); asked.Params.Get("server") != "recursive-resolver" || asked.Params.Get("type") != "AAAA" || asked.Params.Get("dnssec") != "true" {
		t.Errorf("recursion was asked for with %v", asked.Params)
	}

	// servers that say the same do not differ, whatever order their answers come in
	p.rpi.Answer("dnsClient/resolve", strings.Replace(strings.Replace(ownChain, "10.0.0.4", "10.0.0.24", 1), "10.0.0.14", "10.0.0.4", 1))
	p.rpi.Answer("dnsClient/resolve", strings.Replace(strings.Replace(strings.Replace(ownChain, "10.0.0.4", "10.0.0.24", 1), "10.0.0.14", "10.0.0.4", 1), "10.0.0.24", "10.0.0.14", 1))
	if same := suite.Call(t, "dns_resolve", map[string]any{"name": "m.example.com"}); same["differ"] != nil {
		t.Errorf("two servers answering alike differ: %v", same)
	}

	// a CNAME asked for is the answer, not a step on the way to one
	asCNAME := acctest.Rows(t, suite.Call(t, "dns_resolve", map[string]any{"name": "m.example.com", "type": "CNAME", "server": "dock"})["answers"], "answers")[0]
	if got := acctest.Strs(t, asCNAME["answers"], "answers"); !slices.Contains(got, "emby.van.example.com") || asCNAME["chain"] != nil {
		t.Errorf("the CNAME asked for = %v", asCNAME)
	}
}

// An address is resolved to its name, at the name its PTR is at; a server
// that cannot answer for itself is said, and takes nothing from the other.
func TestDNSResolveAnAddressAndAFailure(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("dnsClient/resolve", `{"result":{"Metadata":{"NameServer":"dock (127.0.0.1)"},"AuthoritativeAnswer":true,"RCODE":"NoError","Answer":[{"Name":"4.0.0.10.in-addr.arpa","Type":"PTR","TTL":"3600 (1h)","RDATA":{"Domain":"emby.van.example.com"}}]}}`)
	p.rpi.Fail("dnsClient/resolve", "error", "Access was denied.")
	suite := p.session(t, Options{})

	out := suite.Call(t, "dns_resolve", map[string]any{"name": "10.0.0.4"})
	if out["name"] != "4.0.0.10.in-addr.arpa" || out["type"] != "PTR" || out["differ"] != nil || !strings.Contains(acctest.Str(out["note"]), "a server could not answer for itself") {
		t.Errorf("the answer = %v", out)
	}
	rows := acctest.Rows(t, out["answers"], "answers")
	if !slices.Equal(acctest.Strs(t, rows[0]["answers"], "answers"), []string{"emby.van.example.com"}) || !strings.Contains(acctest.Str(rows[1]["error"]), "Access was denied") {
		t.Errorf("answers = %v", rows)
	}
	if asked := p.dock.Last("dnsClient/resolve"); asked.Params.Get("domain") != "4.0.0.10.in-addr.arpa" || asked.Params.Get("type") != "PTR" {
		t.Errorf("the address was asked for with %v", asked.Params)
	}

	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"no name":                {map[string]any{"name": " "}, "which name"},
		"an address with a type": {map[string]any{"name": "10.0.0.4", "type": "A"}, "is an address, which has a PTR record at 4.0.0.10.in-addr.arpa and no A"},
		"a server that is not":   {map[string]any{"name": "m.example.com", "server": "pi"}, "dock, rpi"},
	} {
		if msg := suite.CallErr(t, "dns_resolve", tc.args); !strings.Contains(msg, tc.want) {
			t.Errorf("%s = %q, want it to say %q", name, msg, tc.want)
		}
	}
}

// A name a server blocks is said to be, and by what; and one server blocking
// what another resolves is the servers not agreeing, though both say the name
// does not exist.
func TestDNSResolveSaysWhatIsBlocked(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("dnsClient/resolve", answerOf("source=blocked-zone; domain=ads.example.net", ""))
	p.rpi.Answer("dnsClient/resolve", answerOf("", ""))
	suite := p.session(t, Options{})

	out := suite.Call(t, "dns_resolve", map[string]any{"name": "x.ads.example.net"})
	rows := acctest.Rows(t, out["answers"], "answers")
	if len(rows) != 2 || rows[0]["blocked"] != "by its own list of blocked names: the entry ads.example.net" || rows[0]["result"] != "NxDomain" || rows[1]["blocked"] != nil || rows[1]["result"] != "NxDomain" || !acctest.BoolOf(out["differ"]) {
		t.Errorf("a name one server blocks = %v", out)
	}

	p.both("dnsClient/resolve", answerOf("source=block-list-zone; blockListUrl=https://lists.example.org/ads.txt; domain=example.net", ""))
	out = suite.Call(t, "dns_resolve", map[string]any{"name": "x.ads.example.net"})
	if rows = acctest.Rows(t, out["answers"], "answers"); rows[1]["blocked"] != "by the block list https://lists.example.org/ads.txt: the entry example.net" || out["differ"] != nil {
		t.Errorf("a name a block list blocks on both = %v", out)
	}
}
