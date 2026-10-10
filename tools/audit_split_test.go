package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

// told is what a name server answers for a name: addresses, or that there is
// no such name.
func told(addresses ...string) string {
	if len(addresses) == 0 {
		return `{"result":{"RCODE":"NxDomain","Answer":[]}}`
	}
	records := make([]string, 0, len(addresses))
	for _, address := range addresses {
		records = append(records, `{"Name":"x","Type":"A","TTL":"300 (5m)","RDATA":{"IPAddress":"`+address+`"}}`)
	}

	return `{"result":{"RCODE":"NoError","Answer":[` + strings.Join(records, ",") + `]}}`
}

// splitPair is one zone the outside knows too, one it does not, and a
// second server with nothing: dock answers for the outside as it is asked.
func splitPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"lan.home","type":"Primary","soaSerial":2}]}`)
	p.rpi.Answer("zones/list", `{"zones":[]}`)
	zoneOf(p, false, "example.com", addr("a.example.com", "10.0.0.4"), addr("b.example.com", "10.0.0.5"), addr("leak.example.com", "10.0.0.6"), cname("c.example.com", "a.example.com"), addr("*.wild.example.com", "10.0.0.8"), cname("dangling.example.com", "nothing.example.com"))
	zoneOf(p, false, "lan.home", addr("nas.lan.home", "10.0.0.9"))

	// the outside: a public address for one name, none for another, and for one the inside's own
	p.dock.Answer("dnsClient/resolve", told())
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "a.example.com", told("203.0.113.9"))
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "c.example.com", told("203.0.113.9"))
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "leak.example.com", told("10.0.0.6"))
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "ext.example.com", told("203.0.113.7"))
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "priv.example.com", told("192.168.4.4"))
	// the other domain, as dock answers a client: one name alike, one elsewhere, the rest nowhere
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "a.example.org", told("10.0.0.4"))
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "b.example.org", told("10.9.9.9"))

	return p
}

// audit_split asks the outside for every name the zones hold an address for
// and finds where inside and outside do not fit: not where they differ,
// which is what a split horizon is.
func TestAuditSplit(t *testing.T) {
	t.Parallel()

	p := splitPair(t)
	suite := p.session(t, Options{})

	out := suite.Call(t, "audit_split", map[string]any{"resolvers": []string{" 1.1.1.1 ", ""}, "names": []string{"ext.example.com", "priv.example.com", "a.example.com", "nowhere.example.com"}, "mirror": []string{"example.com=example.org"}})
	found := acctest.Rows(t, out["findings"], "findings")
	want(t, found, "public_gone", "b.example.com", "b.example.com ends at 10.0.0.5 here and the outside has no address for it (NxDomain), though it has for other names of example.com", "dock")
	want(t, found, "private_outside", "leak.example.com", "the outside is told leak.example.com is at 10.0.0.6, a private address", "dock")
	want(t, found, "no_override", "ext.example.com", "ext.example.com resolves outside to 203.0.113.7 and no zone here has a record for it")
	want(t, found, "private_outside", "priv.example.com", "the outside is told priv.example.com is at 192.168.4.4")
	want(t, found, "mirror_differs", "b.example.com", "b.example.com ends at 10.0.0.5, and b.example.org, which is meant to answer alike, ends at 10.9.9.9 when dock is asked", "dock")
	want(t, found, "mirror_differs", "leak.example.com", "leak.example.org, which is meant to answer alike, ends nowhere when dock is asked (NxDomain)", "dock")
	// answered differently inside and out is the split working; a name that mirrors alike is alike; a CNAME is its target's to mirror
	none(t, found, "public_gone", "a.example.com")
	none(t, found, "public_gone", "c.example.com")
	none(t, found, "mirror_differs", "a.example.com")
	none(t, found, "mirror_differs", "c.example.com")
	// a zone the outside has no name of is kept for the inside, and nothing in it is missing from anywhere
	none(t, found, "public_gone", "nas.lan.home")
	if !slices.Equal(acctest.Strs(t, out["internal"], "internal"), []string{"lan.home"}) {
		t.Errorf("the zones kept for the inside = %v", out["internal"])
	}
	counts := acctest.Object(t, out["counts"], "counts")
	if len(found) != 6 || acctest.Num(t, out["total"], "total") != 6 || acctest.NumOr0(counts["mirror_differs"]) != 2 || acctest.NumOr0(counts["private_outside"]) != 2 || !slices.Equal(acctest.Strs(t, out["asked"], "asked"), []string{"dock", "rpi"}) || out["note"] != nil {
		t.Errorf("found %d: %v (%v), note %v", len(found), found, counts, out["note"])
	}
	// the five names with an address, a wildcard and a CNAME to nothing not among them, and the three given that the zones do not hold
	if acctest.Num(t, out["outside"], "outside") != 8 {
		t.Errorf("%v names were asked of the outside, want 8", out["outside"])
	}
	for _, req := range p.dock.Requests("dnsClient/resolve") {
		if via := req.Params.Get("server"); via != "1.1.1.1" && (via != "this-server" || !strings.HasSuffix(req.Params.Get("domain"), ".example.org")) {
			t.Errorf("%s was asked of %s", req.Params.Get("domain"), via)
		}
	}
	if len(p.rpi.Requests("dnsClient/resolve")) != 0 {
		t.Error("the outside was asked through both servers, where one is enough")
	}

	// one zone, a few at a time
	one := suite.Call(t, "audit_split", map[string]any{"resolvers": []string{"1.1.1.1"}, "zone": "lan.home"})
	if acctest.Num(t, one["total"], "total") != 0 || acctest.Num(t, one["outside"], "outside") != 1 {
		t.Errorf("one zone = %v", one)
	}
	paged := suite.Call(t, "audit_split", map[string]any{"resolvers": []string{"1.1.1.1"}, "limit": 1})
	if len(acctest.Rows(t, paged["findings"], "findings")) != 1 || !strings.Contains(acctest.Str(paged["note"]), "2 things were found and 1 are given") {
		t.Errorf("paged = %v", paged)
	}

	// an outside that cannot be asked is said, and nothing is found for what it was not asked
	p.dock.FailWhen("dnsClient/resolve", "domain", "b.example.com", "error", "request timed out")
	if said := acctest.Str(suite.Call(t, "audit_split", map[string]any{"resolvers": []string{"1.1.1.1"}, "zone": "example.com"})["note"]); !strings.Contains(said, "1 names could not be asked of the outside, and nothing is found for them: dnsClient/resolve: request timed out") {
		t.Errorf("with a name that could not be asked = %q", said)
	}

	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"no resolver":        {map[string]any{"resolvers": []string{" "}}, "which resolvers: give the address of a name server that stands for the outside world"},
		"a resolver by name": {map[string]any{"resolvers": []string{"one.one.one.one"}}, "is not an address"},
		"half a mirror":      {map[string]any{"resolvers": []string{"1.1.1.1"}, "mirror": []string{"example.com"}}, "is not a zone and another domain with = between"},
	} {
		if msg := suite.CallErr(t, "audit_split", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
}

// The checks that go by what is usual in a zone: a TTL far from the rest's,
// one host's names made two ways, and an address of the other kind.
func TestAuditHeuristics(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"usual.example","type":"Primary","soaSerial":3},{"name":"small.example","type":"Primary","soaSerial":1}]}`)
	p.rpi.Answer("zones/list", `{"zones":[]}`)
	ttl := func(record string, seconds string) string {
		return strings.Replace(record, `"ttl":3600`, `"ttl":`+seconds, 1)
	}
	zoneOf(p, false, "usual.example",
		rec("usual.example", "SOA", `{"primaryNameServer":"dock"}`),
		addr("dock.usual.example", "10.0.0.2"), addr("web.dock.usual.example", "10.0.0.2"), addr("jf.dock.usual.example", "10.0.0.2"),
		addr("emby-dock.usual.example", "10.0.0.2"), addr("dock-backup.usual.example", "10.0.0.3"), addr("my-pc.usual.example", "10.0.0.7"),
		ttl(addr("lowered.usual.example", "10.0.0.8"), "300"), ttl(addr("raised.usual.example", "10.0.0.9"), "86400"), ttl(addr("near.usual.example", "10.0.0.10"), "7200"),
		ttl(addr("fast.usual.example", "10.0.0.11"), "30"), ttl(rec("usual.example", "TXT", `{"text":"x"}`), "60"),
		addr("wan.usual.example", "203.0.113.9"),
	)
	// too few records to have a usual anything
	zoneOf(p, false, "small.example", addr("a.small.example", "10.0.0.2"), ttl(addr("b.small.example", "203.0.113.9"), "60"), addr("x-a.small.example", "10.0.0.3"))
	suite := p.session(t, Options{})

	naming := auditFindings(t, suite, "audit_naming", map[string]any{"server": "dock", "problems": []string{"ttl_outlier", "named_two_ways"}})
	want(t, naming, "ttl_outlier", "lowered.usual.example", "the A at lowered.usual.example has a TTL of 300 seconds, where 7 of the zone's 11 such records have 3600")
	want(t, naming, "ttl_outlier", "raised.usual.example", "has a TTL of 86400 seconds")
	// twice the usual is not far from it; under a minute is said for itself; and a TXT keeps its own time
	none(t, naming, "ttl_outlier", "near.usual.example")
	none(t, naming, "ttl_outlier", "fast.usual.example")
	none(t, naming, "ttl_outlier", "usual.example")
	want(t, naming, "named_two_ways", "emby-dock.usual.example", "emby-dock.usual.example is written with a hyphen, and dock.usual.example has names written under it with a dot, as jf.dock.usual.example")
	want(t, naming, "named_two_ways", "dock-backup.usual.example", "dock.usual.example has names written under it with a dot")
	// a hyphen in a name that is no host's with names under it is a name
	none(t, naming, "named_two_ways", "my-pc.usual.example")
	if len(naming) != 4 {
		t.Errorf("audit_naming found %v, want the four", naming)
	}

	overlaps := auditFindings(t, suite, "audit_overlaps", map[string]any{"server": "dock", "problems": []string{"address_out_of_place"}})
	want(t, overlaps, "address_out_of_place", "wan.usual.example", "wan.usual.example holds 203.0.113.9, a public address, in a zone whose 10 other addresses are private")
	if len(overlaps) != 1 {
		t.Errorf("audit_overlaps found %v, want the one public address among private ones", overlaps)
	}
}
