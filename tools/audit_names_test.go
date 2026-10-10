package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

// namesPair is two servers for the names check: dock holds a zone with every
// kind of answer a name can get, and the zone under it; rpi holds the first
// zone with a few of its names, one of them pointing elsewhere.
func namesPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"van.example.com","type":"Primary","soaSerial":3}]}`)
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7}]}`)
	p.dock.AnswerWhen("zones/records/get", "zone", "example.com", `{"zone":{"name":"example.com"},"records":[
		{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"dock.van.example.com"}},
		{"name":"example.com","type":"RRSIG","ttl":900,"rData":{"typeCovered":"NS"}},
		{"name":"m.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"emby.van.example.com"}},
		{"name":"jf.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"M.example.com."}},
		{"name":"gone.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"nothing.van.example.com"}},
		{"name":"out.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"host.example.net"}},
		{"name":"a.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"b.example.com"}},
		{"name":"b.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"a.example.com"}},
		{"name":"off.example.com","type":"A","ttl":3600,"disabled":true,"rData":{"ipAddress":"10.0.0.9"}},
		{"name":"txt.example.com","type":"TXT","ttl":3600,"rData":{"text":"hello"}},
		{"name":"two.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.6"}},
		{"name":"two.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.5"}},
		{"name":"*.wild.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.8"}},
		{"name":"deep.under.wild.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.7"}},
		{"name":"sub.example.com","type":"NS","ttl":3600,"rData":{"nameServer":"ns.elsewhere.net"}},
		{"name":"nsec3hash.example.com","type":"NSEC3","ttl":900,"rData":{"types":["A"]}}
	]}`)
	p.dock.AnswerWhen("zones/records/get", "zone", "van.example.com", `{"zone":{"name":"van.example.com"},"records":[
		{"name":"emby.van.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.4"}},
		{"name":"emby.van.example.com","type":"AAAA","ttl":3600,"rData":{"ipAddress":"fd00::4"}},
		{"name":"dock.van.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.2"}}
	]}`)
	p.rpi.AnswerWhen("zones/records/get", "zone", "example.com", `{"zone":{"name":"example.com"},"records":[
		{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"dock.van.example.com"}},
		{"name":"m.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"emby.van.example.com"}},
		{"name":"two.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.5"}},
		{"name":"two.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.6"}}
	]}`)

	return p
}

// checked is the answer for one name asked of one server: its status, what
// answers, where it ends and what is wrong, as one line.
func checked(t *testing.T, suite *acctest.Suite, server, name string) string {
	t.Helper()

	row := acctest.Rows(t, suite.Call(t, "audit_names", map[string]any{"names": []string{name}, "server": server})["names"], "names")[0]
	line := acctest.Str(row["status"])
	if row["zone"] != nil {
		line += " in " + acctest.Str(row["zone"])
	}
	if row["wildcard"] != nil {
		line += " by " + acctest.Str(row["wildcard"])
	}
	if row["records"] != nil {
		line += " [" + strings.Join(acctest.Strs(t, row["records"], "records"), "; ") + "]"
	}
	if row["chain"] != nil {
		line += " > " + strings.Join(acctest.Strs(t, row["chain"], "chain"), " > ")
	}
	if row["ends_at"] != nil {
		line += " = " + strings.Join(acctest.Strs(t, row["ends_at"], "ends_at"), ", ")
	}
	if row["problem"] != nil {
		line += " ! " + acctest.Str(row["problem"])
	}

	return line
}

// A name is looked up in a server's own zones by the rules a name server
// answers by, and its CNAMEs followed through them to the addresses at the
// end.
func TestAuditNamesOnOneServer(t *testing.T) {
	t.Parallel()

	suite := namesPair(t).session(t, Options{})

	for name, want := range map[string]string{
		// what is at the name, in the closest zone holding it, case and a
		// trailing dot aside
		"Emby.van.example.com.": "exists in van.example.com [A 10.0.0.4; AAAA fd00::4] = 10.0.0.4, fd00::4",
		"two.example.com":       "exists in example.com [A 10.0.0.5; A 10.0.0.6] = 10.0.0.5, 10.0.0.6",
		"example.com":           "exists in example.com [NS dock.van.example.com]",
		"txt.example.com":       "exists in example.com [TXT hello]",
		// CNAMEs followed, from one zone into another
		"m.example.com": "exists in example.com [CNAME emby.van.example.com] > emby.van.example.com = 10.0.0.4, fd00::4",
		// the record is given as it is held, and followed whatever its case
		"jf.example.com": "exists in example.com [CNAME M.example.com.] > m.example.com > emby.van.example.com = 10.0.0.4, fd00::4",
		// and the ways one ends nowhere
		"gone.example.com": "exists in example.com [CNAME nothing.van.example.com] > nothing.van.example.com ! nothing.van.example.com has no record in van.example.com",
		"out.example.com":  "exists in example.com [CNAME host.example.net] > host.example.net ! host.example.net is in no zone here, so where it ends is not this server's to say",
		"a.example.com":    "exists in example.com [CNAME b.example.com] > b.example.com > a.example.com ! the chain loops back to a.example.com",
		// nothing at the name
		"nope.example.com":     "missing in example.com",
		"nope.van.example.com": "missing in van.example.com",
		"www.example.net":      "no_zone",
		"off.example.com":      "disabled in example.com [A 10.0.0.9 (disabled)]",
		// a record DNSSEC keeps at a name is no answer for the name
		"nsec3hash.example.com": "missing in example.com",
		// a wildcard answers for what is not there: at any depth under it,
		"x.wild.example.com":   "wildcard in example.com by *.wild.example.com [A 10.0.0.8] = 10.0.0.8",
		"y.x.wild.example.com": "wildcard in example.com by *.wild.example.com [A 10.0.0.8] = 10.0.0.8",
		// but not for a name that exists, with records or only with names under it,
		"deep.under.wild.example.com": "exists in example.com [A 10.0.0.7] = 10.0.0.7",
		"under.wild.example.com":      "missing in example.com",
		// nor under one: the closest name above that exists decides
		"z.under.wild.example.com": "missing in example.com",
		"wild.example.com":         "missing in example.com",
		// a part of the zone handed to other name servers answers for all under it
		"host.sub.example.com": "delegated in example.com ! it is under sub.example.com, which is delegated to other name servers",
		"sub.example.com":      "exists in example.com [NS ns.elsewhere.net]",
	} {
		if got := checked(t, suite, "dock", name); got != want {
			t.Errorf("%s\n  = %s\n  want %s", name, got, want)
		}
	}
}

// Asked of every server, a name they answer alike is one answer and a name
// they do not is differs with each server's; the names come back in the
// order given, counted by status, and can be held to what they should end at.
func TestAuditNames(t *testing.T) {
	t.Parallel()

	suite := namesPair(t).session(t, Options{})

	out := suite.Call(t, "audit_names", map[string]any{
		"names":  []string{"two.example.com", "jf.example.com", "M.example.com", "nope.example.com", "www.example.net", "two.example.com."},
		"expect": map[string]any{"two.example.com": "10.0.0.5", "m.example.com": "emby.van.example.com", "jf.example.com": "10.0.0.4", "nope.example.com": "10.0.0.1"},
	})
	rows := acctest.Rows(t, out["names"], "names")
	if len(rows) != 5 {
		t.Fatalf("names = %v, want the five asked about once each, in order", rows)
	}

	// held alike, whatever order each server lists the records in
	two := rows[0]
	if two["name"] != "two.example.com" || two["status"] != "exists" || two["per_server"] != nil || !slices.Equal(acctest.Strs(t, two["ends_at"], "ends_at"), []string{"10.0.0.5", "10.0.0.6"}) || two["expected"] != "10.0.0.5" || two["unmet"] != nil {
		t.Errorf("two = %v", two)
	}
	// on dock alone
	jf := rows[1]
	perServer := acctest.Rows(t, jf["per_server"], "per_server")
	if jf["status"] != "differs" || len(perServer) != 2 || perServer[0]["server"] != "dock" || perServer[0]["status"] != "exists" || perServer[1]["server"] != "rpi" || perServer[1]["status"] != "missing" || jf["zone"] != nil {
		t.Errorf("jf = %v", jf)
	}
	if jf["unmet"] != "rpi: it is missing" {
		t.Errorf("jf falls short as %q", jf["unmet"])
	}
	// on both, and rpi cannot follow it: it holds the zone the target's name
	// is in and not the zone under it that has the record, so there the
	// target is a name with nothing at it
	m := rows[2]
	perServer = acctest.Rows(t, m["per_server"], "per_server")
	if m["name"] != "m.example.com" || m["status"] != "differs" || perServer[1]["problem"] != "emby.van.example.com has no record in example.com" || len(acctest.Strs(t, perServer[0]["ends_at"], "ends_at")) != 2 {
		t.Errorf("m = %v", m)
	}
	// it does lead to the name expected, on both
	if m["unmet"] != nil {
		t.Errorf("m falls short as %q, and its CNAME names what was expected on both", m["unmet"])
	}
	if nope := rows[3]; nope["status"] != "missing" || nope["zone"] != "example.com" || nope["unmet"] != "it is missing" {
		t.Errorf("nope = %v", nope)
	}
	if elsewhere := rows[4]; elsewhere["status"] != "no_zone" || elsewhere["zone"] != nil || elsewhere["expected"] != nil {
		t.Errorf("a name in no zone = %v", elsewhere)
	}

	counts := acctest.Object(t, out["counts"], "counts")
	if acctest.NumOr0(counts["exists"]) != 1 || acctest.NumOr0(counts["differs"]) != 2 || acctest.NumOr0(counts["missing"]) != 1 || acctest.NumOr0(counts["no_zone"]) != 1 || acctest.Num(t, out["unmet"], "unmet") != 2 {
		t.Errorf("counts = %v with %v unmet", counts, out["unmet"])
	}

	// only the ones that need looking at, the counts still of all
	short := suite.Call(t, "audit_names", map[string]any{"names": []string{"two.example.com", "nope.example.com", "x.wild.example.com", "jf.example.com"}, "only": []string{"missing", "differs"}})
	got := make([]string, 0, 3)
	for _, row := range acctest.Rows(t, short["names"], "names") {
		got = append(got, acctest.Str(row["name"])+" "+acctest.Str(row["status"]))
	}
	if !slices.Equal(got, []string{"nope.example.com missing", "x.wild.example.com differs", "jf.example.com differs"}) || acctest.NumOr0(acctest.Object(t, short["counts"], "counts")["exists"]) != 1 {
		t.Errorf("only the missing and the differing = %v, counts %v", got, short["counts"])
	}

	// how a name falls short of an address, and of a name
	for name, tc := range map[string]struct{ expect, want string }{
		"two.example.com":  {"10.0.0.9", "it ends at 10.0.0.5, 10.0.0.6"},
		"txt.example.com":  {"10.0.0.9", "it ends at no address"},
		"m.example.com":    {"other.example.com", "it points at emby.van.example.com"},
		"gone.example.com": {"10.0.0.4", "it ends at no address"},
		"off.example.com":  {"10.0.0.9", "it is disabled"},
	} {
		row := acctest.Rows(t, suite.Call(t, "audit_names", map[string]any{"names": []string{name}, "expect": map[string]any{name: tc.expect}, "server": "dock"})["names"], "names")[0]
		if row["unmet"] != tc.want {
			t.Errorf("%s expected at %s falls short as %q, want %q", name, tc.expect, row["unmet"], tc.want)
		}
	}

	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"no names":             {map[string]any{"names": []string{" ", ""}}, "which names"},
		"an expectation alone": {map[string]any{"names": []string{"a.example.com"}, "expect": map[string]any{"b.example.com": "10.0.0.1"}}, "expect names b.example.com, which is not in names"},
		"a status that is not": {map[string]any{"names": []string{"a.example.com"}, "only": []string{"broken"}}, "only takes exists"},
	} {
		if msg := suite.CallErr(t, "audit_names", tc.args); !strings.Contains(msg, tc.want) {
			t.Errorf("%s = %q, want it to say %q", name, msg, tc.want)
		}
	}
}

// With a subtree, the names under it that have an address or a CNAME and
// were not asked about are listed: what nothing in the list uses.
func TestAuditNamesUnlisted(t *testing.T) {
	t.Parallel()

	suite := namesPair(t).session(t, Options{})

	out := suite.Call(t, "audit_names", map[string]any{"names": []string{"m.example.com", "jf.example.com", "emby.van.example.com"}, "subtree": "example.com"})
	got := make([]string, 0, 7)
	for _, row := range acctest.Rows(t, out["unlisted"], "unlisted") {
		line := acctest.Str(row["name"]) + " [" + strings.Join(acctest.Strs(t, row["records"], "records"), "; ") + "]"
		if row["only_on"] != nil {
			line += " @" + strings.Join(acctest.Strs(t, row["only_on"], "only_on"), ",")
		}
		got = append(got, line)
	}
	// no wildcard, no name with only a TXT or an NS, nothing disabled, and
	// nothing asked about; the one both servers hold names no server
	want := []string{
		"a.example.com [CNAME b.example.com] @dock",
		"b.example.com [CNAME a.example.com] @dock",
		"gone.example.com [CNAME nothing.van.example.com] @dock",
		"out.example.com [CNAME host.example.net] @dock",
		"two.example.com [A 10.0.0.5; A 10.0.0.6]",
		"dock.van.example.com [A 10.0.0.2] @dock",
		"deep.under.wild.example.com [A 10.0.0.7] @dock",
	}
	if !slices.Equal(got, want) {
		t.Errorf("unlisted =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	if narrower := acctest.Rows(t, suite.Call(t, "audit_names", map[string]any{"names": []string{"emby.van.example.com"}, "subtree": "van.example.com."})["unlisted"], "unlisted"); len(narrower) != 1 || narrower[0]["name"] != "dock.van.example.com" {
		t.Errorf("unlisted under the zone below = %v", narrower)
	}
	if none := suite.Call(t, "audit_names", map[string]any{"names": []string{"m.example.com"}}); none["unlisted"] != nil {
		t.Errorf("with no subtree, unlisted = %v", none["unlisted"])
	}
}
