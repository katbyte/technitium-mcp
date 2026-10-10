package tools

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// foundLines is every row record_find gave as one line: zone, name, type,
// value, the chain it was reached by, and who alone holds it.
func foundLines(t *testing.T, out map[string]any) []string {
	t.Helper()

	rows := acctest.Rows(t, out["records"], "records")
	got := make([]string, 0, len(rows))
	for _, row := range rows {
		line := "[" + acctest.Str(row["zone"]) + "] " + rowLine(t, row)
		if row["via"] != nil {
			line += " via " + strings.Join(acctest.Strs(t, row["via"], "via"), " > ")
		}
		got = append(got, line)
	}

	return got
}

// A network in small: dock holds a forward zone, a zone under it and the
// reverse zone; rpi holds the forward zone alone, without one of the names
// that end at the emby host.
func findPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"van.example.com","type":"Primary","soaSerial":3},{"name":"0.0.10.in-addr.arpa","type":"Primary","soaSerial":2},{"name":"localhost","type":"Primary","internal":true,"soaSerial":1}]}`)
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7}]}`)
	p.dock.AnswerWhen("zones/records/get", "zone", "example.com", `{"zone":{"name":"example.com"},"records":[
		{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"dock.van.example.com"}},
		{"name":"example.com","type":"MX","ttl":3600,"rData":{"preference":10,"exchange":"m.example.com"}},
		{"name":"m.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"emby.van.example.com"}},
		{"name":"jf.example.com","type":"CNAME","ttl":3600,"comments":"jellyfin","rData":{"cname":"m.example.com"}},
		{"name":"a.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"b.example.com"}},
		{"name":"b.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"a.example.com"}},
		{"name":"six.example.com","type":"AAAA","ttl":3600,"rData":{"ipAddress":"fd00::4"}}
	]}`)
	p.dock.AnswerWhen("zones/records/get", "zone", "van.example.com", `{"zone":{"name":"van.example.com"},"records":[
		{"name":"emby.van.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.4"}},
		{"name":"EMBY2.van.example.com","type":"A","ttl":3600,"disabled":true,"rData":{"ipAddress":"10.0.0.4"}},
		{"name":"dock.van.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.2"}},
		{"name":"old.van.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.40"}}
	]}`)
	p.dock.AnswerWhen("zones/records/get", "zone", "0.0.10.in-addr.arpa", `{"zone":{"name":"0.0.10.in-addr.arpa"},"records":[
		{"name":"4.0.0.10.in-addr.arpa","type":"PTR","ttl":3600,"rData":{"ptrName":"emby.van.example.com"}},
		{"name":"2.0.0.10.in-addr.arpa","type":"PTR","ttl":3600,"rData":{"ptrName":"dock.van.example.com"}}
	]}`)
	p.rpi.AnswerWhen("zones/records/get", "zone", "example.com", `{"zone":{"name":"example.com"},"records":[
		{"name":"example.com","type":"NS","ttl":14400,"rData":{"nameServer":"dock.van.example.com"}},
		{"name":"example.com","type":"MX","ttl":3600,"rData":{"preference":10,"exchange":"m.example.com"}},
		{"name":"m.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"emby.van.example.com"}}
	]}`)

	return p
}

// By address, record_find answers what a move of that address would touch:
// the records holding it, its PTR, and everything that ends at one of those
// names through a chain, each with the chain. Each server is searched by
// itself, so a name one server cannot follow to the address is not found
// there.
func TestRecordFindByAddress(t *testing.T) {
	t.Parallel()

	suite := findPair(t).session(t, Options{})

	out := suite.Call(t, "record_find", map[string]any{"address": "10.0.0.4"})
	want := []string{
		"[0.0.10.in-addr.arpa] 4.0.0.10.in-addr.arpa PTR emby.van.example.com @dock",
		// an MX names a host and is found; its own name is not then an alias for the host
		"[example.com] example.com MX 10 m.example.com @dock via m.example.com > emby.van.example.com > 10.0.0.4",
		"[example.com] jf.example.com CNAME m.example.com @dock via m.example.com > emby.van.example.com > 10.0.0.4",
		"[example.com] m.example.com CNAME emby.van.example.com @dock via emby.van.example.com > 10.0.0.4",
		"[van.example.com] emby.van.example.com A 10.0.0.4 @dock",
		"[van.example.com] EMBY2.van.example.com A 10.0.0.4 @dock",
	}
	if got := foundLines(t, out); !slices.Equal(got, want) {
		t.Errorf("found =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	// rpi holds the names and not the zone the address is in: nothing there
	// ends at the address, so everything found is dock's alone
	if out["reverse_name"] != "4.0.0.10.in-addr.arpa" || acctest.Num(t, out["total"], "total") != 6 || acctest.Num(t, out["zones"], "zones") != 3 || !slices.Equal(acctest.Strs(t, out["asked"], "asked"), []string{"dock", "rpi"}) {
		t.Errorf("the answer = %v", out)
	}
	if disabled := acctest.Rows(t, out["records"], "records")[5]; !acctest.BoolOf(disabled["disabled"]) {
		t.Errorf("the disabled record holding the address = %v", disabled)
	}

	// the holders alone
	direct := foundLines(t, suite.Call(t, "record_find", map[string]any{"address": "10.0.0.4", "direct": true}))
	if !slices.Equal(direct, []string{want[0], want[4], want[5]}) {
		t.Errorf("direct = %v", direct)
	}
	// the filters are asked of what was found
	if cnames := foundLines(t, suite.Call(t, "record_find", map[string]any{"address": "10.0.0.4", "types": []string{"cname"}, "disabled": false})); !slices.Equal(cnames, []string{want[2], want[3]}) {
		t.Errorf("the CNAMEs that end at it = %v", cnames)
	}
	if inZone := foundLines(t, suite.Call(t, "record_find", map[string]any{"address": "10.0.0.4", "zone": "van.example.com"})); !slices.Equal(inZone, []string{want[4], want[5]}) {
		t.Errorf("in one zone, where the chains into it cannot be seen = %v", inZone)
	}

	// an address nothing holds is free of records, and its PTR's place is still said
	free := suite.Call(t, "record_find", map[string]any{"address": "10.0.0.7"})
	if acctest.Num(t, free["total"], "total") != 0 || len(acctest.Rows(t, free["records"], "records")) != 0 || free["reverse_name"] != "7.0.0.10.in-addr.arpa" {
		t.Errorf("an address nothing holds = %v", free)
	}
	// an address is matched whole: .4 is not .40
	if near := foundLines(t, suite.Call(t, "record_find", map[string]any{"address": "10.0.0.40"})); !slices.Equal(near, []string{"[van.example.com] old.van.example.com A 10.0.0.40 @dock"}) {
		t.Errorf("10.0.0.40 = %v", near)
	}
	six := suite.Call(t, "record_find", map[string]any{"address": "FD00::4"})
	if got := foundLines(t, six); !slices.Equal(got, []string{"[example.com] six.example.com AAAA fd00::4 @dock"}) || six["reverse_name"] != "4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa" {
		t.Errorf("an IPv6 address = %v at %v", got, six["reverse_name"])
	}
}

// By target, record_find answers what points at a name, straight or through
// a chain, on each server by itself; a loop of CNAMEs is followed once round
// and no further.
func TestRecordFindByTarget(t *testing.T) {
	t.Parallel()

	suite := findPair(t).session(t, Options{})

	out := suite.Call(t, "record_find", map[string]any{"target": "Emby.van.example.com."})
	want := []string{
		"[0.0.10.in-addr.arpa] 4.0.0.10.in-addr.arpa PTR emby.van.example.com @dock",
		// both servers hold these two, and each follows them to the name
		"[example.com] example.com MX 10 m.example.com via m.example.com > emby.van.example.com",
		"[example.com] jf.example.com CNAME m.example.com @dock via m.example.com > emby.van.example.com",
		"[example.com] m.example.com CNAME emby.van.example.com",
	}
	if got := foundLines(t, out); !slices.Equal(got, want) {
		t.Errorf("found =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	if out["reverse_name"] != nil {
		t.Errorf("a search by name has a reverse name: %v", out["reverse_name"])
	}
	if direct := foundLines(t, suite.Call(t, "record_find", map[string]any{"target": "emby.van.example.com", "direct": true})); !slices.Equal(direct, []string{want[0], want[3]}) {
		t.Errorf("direct = %v", direct)
	}

	loop := foundLines(t, suite.Call(t, "record_find", map[string]any{"target": "a.example.com"}))
	if !slices.Equal(loop, []string{"[example.com] a.example.com CNAME b.example.com @dock via b.example.com > a.example.com", "[example.com] b.example.com CNAME a.example.com @dock"}) {
		t.Errorf("a loop = %v", loop)
	}
}

// With neither, record_find is a search of every zone at once, by name,
// value, type or comment, read whole and paged.
func TestRecordFindBySearch(t *testing.T) {
	t.Parallel()

	p := findPair(t)
	suite := p.session(t, Options{})

	for name, tc := range map[string]struct {
		args map[string]any
		want []string
	}{
		"a name anywhere":    {map[string]any{"name": "emby"}, []string{"[van.example.com] emby.van.example.com A 10.0.0.4 @dock", "[van.example.com] EMBY2.van.example.com A 10.0.0.4 @dock"}},
		"a subtree":          {map[string]any{"name": "*.van.example.com", "disabled": false, "value": "10.0.0.?"}, []string{"[van.example.com] dock.van.example.com A 10.0.0.2 @dock", "[van.example.com] emby.van.example.com A 10.0.0.4 @dock"}},
		"a range of values":  {map[string]any{"value": "10.0.0.4"}, []string{"[van.example.com] emby.van.example.com A 10.0.0.4 @dock", "[van.example.com] EMBY2.van.example.com A 10.0.0.4 @dock", "[van.example.com] old.van.example.com A 10.0.0.40 @dock"}},
		"a type everywhere":  {map[string]any{"types": []string{"PTR", "AAAA"}}, []string{"[0.0.10.in-addr.arpa] 2.0.0.10.in-addr.arpa PTR dock.van.example.com @dock", "[0.0.10.in-addr.arpa] 4.0.0.10.in-addr.arpa PTR emby.van.example.com @dock", "[example.com] six.example.com AAAA fd00::4 @dock"}},
		"held by both":       {map[string]any{"types": []string{"MX", "NS"}}, []string{"[example.com] example.com MX 10 m.example.com", "[example.com] example.com NS dock.van.example.com"}},
		"commented":          {map[string]any{"comment": "*"}, []string{"[example.com] jf.example.com CNAME m.example.com @dock"}},
		"the disabled":       {map[string]any{"disabled": true}, []string{"[van.example.com] EMBY2.van.example.com A 10.0.0.4 @dock"}},
		"in some zones":      {map[string]any{"zone": "*.arpa", "name": "4."}, []string{"[0.0.10.in-addr.arpa] 4.0.0.10.in-addr.arpa PTR emby.van.example.com @dock"}},
		"one server's alone": {map[string]any{"server": "rpi", "types": []string{"CNAME"}}, []string{"[example.com] m.example.com CNAME emby.van.example.com"}},
		"nothing":            {map[string]any{"name": "nope"}, []string{}},
	} {
		if got := foundLines(t, suite.Call(t, "record_find", tc.args)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v\n  = %v\n  want %v", name, tc.args, got, tc.want)
		}
	}

	// the servers' own zones are not searched, and each zone is read once
	before := len(p.dock.Requests("zones/records/get"))
	suite.Call(t, "record_find", map[string]any{"name": "emby"})
	if n := len(p.dock.Requests("zones/records/get")) - before; n != 3 {
		t.Errorf("one search asked dock for records %d times, want once for each of the three zones it serves", n)
	}

	// a limit says where to read on from
	first := suite.Call(t, "record_find", map[string]any{"types": []string{"A"}, "limit": 2})
	if len(foundLines(t, first)) != 2 || acctest.Num(t, first["total"], "total") != 4 || !strings.Contains(acctest.Str(first["note"]), "4 records were found and 2 are given, starting at the 1st: read on with offset 2") {
		t.Errorf("the first two = %v", first)
	}
	if rest := suite.Call(t, "record_find", map[string]any{"types": []string{"A"}, "offset": 2}); len(foundLines(t, rest)) != 2 || rest["note"] != nil {
		t.Errorf("the rest = %v", rest)
	}

	// each server's own facts, on request
	details := acctest.Rows(t, suite.Call(t, "record_find", map[string]any{"types": []string{"MX"}, "details": true})["records"], "records")
	if on := acctest.Rows(t, details[0]["on"], "on"); len(on) != 2 || on[0]["server"] != "dock" || on[1]["server"] != "rpi" {
		t.Errorf("the MX's own facts = %v", details[0]["on"])
	}

	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"nothing asked for":    {map[string]any{}, "say what to find"},
		"a zone alone":         {map[string]any{"zone": "example.com"}, "say what to find"},
		"no address":           {map[string]any{"address": "10.0.0"}, "is not an IPv4 or IPv6 address"},
		"both searches":        {map[string]any{"address": "10.0.0.4", "target": "emby.van.example.com"}, "not both"},
		"a server that is not": {map[string]any{"name": "emby", "server": "pi"}, "dock, rpi"},
	} {
		if msg := suite.CallErr(t, "record_find", tc.args); !strings.Contains(msg, tc.want) {
			t.Errorf("%s = %q, want it to say %q", name, msg, tc.want)
		}
	}
}

// A zone a server will not give the records of, and a server that cannot be
// asked, are said beside what was found; the search fails only when no
// server can be asked.
func TestRecordFindWhenSomethingCannotBeRead(t *testing.T) {
	t.Parallel()

	p := findPair(t)
	p.dock.FailWhen("zones/records/get", "zone", "van.example.com", "error", "Access was denied.")
	suite := p.session(t, Options{})

	out := suite.Call(t, "record_find", map[string]any{"types": []string{"A", "PTR"}})
	if got := foundLines(t, out); len(got) != 2 || !strings.HasPrefix(got[0], "[0.0.10.in-addr.arpa]") {
		t.Errorf("found = %v, want the reverse zone's two records", got)
	}
	problems := acctest.Rows(t, out["problems"], "problems")
	if len(problems) != 1 || problems[0]["server"] != "dock" || problems[0]["zone"] != "van.example.com" || !strings.Contains(acctest.Str(problems[0]["error"]), "Access was denied") || acctest.Num(t, out["zones"], "zones") != 2 {
		t.Errorf("problems = %v with %v zones read", problems, out["zones"])
	}

	p.rpi.Fail("zones/list", "invalid-token", "Invalid token or session expired.")
	out = suite.Call(t, "record_find", map[string]any{"types": []string{"MX"}})
	if failed := acctest.Rows(t, out["failed"], "failed"); len(failed) != 1 || failed[0]["server"] != "rpi" || !slices.Equal(acctest.Strs(t, out["asked"], "asked"), []string{"dock"}) {
		t.Errorf("failed = %v, asked = %v", out["failed"], out["asked"])
	}
	// with one server asked, everything found is on every server asked
	if got := foundLines(t, out); !slices.Equal(got, []string{"[example.com] example.com MX 10 m.example.com"}) {
		t.Errorf("found with rpi down = %v", got)
	}

	p.dock.Fail("zones/list", "error", "boom")
	if msg := suite.CallErr(t, "record_find", map[string]any{"name": "emby"}); !strings.Contains(msg, "dock: zones/list: boom") || !strings.Contains(msg, "rpi: ") {
		t.Errorf("with no server answering = %q", msg)
	}
}

// A catalog zone's records are the list of its members, kept as PTR and TXT
// records that point at every zone it lists: bookkeeping, which a search of
// every zone leaves out and a search that names the zone gives.
func TestRecordFindLeavesCatalogsOut(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"catalog.example","type":"Catalog","soaSerial":3}]}`)
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Secondary","soaSerial":7},{"name":"catalog.example","type":"SecondaryCatalog","soaSerial":3}]}`)
	p.both("zones/records/get", `{"zone":{"name":"example.com"},"records":[{"name":"www.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"example.com"}}]}`)
	for _, server := range []*technitiumtest.Server{p.dock, p.rpi} {
		server.AnswerWhen("zones/records/get", "zone", "catalog.example", `{"zone":{"name":"catalog.example"},"records":[{"name":"abc.zones.catalog.example","type":"PTR","ttl":0,"rData":{"ptrName":"example.com"}}]}`)
	}
	suite := p.session(t, Options{})

	out := suite.Call(t, "record_find", map[string]any{"target": "example.com"})
	if got := foundLines(t, out); !slices.Equal(got, []string{"[example.com] www.example.com CNAME example.com"}) || acctest.Num(t, out["zones"], "zones") != 1 {
		t.Errorf("what points at the zone = %v in %v zones, want the catalog's own record of it left out", got, out["zones"])
	}
	if got := foundLines(t, suite.Call(t, "record_find", map[string]any{"types": []string{"PTR"}, "zone": "catalog"})); !slices.Equal(got, []string{"[catalog.example] abc.zones.catalog.example PTR example.com"}) {
		t.Errorf("the catalog searched by name = %v", got)
	}
}

func TestReverseName(t *testing.T) {
	t.Parallel()

	for addr, want := range map[string]string{
		"10.0.0.4":        "4.0.0.10.in-addr.arpa",
		"192.168.100.250": "250.100.168.192.in-addr.arpa",
		"::ffff:10.0.0.4": "4.0.0.10.in-addr.arpa",
		"2001:db8::1":     "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
	} {
		if got := reverseName(netip.MustParseAddr(addr)); got != want {
			t.Errorf("reverseName(%s) = %q, want %q", addr, got, want)
		}
	}
}
