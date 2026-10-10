package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

const (
	cachedAddress  = `{"name":"a.cached.test","type":"A","ttl":"600 (10m)","rData":{"ipAddress":"10.5.5.5"},"responseMetadata":{"nameServer":"172.18.0.3"},"lastUsedOn":"2026-10-10T01:19:26.6210257Z"}`
	cachedNegative = `{"name":"nope.cached.test","type":"A","ttl":"900 (15m)","rData":{"dataType":"DnsSpecialCacheRecordData","data":"NegativeCache: NxDomain; cached.test. 900 IN SOA ns2. hostadmin.cached.test. 3 900 300 604800 900"},"responseMetadata":{"nameServer":"172.18.0.3"},"lastUsedOn":"0001-01-01T00:00:00"}`
)

// cachePair is two servers of which dock keeps answers for three names under
// one domain, one of them that the name is not there, and rpi keeps nothing.
func cachePair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	// asked for a name it keeps nothing at, a server answers for the nearest
	// below that it does - or for the name itself, empty
	p.dock.Answer("cache/list", `{"domain":"cached.test","zones":["a.cached.test","nope.cached.test"],"records":[]}`)
	p.dock.AnswerWhen("cache/list", "domain", "a.cached.test", `{"domain":"a.cached.test","zones":[],"records":[`+cachedAddress+`]}`)
	p.dock.AnswerWhen("cache/list", "domain", "nope.cached.test", `{"domain":"nope.cached.test","zones":[],"records":[`+cachedNegative+`]}`)
	p.dock.AnswerWhen("cache/list", "domain", "other.example", `{"domain":"other.example","zones":[],"records":[]}`)
	for _, name := range []string{"a.cached.test", "nope.cached.test", "cached.test", "test", "other.example"} {
		p.rpi.AnswerWhen("cache/list", "domain", name, `{"domain":"`+name+`","zones":[],"records":[]}`)
	}
	p.rpi.Answer("cache/list", `{"domain":"","zones":[],"records":[]}`)
	p.dock.Answer("cache/delete", `{}`)
	p.dock.Answer("cache/flush", `{}`)
	p.rpi.Answer("cache/delete", `{}`)
	p.rpi.Answer("cache/flush", `{}`)

	return p
}

// cache_get says what each server is keeping for a name: an answer with the
// time it has left and where it came from, or the answer that there is none.
func TestCacheGet(t *testing.T) {
	t.Parallel()

	suite := cachePair(t).session(t, Options{})

	out := suite.Call(t, "cache_get", map[string]any{"name": "A.cached.test."})
	rows := acctest.Rows(t, out["cached"], "cached")
	if out["name"] != "a.cached.test" || len(rows) != 1 || acctest.Num(t, out["total"], "total") != 1 || !slices.Equal(acctest.Strs(t, out["not_on"], "not_on"), []string{"rpi"}) || out["under"] != nil {
		t.Fatalf("the answer = %v", out)
	}
	if row := rows[0]; row["server"] != "dock" || row["type"] != "A" || row["value"] != "10.5.5.5" || acctest.Num(t, row["ttl"], "ttl") != 600 || row["from"] != "172.18.0.3" || row["last_used"] != "2026-10-10T01:19:26Z" || row["negative"] != nil {
		t.Errorf("the address kept = %v", row)
	}

	negative := acctest.Rows(t, suite.Call(t, "cache_get", map[string]any{"name": "nope.cached.test", "server": "dock"})["cached"], "cached")
	if len(negative) != 1 || !acctest.BoolOf(negative[0]["negative"]) || negative[0]["value"] != "NxDomain" || negative[0]["last_used"] != nil {
		t.Errorf("the negative answer = %v", negative)
	}

	// a name with nothing kept at it and names under it that have: they are named
	above := suite.Call(t, "cache_get", map[string]any{"name": "cached.test"})
	under := acctest.Rows(t, above["under"], "under")
	if len(acctest.Rows(t, above["cached"], "cached")) != 0 || len(under) != 1 || under[0]["server"] != "dock" || !slices.Equal(acctest.Strs(t, under[0]["names"], "names"), []string{"a.cached.test", "nope.cached.test"}) || !slices.Equal(acctest.Strs(t, above["not_on"], "not_on"), []string{"dock", "rpi"}) {
		t.Errorf("the name above them = %v", above)
	}
	// and from further up, where the server answers for the nearest name below
	if top := acctest.Rows(t, suite.Call(t, "cache_get", map[string]any{"name": "test", "server": "dock"})["under"], "under"); len(top) != 1 || !slices.Equal(acctest.Strs(t, top[0]["names"], "names"), []string{"cached.test"}) {
		t.Errorf("from the name above that = %v", top)
	}
	// with subtree, every answer under it
	deep := suite.Call(t, "cache_get", map[string]any{"name": "test", "subtree": true, "server": "dock"})
	if got := acctest.Rows(t, deep["cached"], "cached"); len(got) != 2 || got[0]["name"] != "a.cached.test" || got[1]["name"] != "nope.cached.test" || deep["under"] != nil || deep["not_on"] != nil {
		t.Errorf("the subtree = %v", deep)
	}
	if limited := suite.Call(t, "cache_get", map[string]any{"name": "test", "subtree": true, "limit": 1}); len(acctest.Rows(t, limited["cached"], "cached")) != 1 || acctest.Num(t, limited["total"], "total") != 2 || !strings.Contains(acctest.Str(limited["note"]), "2 answers are kept and the first 1 are given") {
		t.Errorf("limited = %v", limited)
	}
	// nothing kept anywhere
	if none := suite.Call(t, "cache_get", map[string]any{"name": "other.example"}); len(acctest.Rows(t, none["cached"], "cached")) != 0 || !slices.Equal(acctest.Strs(t, none["not_on"], "not_on"), []string{"dock", "rpi"}) {
		t.Errorf("a name no server keeps = %v", none)
	}
	if msg := suite.CallErr(t, "cache_get", map[string]any{"name": " "}); !strings.Contains(msg, "which name") {
		t.Errorf("no name = %q", msg)
	}
}

// cache_flush drops what is kept for a name and under it, on one server or
// on all, and says how much went; the whole cache only when asked for in so
// many words.
func TestCacheFlush(t *testing.T) {
	t.Parallel()

	p := cachePair(t)
	suite := p.session(t, everything)

	// what would go
	dry := suite.Call(t, "cache_flush", map[string]any{"server": "all", "name": "cached.test", "dry_run": true})
	rows := acctest.Rows(t, dry["flushed"], "flushed")
	if len(rows) != 2 || acctest.Num(t, rows[0]["dropped"], "dropped") != 2 || acctest.Num(t, rows[1]["dropped"], "dropped") != 0 || !strings.Contains(acctest.Str(dry["note"]), "a dry run") || len(p.dock.Requests("cache/delete")) != 0 {
		t.Errorf("a dry run = %v", dry)
	}

	// dropped, and read back empty
	p.dock.Then("cache/delete", func(technitiumtest.Request) {
		p.dock.Answer("cache/list", `{"domain":"cached.test","zones":[],"records":[]}`)
		p.dock.AnswerWhen("cache/list", "domain", "a.cached.test", `{"domain":"a.cached.test","zones":[],"records":[]}`)
		p.dock.AnswerWhen("cache/list", "domain", "nope.cached.test", `{"domain":"nope.cached.test","zones":[],"records":[]}`)
	})
	out := suite.Call(t, "cache_flush", map[string]any{"server": "dock", "name": "cached.test"})
	rows = acctest.Rows(t, out["flushed"], "flushed")
	if len(rows) != 1 || rows[0]["server"] != "dock" || acctest.Num(t, rows[0]["dropped"], "dropped") != 2 || rows[0]["error"] != nil || out["note"] != nil {
		t.Errorf("dropped = %v", out)
	}
	if asked := p.dock.Last("cache/delete"); asked.Params.Get("domain") != "cached.test" {
		t.Errorf("the name was dropped with %v", asked.Params)
	}
	if len(p.rpi.Requests("cache/delete")) != 0 {
		t.Error("a drop on dock reached rpi")
	}

	// the whole cache, on every server
	if all := acctest.Rows(t, suite.Call(t, "cache_flush", map[string]any{"server": "all", "everything": true})["flushed"], "flushed"); len(all) != 2 || len(p.dock.Requests("cache/flush")) != 1 || len(p.rpi.Requests("cache/flush")) != 1 {
		t.Errorf("everything on all = %v", all)
	}
	// a server that will not is said beside the one that did
	p.rpi.Fail("cache/delete", "error", "Access was denied.")
	p.rpi.AnswerWhen("cache/list", "domain", "x.example", `{"domain":"x.example","zones":[],"records":[]}`)
	p.dock.AnswerWhen("cache/list", "domain", "x.example", `{"domain":"x.example","zones":[],"records":[]}`)
	mixed := acctest.Rows(t, suite.Call(t, "cache_flush", map[string]any{"server": "all", "name": "x.example"})["flushed"], "flushed")
	if mixed[0]["error"] != nil || !strings.Contains(acctest.Str(mixed[1]["error"]), "Access was denied") {
		t.Errorf("one server refusing = %v", mixed)
	}

	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"nothing named":         {map[string]any{"server": "dock"}, "which name"},
		"a name and everything": {map[string]any{"server": "dock", "name": "cached.test", "everything": true}, "not both"},
		"no server, with two":   {map[string]any{"name": "cached.test"}, "which server"},
	} {
		if msg := suite.CallErr(t, "cache_flush", tc.args); !strings.Contains(msg, tc.want) {
			t.Errorf("%s = %q, want it to say %q", name, msg, tc.want)
		}
	}
	if msg := suite.CallErr(t, "cache_flush", map[string]any{"name": "cached.test"}); !strings.Contains(msg, "or all to drop from every one") {
		t.Errorf("no server named = %q, want it to say all is a choice", msg)
	}
}
