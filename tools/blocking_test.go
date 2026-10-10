package tools

import (
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

const (
	blockingOnSettings = `{"enableBlocking":true,"blockingType":"NxDomain","blockListUrls":["https://lists.example.org/ads.txt"],"blockListUpdateIntervalHours":24,"blockListNextUpdatedOn":"2026-10-11T03:50:00.123Z","blockingBypassList":["10.0.0.9"]}`
	notInACluster      = `{"clusterInitialized":false,"dnsServerDomain":"dock","version":"15.6","serverIpAddresses":["10.0.0.2"]}`
	listStats          = `{"stats":{"totalQueries":0,"blockedZones":3,"blockListZones":307447}}`
)

// answerOf is a server's answer for a name: blocked by what the text says,
// from its own zone with an address, or simply that it does not exist.
func answerOf(blockedBy, ownAddress string) string {
	switch {
	case blockedBy != "":
		return `{"result":{"RCODE":"NxDomain","AuthoritativeAnswer":false,"EDNS":{"Options":[{"Code":"EXTENDED_DNS_ERROR","Data":{"InfoCode":"Blocked","ExtraText":"` + blockedBy + `"}}]},"Answer":[]}}`
	case ownAddress != "":
		return `{"result":{"RCODE":"NoError","AuthoritativeAnswer":true,"EDNS":{"Options":[]},"Answer":[{"Name":"x","Type":"A","TTL":"3600 (1h)","RDATA":{"IPAddress":"` + ownAddress + `"}}]}}`
	default:
		return `{"result":{"RCODE":"NxDomain","AuthoritativeAnswer":false,"EDNS":{"Options":[]},"Answer":[]}}`
	}
}

// blockPair is two servers that block: dock with three names on its own
// blocked list, one on its allowed list and a zone of its own; rpi with one
// of the three, and nothing else.
func blockPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.both("settings/get", blockingOnSettings)
	p.both("admin/cluster/state", notInACluster)
	p.both("dashboard/stats/get", listStats)
	p.dock.AnswerText("blocked/export", "tracker.example.org\nads.example.net\nheld.example.com\nads.blocked.test\n")
	p.dock.AnswerText("allowed/export", "good.ads.example.net\n")
	p.rpi.AnswerText("blocked/export", "ads.example.net\n")
	p.rpi.AnswerText("allowed/export", "")
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"fwd.example.org","type":"Forwarder"}]}`)
	p.rpi.Answer("zones/list", `{"zones":[]}`)

	// what each answers when a test does not say otherwise: no such name, and nothing said of a block
	p.both("dnsClient/resolve", answerOf("", ""))
	for _, name := range []string{"ads.example.net", "x.ads.example.net"} {
		p.dock.AnswerWhen("dnsClient/resolve", "domain", name, answerOf("source=blocked-zone; domain=ads.example.net", ""))
		p.rpi.AnswerWhen("dnsClient/resolve", "domain", name, answerOf("source=blocked-zone; domain=ads.example.net", ""))
	}
	p.rpi.AnswerWhen("dnsClient/resolve", "domain", "good.ads.example.net", answerOf("source=blocked-zone; domain=ads.example.net", ""))
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "held.example.com", answerOf("", "10.0.0.4"))
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "ads.blocked.test", `{"result":{"RCODE":"NxDomain","AuthoritativeAnswer":true,"EDNS":{"Options":[]},"Answer":[]}}`)
	for _, server := range []*technitiumtest.Server{p.dock, p.rpi} {
		server.AnswerWhen("dnsClient/resolve", "domain", "list.example.org", answerOf("source=block-list-zone; blockListUrl=https://lists.example.org/ads.txt; domain=example.org", ""))
		for _, path := range []string{"blocked/add", "blocked/delete", "allowed/add", "allowed/delete"} {
			server.Answer(path, `{}`)
		}
	}

	return p
}

// blockWritten are the calls a server was sent that change its lists.
func blockWritten(server *technitiumtest.Server) []string {
	var out []string
	for _, path := range []string{"blocked/add", "blocked/delete", "allowed/add", "allowed/delete"} {
		for _, req := range server.Requests(path) {
			out = append(out, path+" "+req.Params.Get("domain"))
		}
	}

	return out
}

// block_check asks each server for each name and weighs the answer against
// its lists: blocked and by what, or not and why an entry does nothing.
func TestBlockCheck(t *testing.T) {
	t.Parallel()

	p := blockPair(t)
	suite := p.session(t, Options{})

	out := suite.Call(t, "block_check", map[string]any{"names": []string{"X.ads.example.net.", "good.ads.example.net", "held.example.com", "list.example.org", "fine.example.org", "ads.blocked.test", "x.ads.example.net"}})
	checks := acctest.Rows(t, out["checks"], "checks")
	if len(checks) != 12 || out["failed"] != nil {
		t.Fatalf("checks = %v, want six names on two servers, the one given twice checked once", checks)
	}
	of := func(name, server string) map[string]any {
		t.Helper()
		for _, c := range checks {
			if c["name"] == name && c["server"] == server {
				return c
			}
		}
		t.Fatalf("no check of %s on %s", name, server)

		return nil
	}
	// name by name, and for each the servers in their order
	if checks[0]["name"] != "x.ads.example.net" || checks[0]["server"] != "dock" || checks[1]["server"] != "rpi" || checks[2]["name"] != "good.ads.example.net" {
		t.Errorf("the order = %v", checks)
	}

	// blocked by the server's own entry above the name
	for _, server := range []string{"dock", "rpi"} {
		if c := of("x.ads.example.net", server); !acctest.BoolOf(c["blocked"]) || c["by"] != "own_list" || c["entry"] != "ads.example.net" || c["list"] != nil || c["listed"] != nil || c["why"] != nil || c["answer"] != "NxDomain" {
			t.Errorf("x.ads.example.net on %s = %v", server, c)
		}
	}
	// allowed on dock, which wins over the entry that blocks it on rpi
	if c := of("good.ads.example.net", "dock"); acctest.BoolOf(c["blocked"]) || c["allowed"] != "good.ads.example.net" || c["listed"] != "ads.example.net" || c["why"] != "the allowed entry good.ads.example.net wins over it" {
		t.Errorf("the allowed name on dock = %v", c)
	}
	if c := of("good.ads.example.net", "rpi"); !acctest.BoolOf(c["blocked"]) || c["entry"] != "ads.example.net" || c["allowed"] != nil {
		t.Errorf("the name rpi does not allow = %v", c)
	}
	// on the list, and answered by the server's own zone all the same
	if c := of("held.example.com", "dock"); acctest.BoolOf(c["blocked"]) || c["listed"] != "held.example.com" || c["why"] != "dock answers the name from its own zone example.com, and no list is looked at for a name a zone here holds" || c["answer"] != "NoError 10.0.0.4" {
		t.Errorf("the blocked name a zone holds = %v", c)
	}
	// on the list under .test, which the server refuses itself first
	if c := of("ads.blocked.test", "dock"); acctest.BoolOf(c["blocked"]) || c["listed"] != "ads.blocked.test" || !strings.Contains(acctest.Str(c["why"]), "dock answers for this name itself before any list is looked at") {
		t.Errorf("the blocked name under .test = %v", c)
	}
	// blocked by a list the server fetches
	if c := of("list.example.org", "rpi"); !acctest.BoolOf(c["blocked"]) || c["by"] != "block_list" || c["list"] != "https://lists.example.org/ads.txt" || c["entry"] != "example.org" {
		t.Errorf("the name a block list blocks = %v", c)
	}
	// and one nothing blocks
	if c := of("fine.example.org", "dock"); acctest.BoolOf(c["blocked"]) || c["by"] != nil || c["listed"] != nil || c["allowed"] != nil || c["why"] != nil || c["error"] != nil {
		t.Errorf("a name nothing blocks = %v", c)
	}

	// blocking off, and paused: the entry is there and does nothing
	p.dock.Answer("settings/get", `{"enableBlocking":false,"blockingType":"NxDomain"}`)
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "ads.example.net", answerOf("", ""))
	off := acctest.Rows(t, suite.Call(t, "block_check", map[string]any{"names": []string{"ads.example.net"}, "server": "dock"})["checks"], "checks")
	if len(off) != 1 || acctest.BoolOf(off[0]["blocked"]) || off[0]["listed"] != "ads.example.net" || off[0]["why"] != "blocking is switched off on dock" {
		t.Errorf("with blocking off = %v", off)
	}
	p.dock.Answer("settings/get", `{"enableBlocking":false,"blockingType":"NxDomain","temporaryDisableBlockingTill":"2099-01-01T00:00:00.5Z"}`)
	paused := acctest.Rows(t, suite.Call(t, "block_check", map[string]any{"names": []string{"ads.example.net"}, "server": "dock"})["checks"], "checks")
	if paused[0]["why"] != "blocking is paused on dock until 2099-01-01T00:00:00Z" {
		t.Errorf("with blocking paused = %v", paused)
	}

	// a name the server cannot be asked for is its own row's error; a server whose lists will not be read is said beside the other's
	p.rpi.FailWhen("dnsClient/resolve", "domain", "fine.example.org", "error", "boom")
	if got := acctest.Rows(t, suite.Call(t, "block_check", map[string]any{"names": []string{"fine.example.org"}, "server": "rpi"})["checks"], "checks"); len(got) != 1 || got[0]["error"] != "dnsClient/resolve: boom" {
		t.Errorf("a name that could not be asked for = %v", got)
	}
	p.rpi.Fail("blocked/export", "error", "Access was denied.")
	denied := suite.Call(t, "block_check", map[string]any{"names": []string{"fine.example.org"}})
	if failed := acctest.Rows(t, denied["failed"], "failed"); len(failed) != 1 || failed[0]["server"] != "rpi" || len(acctest.Rows(t, denied["checks"], "checks")) != 1 {
		t.Errorf("with rpi's lists refused = %v", denied)
	}

	if msg := suite.CallErr(t, "block_check", map[string]any{"names": []string{" ", ""}}); !strings.Contains(msg, "which names") {
		t.Errorf("no names = %q", msg)
	}
	many := make([]string, 0, 51)
	for i := range 51 {
		many = append(many, "n"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example.org")
	}
	if msg := suite.CallErr(t, "block_check", map[string]any{"names": many}); !strings.Contains(msg, "51 names: block_check takes 50 at a time") {
		t.Errorf("too many names = %q", msg)
	}
}

// block_list sets the servers' blocking side by side with their own two
// lists as one table, and names what they do not have alike.
func TestBlockList(t *testing.T) {
	t.Parallel()

	p := blockPair(t)
	suite := p.session(t, Options{})

	out := suite.Call(t, "block_list", nil)
	rows := acctest.Rows(t, out["servers"], "servers")
	if len(rows) != 2 {
		t.Fatalf("servers = %v", rows)
	}
	if d := rows[0]; d["server"] != "dock" || d["blocking"] != "on" || d["paused_until"] != nil || d["answers"] != "NxDomain" || !slices.Equal(acctest.Texts(d["lists"]), []string{"https://lists.example.org/ads.txt"}) || d["lists_every"] != "24h" || d["lists_next"] != "2026-10-11T03:50:00Z" || acctest.Num(t, d["list_names"], "list_names") != 307447 || acctest.Num(t, d["blocked"], "blocked") != 4 || acctest.Num(t, d["allowed"], "allowed") != 1 || !slices.Equal(acctest.Texts(d["bypass"]), []string{"10.0.0.9"}) || d["note"] != nil {
		t.Errorf("dock = %v", d)
	}
	if acctest.Num(t, rows[1]["blocked"], "blocked") != 1 || acctest.Num(t, rows[1]["allowed"], "allowed") != 0 {
		t.Errorf("rpi = %v", rows[1])
	}

	// one table, in the order a zone tree reads: an entry both have is one row, and one that only dock has says so
	entries := acctest.Rows(t, out["entries"], "entries")
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, acctest.Str(e["name"])+" "+acctest.Str(e["list"])+" "+strings.Join(acctest.Texts(e["only_on"]), ","))
	}
	if want := []string{"held.example.com blocked dock", "ads.example.net blocked ", "good.ads.example.net allowed dock", "tracker.example.org blocked dock", "ads.blocked.test blocked dock"}; !slices.Equal(got, want) || acctest.Num(t, out["total"], "total") != 5 {
		t.Errorf("entries = %q, want %q", got, want)
	}
	if !slices.Equal(acctest.Strs(t, out["differ"], "differ"), []string{"blocked", "allowed"}) {
		t.Errorf("differ = %v, want the two lists", out["differ"])
	}

	// narrowed, and a few at a time
	if found := suite.Call(t, "block_list", map[string]any{"find": "ads.example"}); acctest.Num(t, found["total"], "total") != 2 {
		t.Errorf("the entries with ads.example in them = %v", found["entries"])
	}
	if allowed := acctest.Rows(t, suite.Call(t, "block_list", map[string]any{"list": "Allowed"})["entries"], "entries"); len(allowed) != 1 || allowed[0]["name"] != "good.ads.example.net" {
		t.Errorf("the allowed entries = %v", allowed)
	}
	paged := suite.Call(t, "block_list", map[string]any{"limit": 2, "offset": 1})
	if e := acctest.Rows(t, paged["entries"], "entries"); len(e) != 2 || e[0]["name"] != "ads.example.net" || !strings.Contains(acctest.Str(paged["note"]), "5 entries matched and 2 are given, starting at the 2nd: read on with offset 3") {
		t.Errorf("paged = %v", paged)
	}
	if msg := suite.CallErr(t, "block_list", map[string]any{"list": "denied"}); !strings.Contains(msg, "it takes blocked or allowed") {
		t.Errorf("a list there is none of = %q", msg)
	}

	// what differs in how they block is named too; what the lists hold is the dashboard's to say, which may not be read
	p.rpi.Answer("settings/get", `{"enableBlocking":false,"blockingType":"CustomAddress","customBlockingAddresses":["10.66.66.66","fd00::66"],"blockListUrls":[],"temporaryDisableBlockingTill":"2099-01-01T00:00:00Z"}`)
	p.dock.Fail("dashboard/stats/get", "error", "Access was denied.")
	out = suite.Call(t, "block_list", nil)
	rows = acctest.Rows(t, out["servers"], "servers")
	if r := rows[1]; r["blocking"] != "paused" || r["paused_until"] != "2099-01-01T00:00:00Z" || r["answers"] != "CustomAddress 10.66.66.66, fd00::66" || r["lists"] != nil || r["lists_next"] != nil || r["list_names"] != nil {
		t.Errorf("rpi, set otherwise = %v", r)
	}
	if d := rows[0]; d["list_names"] != nil || !strings.Contains(acctest.Str(d["note"]), "how many names the lists hold could not be read: dashboard/stats/get: Access was denied.") {
		t.Errorf("dock, with its dashboard refused = %v", d)
	}
	if !slices.Equal(acctest.Strs(t, out["differ"], "differ"), []string{"blocking", "answers", "lists", "blocked", "allowed"}) {
		t.Errorf("differ = %v, want everything", out["differ"])
	}

	// a server that cannot be read is a row that says so, and the other's entries are not called its alone
	p.rpi.Fail("settings/get", "error", "boom")
	out = suite.Call(t, "block_list", nil)
	if rows = acctest.Rows(t, out["servers"], "servers"); rows[1]["error"] != "settings/get: boom" || out["differ"] != nil {
		t.Errorf("with rpi unread = %v, differ %v", rows[1], out["differ"])
	}
	for _, e := range acctest.Rows(t, out["entries"], "entries") {
		if e["only_on"] != nil {
			t.Errorf("with one server read, %v is said to be on it alone", e)
		}
	}
}

// A name is put on a list and taken off, each read back from the server and
// followed by asking it for the name.
func TestBlockSetAndDelete(t *testing.T) {
	t.Parallel()

	p := blockPair(t)
	suite := p.session(t, everything)
	const dockBlocked = "tracker.example.org\nads.example.net\nheld.example.com\nads.blocked.test\n"

	// added, read back, and blocked now
	p.dock.Then("blocked/add", func(technitiumtest.Request) {
		p.dock.AnswerText("blocked/export", dockBlocked+"new.example.net\n")
		p.dock.AnswerWhen("dnsClient/resolve", "domain", "new.example.net", answerOf("source=blocked-zone; domain=new.example.net", ""))
	})
	out := suite.Call(t, "block_set", map[string]any{"server": "dock", "name": "New.Example.net."})
	if out["server"] != "dock" || out["list"] != "blocked" || out["name"] != "new.example.net" || !acctest.BoolOf(out["changed"]) || !slices.Equal(acctest.Strs(t, out["changes"], "changes"), []string{"added new.example.net to the blocked list of dock"}) || out["note"] != nil || out["under"] != nil {
		t.Errorf("the answer = %v", out)
	}
	if now := acctest.Object(t, out["now"], "now"); !acctest.BoolOf(now["blocked"]) || now["by"] != "own_list" || now["entry"] != "new.example.net" {
		t.Errorf("now = %v", now)
	}
	if asked := p.dock.Last("blocked/add"); asked.Params.Get("domain") != "new.example.net" {
		t.Errorf("added with %v", asked.Params)
	}
	p.dock.Then("blocked/add", nil)
	p.dock.AnswerText("blocked/export", dockBlocked)

	// on the list already, itself or by the entry above it: nothing is written
	sent := len(blockWritten(p.dock))
	if again := suite.Call(t, "block_set", map[string]any{"server": "dock", "name": "ads.example.net"}); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 || again["note"] != nil || !acctest.BoolOf(acctest.Object(t, again["now"], "now")["blocked"]) {
		t.Errorf("an entry that is there = %v", again)
	}
	covered := suite.Call(t, "block_set", map[string]any{"server": "dock", "name": "x.ads.example.net"})
	if acctest.BoolOf(covered["changed"]) || !strings.Contains(acctest.Str(covered["note"]), "x.ads.example.net is on the blocked list already by the entry above it, ads.example.net, which stands for every name under it: nothing was added") {
		t.Errorf("a name an entry above covers = %v", covered)
	}
	// a dry run says what would be done, and the entries the new one would stand for
	dry := suite.Call(t, "block_set", map[string]any{"server": "dock", "name": "net", "dry_run": true})
	if !acctest.BoolOf(dry["changed"]) || !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have added net to the blocked list of dock"}) || !slices.Equal(acctest.Texts(dry["under"]), []string{"ads.example.net"}) || dry["now"] != nil || !strings.Contains(acctest.Str(dry["note"]), "the entry stands for every name that ends in .net") {
		t.Errorf("a dry run = %v", dry)
	}
	if len(blockWritten(p.dock)) != sent {
		t.Errorf("%d writes for what changed nothing: %v", len(blockWritten(p.dock))-sent, blockWritten(p.dock)[sent:])
	}

	// allowed: on the other list, and not blocked afterwards
	p.dock.Then("allowed/add", func(technitiumtest.Request) {
		p.dock.AnswerText("allowed/export", "good.ads.example.net\nads.example.net\n")
	})
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "ads.example.net", answerOf("", ""))
	allowed := suite.Call(t, "block_set", map[string]any{"server": "dock", "name": "ads.example.net", "list": "allowed"})
	if now := acctest.Object(t, allowed["now"], "now"); allowed["list"] != "allowed" || acctest.BoolOf(now["blocked"]) || now["allowed"] != "ads.example.net" || now["why"] != "the allowed entry ads.example.net wins over it" || !slices.Equal(acctest.Texts(allowed["under"]), []string{"good.ads.example.net"}) {
		t.Errorf("allowed = %v", allowed)
	}
	if asked := p.dock.Last("allowed/add"); asked.Params.Get("domain") != "ads.example.net" {
		t.Errorf("allowed with %v", asked.Params)
	}
	p.dock.AnswerText("allowed/export", "good.ads.example.net\n")
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "ads.example.net", answerOf("source=blocked-zone; domain=ads.example.net", ""))

	// a blocked entry for a name a zone here answers does nothing, which the answer says
	p.dock.Then("blocked/add", func(technitiumtest.Request) { p.dock.AnswerText("blocked/export", dockBlocked+"www.example.com\n") })
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "www.example.com", answerOf("", "10.0.0.5"))
	if now := acctest.Object(t, suite.Call(t, "block_set", map[string]any{"server": "dock", "name": "www.example.com"})["now"], "now"); acctest.BoolOf(now["blocked"]) || !strings.Contains(acctest.Str(now["why"]), "dock answers the name from its own zone example.com") {
		t.Errorf("a blocked entry for a name a zone holds = %v", now)
	}
	p.dock.Then("blocked/add", nil)
	p.dock.AnswerText("blocked/export", dockBlocked)

	// what is no entry is refused before anything is written
	sent = len(blockWritten(p.dock))
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"a wildcard":       {map[string]any{"server": "dock", "name": "*.ads.example.net"}, "it takes no wildcard: give ads.example.net"},
		"an address":       {map[string]any{"server": "dock", "name": "https://ads.example.net/x"}, "is no domain name"},
		"no name":          {map[string]any{"server": "dock", "name": " "}, "which name"},
		"a list of no use": {map[string]any{"server": "dock", "name": "ads.example.net", "list": "denied"}, "it takes blocked (the default) or allowed"},
		"no server":        {map[string]any{"name": "ads.example.net"}, "rpi"},
	} {
		if msg := suite.CallErr(t, "block_set", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
	// the server says ok and the list does not have it: an error, not a success
	if msg := suite.CallErr(t, "block_set", map[string]any{"server": "dock", "name": "lost.example.net"}); !strings.Contains(msg, "the server took the change and lost.example.net is not on the blocked list of dock") {
		t.Errorf("a change that did not take = %q", msg)
	}
	if got := blockWritten(p.dock); len(got) != sent+1 || p.dock.Last("blocked/add").Params.Get("domain") != "lost.example.net" {
		t.Errorf("the refused changes wrote %v, want the one the server took and lost", got)
	}

	// removed: named exactly, read back, and asked for afterwards
	if msg := suite.CallErr(t, "block_delete", map[string]any{"server": "dock", "name": "x.ads.example.net"}); !strings.Contains(msg, "x.ads.example.net is not an entry of the blocked list of dock: it is on the list by the entry above it, ads.example.net, and removing that one takes every name under ads.example.net off with it. Nothing was removed") {
		t.Errorf("removing a name an entry above covers = %q", msg)
	}
	if msg := suite.CallErr(t, "block_delete", map[string]any{"server": "dock", "name": "example.net"}); !strings.Contains(msg, "example.net is not an entry of the blocked list of dock: the entries under it are ads.example.net. Nothing was removed") {
		t.Errorf("removing a name with entries under it = %q", msg)
	}
	dry = suite.Call(t, "block_delete", map[string]any{"server": "dock", "name": "tracker.example.org", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have removed tracker.example.org from the blocked list of dock"}) || dry["now"] != nil || len(p.dock.Requests("blocked/delete")) != 0 {
		t.Errorf("a dry run of a removal = %v", dry)
	}
	p.dock.Then("blocked/delete", func(technitiumtest.Request) {
		p.dock.AnswerText("blocked/export", "ads.example.net\nheld.example.com\nads.blocked.test\n")
	})
	gone := suite.Call(t, "block_delete", map[string]any{"server": "dock", "name": "tracker.example.org"})
	if now := acctest.Object(t, gone["now"], "now"); !slices.Equal(acctest.Strs(t, gone["changes"], "changes"), []string{"removed tracker.example.org from the blocked list of dock"}) || acctest.BoolOf(now["blocked"]) || now["listed"] != nil || gone["note"] != nil {
		t.Errorf("removed = %v", gone)
	}
	if asked := p.dock.Last("blocked/delete"); asked.Params.Get("domain") != "tracker.example.org" {
		t.Errorf("removed with %v", asked.Params)
	}
	// an allowed entry removed: the name is blocked again, which the answer says
	p.dock.Then("allowed/delete", func(technitiumtest.Request) { p.dock.AnswerText("allowed/export", "") })
	p.dock.AnswerWhen("dnsClient/resolve", "domain", "good.ads.example.net", answerOf("source=blocked-zone; domain=ads.example.net", ""))
	if now := acctest.Object(t, suite.Call(t, "block_delete", map[string]any{"server": "dock", "name": "good.ads.example.net", "list": "allowed"})["now"], "now"); !acctest.BoolOf(now["blocked"]) || now["entry"] != "ads.example.net" || now["allowed"] != nil {
		t.Errorf("after its allowed entry went = %v", now)
	}
	// the server says it is gone and still lists it: an error
	p.dock.Then("blocked/delete", nil)
	if msg := suite.CallErr(t, "block_delete", map[string]any{"server": "dock", "name": "ads.example.net"}); !strings.Contains(msg, "the server took the removal and ads.example.net is still on the blocked list of dock") {
		t.Errorf("a removal that did not take = %q", msg)
	}
}

// On a cluster's secondary node a change goes to the primary and comes back
// a while later: the lists are read until it has.
func TestBlockSetOnASecondaryNode(t *testing.T) {
	t.Parallel()

	p := blockPair(t)
	p.rpi.Answer("admin/cluster/state", `{"clusterInitialized":true,"clusterDomain":"cluster.example","dnsServerDomain":"rpi.cluster.example","clusterNodes":[{"id":1,"name":"dock.cluster.example","type":"Primary","state":"Connected"},{"id":2,"name":"rpi.cluster.example","type":"Secondary","state":"Self"}]}`)
	suite := p.session(t, everything)

	// the list has the name the second time it is read after the change
	var reads atomic.Int32
	p.rpi.Then("blocked/add", func(technitiumtest.Request) { reads.Store(0) })
	p.rpi.Then("blocked/export", func(technitiumtest.Request) {
		if reads.Add(1) == 3 {
			p.rpi.AnswerText("blocked/export", "ads.example.net\nlate.example.net\n")
			p.rpi.AnswerWhen("dnsClient/resolve", "domain", "late.example.net", answerOf("source=blocked-zone; domain=late.example.net", ""))
		}
	})
	reads.Store(-1)
	out := suite.Call(t, "block_set", map[string]any{"server": "rpi", "name": "late.example.net"})
	if now := acctest.Object(t, out["now"], "now"); !acctest.BoolOf(now["blocked"]) || !strings.Contains(acctest.Str(out["note"]), "rpi is a secondary node of a cluster: the change went to the cluster's primary, and rpi has copied it back") {
		t.Errorf("a name blocked on a secondary node = %v", out)
	}
	if n := len(p.rpi.Requests("blocked/add")); n != 1 {
		t.Errorf("the name was added %d times", n)
	}
}
