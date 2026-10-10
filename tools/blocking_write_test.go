package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// Blocking is switched on and off and paused, each read back.
func TestBlockSwitch(t *testing.T) {
	t.Parallel()

	p := blockPair(t)
	p.both("settings/set", blockingOnSettings)
	p.both("settings/temporaryDisableBlocking", `{"temporaryDisableBlockingTill":"2099-01-01T00:05:00Z"}`)
	suite := p.session(t, everything)
	writes := func() int {
		return len(p.dock.Requests("settings/set")) + len(p.dock.Requests("settings/temporaryDisableBlocking"))
	}

	// on already: nothing to do
	if same := suite.Call(t, "block_switch", map[string]any{"server": "dock", "to": "On"}); acctest.BoolOf(same["changed"]) || writes() != 0 || acctest.Object(t, same["after"], "after")["blocking"] != "on" {
		t.Errorf("blocking that is on, switched on = %v", same)
	}
	dry := suite.Call(t, "block_switch", map[string]any{"server": "dock", "to": "paused", "minutes": 5, "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have paused blocking on dock for 5 minutes: nothing is blocked till then"}) || writes() != 0 || dry["after"] != nil {
		t.Errorf("a dry run = %v", dry)
	}

	// paused, with when it ends
	p.dock.Then("settings/temporaryDisableBlocking", func(technitiumtest.Request) {
		p.dock.Answer("settings/get", `{"enableBlocking":false,"blockingType":"NxDomain","temporaryDisableBlockingTill":"2099-01-01T00:05:00Z"}`)
	})
	out := suite.Call(t, "block_switch", map[string]any{"server": "dock", "to": "pause", "minutes": 5})
	if before, after := acctest.Object(t, out["before"], "before"), acctest.Object(t, out["after"], "after"); before["blocking"] != "on" || after["blocking"] != "paused" || after["paused_until"] != "2099-01-01T00:05:00Z" || p.dock.Last("settings/temporaryDisableBlocking").Params.Get("minutes") != "5" || out["note"] != nil {
		t.Errorf("paused = %v", out)
	}
	// switched on, the pause is over; and off
	p.dock.Then("settings/set", func(req technitiumtest.Request) {
		p.dock.Answer("settings/get", `{"enableBlocking":`+req.Params.Get("enableBlocking")+`,"blockingType":"NxDomain"}`)
	})
	if on := suite.Call(t, "block_switch", map[string]any{"server": "dock", "to": "on"}); acctest.Object(t, on["before"], "before")["blocking"] != "paused" || acctest.Object(t, on["after"], "after")["blocking"] != "on" || p.dock.Last("settings/set").Params.Get("enableBlocking") != "true" || len(p.dock.Last("settings/set").Params) != 1 {
		t.Errorf("switched on in a pause = %v, sent %v", on, p.dock.Last("settings/set").Params)
	}
	if off := suite.Call(t, "block_switch", map[string]any{"server": "dock", "to": "off"}); acctest.Object(t, off["after"], "after")["blocking"] != "off" || !slices.Equal(acctest.Strs(t, off["changes"], "changes"), []string{"switched blocking off on dock"}) {
		t.Errorf("switched off = %v", off)
	}

	// switched off in a pause: the server would leave the pause running and switch blocking back on when it ended, so the pause is ended first
	p.dock.Answer("settings/get", `{"enableBlocking":false,"blockingType":"NxDomain","temporaryDisableBlockingTill":"2099-01-01T00:05:00Z"}`)
	sent := len(p.dock.Requests("settings/set"))
	// off again, the server goes on giving the time the pause would have ended: that is said, and is not a pause
	p.dock.Then("settings/set", func(req technitiumtest.Request) {
		p.dock.Answer("settings/get", `{"enableBlocking":`+req.Params.Get("enableBlocking")+`,"blockingType":"NxDomain","temporaryDisableBlockingTill":"2099-01-01T00:05:00Z"}`)
	})
	forGood := suite.Call(t, "block_switch", map[string]any{"server": "dock", "to": "off"})
	if got, after := acctest.Strs(t, forGood["changes"], "changes"), acctest.Object(t, forGood["after"], "after"); !slices.Equal(got, []string{"ended the pause on dock, which would have switched blocking back on at 2099-01-01T00:05:00Z", "switched blocking off on dock"}) || after["blocking"] != "off" || after["paused_until"] != nil || !strings.Contains(acctest.Str(forGood["note"]), "the server goes on showing 2099-01-01T00:05:00Z, when the pause would have ended") {
		t.Errorf("switched off in a pause = %v", forGood)
	}
	if reqs := p.dock.Requests("settings/set")[sent:]; len(reqs) != 2 || reqs[0].Params.Get("enableBlocking") != "true" || reqs[1].Params.Get("enableBlocking") != "false" {
		t.Errorf("switched off in a pause with %v", reqs)
	}

	// the server says ok and blocking stands as it did: an error
	p.dock.Then("settings/set", nil)
	if msg := suite.CallErr(t, "block_switch", map[string]any{"server": "dock", "to": "on"}); !strings.Contains(msg, "the server took the change and blocking on dock is paused, not on") {
		t.Errorf("a switch that did not take = %q", msg)
	}
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"a state there is none of": {map[string]any{"to": "maybe"}, "it takes on, off or paused"},
		"a pause of no length":     {map[string]any{"to": "paused"}, "a pause is for 1 to 1440 minutes"},
		"a pause of a week":        {map[string]any{"to": "paused", "minutes": 10080}, "a pause is for 1 to 1440 minutes"},
		"minutes for a switch":     {map[string]any{"to": "off", "minutes": 5}, "minutes is how long a pause lasts"},
	} {
		refused.args["server"] = "dock"
		if msg := suite.CallErr(t, "block_switch", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
}

// The lists a server fetches are set whole, or one at a time, and fetched
// when asked.
func TestBlockListsSet(t *testing.T) {
	t.Parallel()

	p := blockPair(t)
	p.both("settings/set", blockingOnSettings)
	p.both("settings/forceUpdateBlockLists", `{}`)
	suite := p.session(t, everything)
	const had, more = "https://lists.example.org/ads.txt", "!https://lists.example.org/fine.txt"
	fetches := func(lists ...string) {
		p.dock.Answer("settings/get", `{"enableBlocking":true,"blockingType":"NxDomain","blockListUrls":["`+strings.Join(lists, `","`)+`"],"blockListUpdateIntervalHours":24,"blockListNextUpdatedOn":"0001-01-02T00:00:00"}`)
	}

	dry := suite.Call(t, "block_lists_set", map[string]any{"server": "dock", "add": []string{more}, "fetch": true, "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have added the list " + more + " to those dock fetches", "would have asked dock to fetch its lists now"}) || len(p.dock.Requests("settings/set")) != 0 || len(p.dock.Requests("settings/forceUpdateBlockLists")) != 0 || dry["after"] != nil {
		t.Errorf("a dry run = %v", dry)
	}

	// one added, and fetched
	p.dock.Then("settings/set", func(technitiumtest.Request) { fetches(had, more) })
	out := suite.Call(t, "block_lists_set", map[string]any{"server": "dock", "add": []string{more, had}, "fetch": true})
	if !acctest.BoolOf(out["changed"]) || !slices.Equal(acctest.Strs(t, out["before"], "before"), []string{had}) || len(acctest.Strs(t, out["changes"], "changes")) != 2 || p.dock.Last("settings/set").Params.Get("blockListUrls") != had+","+more || len(p.dock.Requests("settings/forceUpdateBlockLists")) != 1 {
		t.Errorf("one added = %v, sent %v", out, p.dock.Last("settings/set").Params)
	}
	if after := acctest.Object(t, out["after"], "after"); !slices.Equal(acctest.Texts(after["lists"]), []string{had, more}) || acctest.Num(t, after["list_names"], "list_names") != 307447 || !strings.Contains(acctest.Str(after["note"]), "the lists have not been fetched since they were set") {
		t.Errorf("how blocking stands after = %v", after)
	}
	// fetched alone: the set is not sent again
	if again := suite.Call(t, "block_lists_set", map[string]any{"server": "dock", "fetch": true}); !slices.Equal(acctest.Strs(t, again["changes"], "changes"), []string{"asked dock to fetch its lists now"}) || len(p.dock.Requests("settings/set")) != 1 || len(p.dock.Requests("settings/forceUpdateBlockLists")) != 2 {
		t.Errorf("fetched alone = %v", again)
	}
	// one taken off; and the whole set replaced, an empty one clearing it
	p.dock.Then("settings/set", func(technitiumtest.Request) { fetches(more) })
	if off := suite.Call(t, "block_lists_set", map[string]any{"server": "dock", "remove": []string{had}}); !slices.Equal(acctest.Strs(t, off["changes"], "changes"), []string{"removed the list " + had + " from those dock fetches"}) || p.dock.Last("settings/set").Params.Get("blockListUrls") != more {
		t.Errorf("one taken off = %v", off)
	}
	p.dock.Then("settings/set", func(technitiumtest.Request) {
		p.dock.Answer("settings/get", `{"enableBlocking":true,"blockingType":"NxDomain","blockListUrls":null}`)
	})
	none := suite.Call(t, "block_lists_set", map[string]any{"server": "dock", "lists": []string{}, "fetch": true})
	if p.dock.Last("settings/set").Params.Get("blockListUrls") != "false" || acctest.Object(t, none["after"], "after")["lists"] != nil || !strings.Contains(acctest.Str(none["note"]), "there are no lists to fetch") || len(p.dock.Requests("settings/forceUpdateBlockLists")) != 2 {
		t.Errorf("the set cleared = %v, sent %v", none, p.dock.Last("settings/set").Params)
	}

	sent := len(p.dock.Requests("settings/set"))
	for what, refused := range map[string]struct {
		args map[string]any
		with string
	}{
		"a list that is not fetched": {map[string]any{"remove": []string{had}}, "dock fetches no list at " + had + ": it fetches none"},
		"no address":                 {map[string]any{"add": []string{"ads.txt"}}, `"ads.txt" is no list's address`},
		"two addresses in one":       {map[string]any{"add": []string{"https://a.example/x,https://b.example/y"}}, "is no list's address"},
		"both the set and a change":  {map[string]any{"lists": []string{had}, "add": []string{more}}, "not both"},
		"nothing to do":              {map[string]any{}, "what to do"},
	} {
		refused.args["server"] = "dock"
		if msg := suite.CallErr(t, "block_lists_set", refused.args); !strings.Contains(msg, refused.with) {
			t.Errorf("%s = %q, want %q", what, msg, refused.with)
		}
	}
	if len(p.dock.Requests("settings/set")) != sent {
		t.Errorf("%d refused changes reached the server", len(p.dock.Requests("settings/set"))-sent)
	}
}
