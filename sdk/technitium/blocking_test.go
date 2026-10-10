package technitium_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

func TestBlockedAndAllowedNames(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	// a list comes as a text file, one name a line
	fake.AnswerText("blocked/export", "ads.example.net\ntracker.example.org\n\n")
	fake.AnswerText("allowed/export", "")
	for _, path := range []string{"blocked/add", "blocked/delete", "allowed/add", "allowed/delete"} {
		fake.Answer(path, `{}`)
	}
	c := client(t, fake)

	blocked, err := c.BlockedNames(t.Context())
	if err != nil || !slices.Equal(blocked, []string{"ads.example.net", "tracker.example.org"}) {
		t.Errorf("BlockedNames = %v, %v", blocked, err)
	}
	if allowed, err := c.AllowedNames(t.Context()); err != nil || len(allowed) != 0 {
		t.Errorf("AllowedNames = %v, %v, want none", allowed, err)
	}

	for path, call := range map[string]func(string) error{
		"blocked/add":    func(name string) error { return c.BlockName(t.Context(), name) },
		"blocked/delete": func(name string) error { return c.UnblockName(t.Context(), name) },
		"allowed/add":    func(name string) error { return c.AllowName(t.Context(), name) },
		"allowed/delete": func(name string) error { return c.UnallowName(t.Context(), name) },
	} {
		if err := call("ads.example.net"); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if asked := fake.Last(path); asked.Method != http.MethodPost || asked.Params.Get("domain") != "ads.example.net" {
			t.Errorf("%s was sent as a %s with %v", path, asked.Method, asked.Params)
		}
		// which name is asked before anything is sent
		if err := call(""); err == nil || len(fake.Requests(path)) != 1 {
			t.Errorf("%s with no name = %v, after %d requests", path, err, len(fake.Requests(path)))
		}
	}

	// a list the server will not give is refused in JSON, as every call is
	fake.Fail("blocked/export", "error", "Access was denied.")
	if _, err := c.BlockedNames(t.Context()); err == nil || !strings.Contains(err.Error(), "blocked/export: Access was denied.") {
		t.Errorf("a list refused = %v", err)
	}
	fake.Fail("allowed/export", "invalid-token", "Invalid token or session expired.")
	if _, err := c.AllowedNames(t.Context()); !technitium.IsInvalidToken(err) {
		t.Errorf("a list asked for with a token the server does not know = %v", err)
	}
	// and a server that says ok where the file belongs has sent none
	fake.Answer("blocked/export", `{}`)
	if _, err := c.BlockedNames(t.Context()); err == nil || !strings.Contains(err.Error(), "sent no file") {
		t.Errorf("ok and no file = %v", err)
	}
}

// A server that blocked a name says so in its answer, and by which list.
func TestResolveBlocked(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	c := client(t, fake)
	for answer, want := range map[string]*technitium.Block{
		// its own list of blocked names, as a 15.6 server answered
		`{"result":{"RCODE":"NxDomain","EDNS":{"UdpPayloadSize":1232,"Options":[{"Code":"EXTENDED_DNS_ERROR","Length":"55 bytes","Data":{"InfoCode":"Blocked","ExtraText":"source=blocked-zone; domain=ads.example.net"}}]},"Answer":[],"Authority":[]}}`: {Source: technitium.BlockedZone, Entry: "ads.example.net", Text: "source=blocked-zone; domain=ads.example.net"},
		// a list it fetches
		`{"result":{"RCODE":"NoError","EDNS":{"Options":[{"Code":"EXTENDED_DNS_ERROR","Data":{"InfoCode":"Blocked","ExtraText":"source=block-list-zone; blockListUrl=https://lists.example.org/ads.txt; domain=example.net"}}]},"Answer":[{"Name":"x.example.net","Type":"A","TTL":"30 (30s)","RDATA":{"IPAddress":"0.0.0.0"}}]}}`: {Source: technitium.BlockList, List: "https://lists.example.org/ads.txt", Entry: "example.net", Text: "source=block-list-zone; blockListUrl=https://lists.example.org/ads.txt; domain=example.net"},
		// another kind of extended error is not a block, and most answers carry none
		`{"result":{"RCODE":"ServerFailure","EDNS":{"Options":[{"Code":"EXTENDED_DNS_ERROR","Data":{"InfoCode":"DnssecBogus","ExtraText":"no"}}]}}}`: nil,
		`{"result":{"RCODE":"NxDomain","EDNS":{"Options":[]},"Answer":[]}}`:                                                                          nil,
	} {
		fake.Answer("dnsClient/resolve", answer)
		got, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "x.example.net"})
		if err != nil {
			t.Fatal(err)
		}
		if block := got.Blocked(); (block == nil) != (want == nil) || (want != nil && *block != *want) {
			t.Errorf("Blocked() = %+v, want %+v, for %s", block, want, answer)
		}
	}
}

func TestBlockingSwitches(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("settings/set", `{"enableBlocking":true,"blockingType":"NxDomain","blockListUrls":["https://lists.example.org/ads.txt","!https://lists.example.org/fine.txt"],"blockListUpdateIntervalHours":24}`)
	fake.Answer("settings/temporaryDisableBlocking", `{"temporaryDisableBlockingTill":"2026-10-10T01:14:27.1106773Z"}`)
	fake.Answer("settings/forceUpdateBlockLists", `{}`)
	c := client(t, fake)

	// each sends the one setting it is about, and nothing else to be reset by it
	got, err := c.SetBlocking(t.Context(), true)
	if err != nil || !got.EnableBlocking || len(got.BlockListURLs) != 2 {
		t.Errorf("SetBlocking = %+v, %v", got, err)
	}
	if asked := fake.Last("settings/set"); asked.Method != http.MethodPost || len(asked.Params) != 1 || asked.Params.Get("enableBlocking") != "true" {
		t.Errorf("blocking was switched on with %v", asked.Params)
	}
	if _, err := c.SetBlocking(t.Context(), false); err != nil || fake.Last("settings/set").Params.Get("enableBlocking") != "false" {
		t.Errorf("blocking was switched off with %v, %v", fake.Last("settings/set").Params, err)
	}

	if got, err = c.SetBlockLists(t.Context(), []string{"https://lists.example.org/ads.txt", "!https://lists.example.org/fine.txt"}); err != nil || got.BlockListUpdateIntervalHours != 24 {
		t.Errorf("SetBlockLists = %+v, %v", got, err)
	}
	if asked := fake.Last("settings/set"); len(asked.Params) != 1 || asked.Params.Get("blockListUrls") != "https://lists.example.org/ads.txt,!https://lists.example.org/fine.txt" {
		t.Errorf("the lists were set with %v", asked.Params)
	}
	// none is the API's own word for it, not a parameter left empty
	if _, err := c.SetBlockLists(t.Context(), nil); err != nil || fake.Last("settings/set").Params.Get("blockListUrls") != "false" {
		t.Errorf("the lists were cleared with %v, %v", fake.Last("settings/set").Params, err)
	}

	till, err := c.PauseBlocking(t.Context(), 5)
	if err != nil || till != "2026-10-10T01:14:27.1106773Z" || fake.Last("settings/temporaryDisableBlocking").Params.Get("minutes") != "5" {
		t.Errorf("PauseBlocking = %q, %v, asked with %v", till, err, fake.Last("settings/temporaryDisableBlocking").Params)
	}
	if _, err := c.PauseBlocking(t.Context(), 0); err == nil || len(fake.Requests("settings/temporaryDisableBlocking")) != 1 {
		t.Errorf("a pause of no minutes = %v, and was sent: %v", err, len(fake.Requests("settings/temporaryDisableBlocking")) != 1)
	}

	if err := c.UpdateBlockLists(t.Context()); err != nil || fake.Last("settings/forceUpdateBlockLists").Method != http.MethodPost {
		t.Errorf("UpdateBlockLists: %v", err)
	}
}
