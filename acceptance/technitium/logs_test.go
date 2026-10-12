//go:build acceptance

package technitium_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// logApp is the app .scripts/testenv.sh gives each server: the one that keeps
// a log of queries that can be searched.
const logApp = "Query Logs (Sqlite)"

// A server's log of queries, as the app that keeps it gives it: queries put
// to the server's DNS port - here by the server itself - are in it at once,
// each with who asked, for what, how it was answered and with what, and the
// log is searched by each of those. A name is matched whole, with a * for
// any run of characters.
func TestQueryLog(t *testing.T) {
	t.Parallel()

	ready(t)
	// every server has the app, which says which of its parts keeps the log and how much it keeps
	for _, name := range world.Names() {
		c := server(t, name)
		apps, err := c.Apps(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(apps, func(app technitium.App) bool { return app.Name == logApp })
		if i < 0 {
			t.Fatalf("%s has no %s among %+v: .scripts/testenv.sh installs it", name, logApp, apps)
		}
		if class, ok := apps[i].QueryLog(); !ok || class == "" {
			t.Errorf("%s: the log app's log = %q, %v", name, class, ok)
		}
		if config, err := c.AppConfig(t.Context(), logApp); err != nil || !strings.Contains(config, `"enableLogging": true`) || !strings.Contains(config, `"maxLogDays"`) || !strings.Contains(config, `"maxLogRecords"`) {
			t.Errorf("%s: AppConfig = %q, %v: the app's configuration no longer says what log_search reads it for", name, config, err)
		}
	}

	c := first(t)
	// the log outlives the zone and the run: a name of this run's own, so that what an earlier one asked is not counted with it
	z := fmt.Sprintf("sdk-logs-%d.test", time.Now().UnixNano()%1_000_000_000)
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	zone(t, c, z)
	for _, rec := range []technitium.NewRecord{{Zone: z, Name: "a." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.4.4.5"}}, {Zone: z, Name: "c." + z, Type: "CNAME", Data: technitium.RData{"cname": "a." + z}}} {
		if _, err := c.AddRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	apps, err := c.Apps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	class, _ := apps[slices.IndexFunc(apps, func(app technitium.App) bool { return app.Name == logApp })].QueryLog()
	search := func(q technitium.LogQuery) *technitium.LogPage {
		t.Helper()
		q.App, q.ClassPath = logApp, class
		page, err := c.QueryLog(ctx, q)
		if err != nil {
			t.Fatal(err)
		}

		return page
	}

	before := time.Now().Add(-time.Minute)
	for _, ask := range [][2]string{{"a." + z, "A"}, {"a." + z, "AAAA"}, {"c." + z, "A"}, {"nothing." + z, "A"}} {
		if _, err := c.Resolve(ctx, technitium.ResolveQuery{Via: "127.0.0.1", Name: ask[0], Type: ask[1]}); err != nil {
			t.Fatal(err)
		}
	}
	// the app writes what it is given a moment after
	var all *technitium.LogPage
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		all = search(technitium.LogQuery{Name: "*." + z, OldestFirst: true, PerPage: 50})

		return all.TotalEntries >= 4
	}) {
		t.Fatalf("the queries never showed in the log: %+v", all)
	}
	if all.TotalEntries != 4 || len(all.Entries) != 4 || all.PageNumber != 1 || all.TotalPages != 1 {
		t.Fatalf("the log of %s = %+v, want the four queries", z, all)
	}
	// in the order asked, the oldest first
	if e := all.Entries[0]; e.Name != "a."+z || e.Type != "A" || e.Class != "IN" || e.Client != "127.0.0.1" || e.Protocol != "Udp" || e.ResponseType != "Authoritative" || e.RCode != "NoError" || e.Answer != "A 10.4.4.5" || e.ResponseRTT != nil {
		t.Errorf("the first entry = %+v", e)
	}
	// the servers' clock is not this machine's to the second
	if at, ok := technitium.ParseTime(all.Entries[0].Timestamp); !ok || time.Since(at) > time.Hour || time.Since(at) < -time.Hour {
		t.Errorf("an entry's time = %q, want just now in a form ParseTime reads", all.Entries[0].Timestamp)
	}
	if e := all.Entries[1]; e.Type != "AAAA" || e.RCode != "NoError" || e.Answer != "" {
		t.Errorf("a name with no record of the type asked for = %+v", e)
	}
	if e := all.Entries[2]; e.Name != "c."+z || e.Answer != "CNAME a."+z+"., A 10.4.4.5" {
		t.Errorf("a chain = %+v", e)
	}
	if e := all.Entries[3]; e.Name != "nothing."+z || e.RCode != "NxDomain" || e.Answer != "" {
		t.Errorf("a name that does not exist = %+v", e)
	}

	// each filter, and the newest first without OldestFirst
	if newest := search(technitium.LogQuery{Name: "*." + z}); len(newest.Entries) != 4 || newest.Entries[0].Name != "nothing."+z {
		t.Errorf("the newest first = %+v", newest.Entries)
	}
	for what, want := range map[string]struct {
		q technitium.LogQuery
		n int
	}{
		"a name exactly, whatever its case":     {technitium.LogQuery{Name: "A." + strings.ToUpper(z)}, 2},
		"a name that is part of one, with no *": {technitium.LogQuery{Name: z}, 0},
		"a * within a name":                     {technitium.LogQuery{Name: "*thing." + z}, 1},
		"a ?, which is no wildcard":             {technitium.LogQuery{Name: "?." + z}, 0},
		"names that do not exist":               {technitium.LogQuery{Name: "*." + z, RCode: "NxDomain"}, 1},
		"one type":                              {technitium.LogQuery{Name: "*." + z, Type: "AAAA"}, 1},
		"one client":                            {technitium.LogQuery{Name: "*." + z, Client: "127.0.0.1"}, 4},
		"another client":                        {technitium.LogQuery{Name: "*." + z, Client: "10.250.250.250"}, 0},
		"from the server's own zones":           {technitium.LogQuery{Name: "*." + z, ResponseType: "Authoritative"}, 4},
		"from its cache":                        {technitium.LogQuery{Name: "*." + z, ResponseType: "Cached"}, 0},
		"over UDP":                              {technitium.LogQuery{Name: "*." + z, Protocol: "Udp"}, 4},
		"over TCP":                              {technitium.LogQuery{Name: "*." + z, Protocol: "Tcp"}, 0},
		"since a minute before they were asked": {technitium.LogQuery{Name: "*." + z, Start: before}, 4},
		"until a minute before they were asked": {technitium.LogQuery{Name: "*." + z, End: before}, 0},
		"since a time that has not come":        {technitium.LogQuery{Name: "*." + z, Start: time.Now().Add(time.Hour)}, 0},
	} {
		if got := search(want.q); got.TotalEntries != want.n {
			t.Errorf("%s matched %d entries, want %d: %+v", what, got.TotalEntries, want.n, got.Entries)
		}
	}

	// a page at a time
	if page := search(technitium.LogQuery{Name: "*." + z, OldestFirst: true, PerPage: 3, Page: 2}); page.PageNumber != 2 || page.TotalPages != 2 || page.TotalEntries != 4 || len(page.Entries) != 1 || page.Entries[0].Name != "nothing."+z {
		t.Errorf("the second page of three = %+v", page)
	}

	// what the server refuses
	if _, err := c.QueryLog(ctx, technitium.LogQuery{App: "sdk-no-such-app", ClassPath: class}); err == nil || !strings.Contains(err.Error(), "DNS application was not found") {
		t.Errorf("the log of an app that is not installed = %v", err)
	}
	if _, err := c.QueryLog(ctx, technitium.LogQuery{App: logApp, ClassPath: class, RCode: "Nonsense"}); err == nil || !strings.Contains(err.Error(), "Requested value") {
		t.Errorf("a response code there is none of = %v", err)
	}
	if _, err := c.QueryLog(ctx, technitium.LogQuery{App: logApp, ClassPath: class, Client: "10.0.0.0/24"}); err == nil {
		t.Error("a network for a client was searched by: the log takes one address, and log_search says so")
	}
	if _, err := c.AppConfig(ctx, "sdk-no-such-app"); err == nil {
		t.Error("the configuration of an app that is not installed was given")
	}
}
