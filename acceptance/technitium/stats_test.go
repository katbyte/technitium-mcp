//go:build acceptance

package technitium_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// What a server counts: queries put to its DNS port - here by the server
// itself, asked to resolve through its own address - show in its statistics
// once the minute they came in is over, by how they were answered, by who
// asked, and by name.
func TestStats(t *testing.T) {
	t.Parallel()

	ready(t)
	for _, name := range world.Names() {
		got, err := server(t, name).Stats(t.Context(), technitium.StatsWindow{})
		if err != nil || got.Totals.Queries < 0 || got.TopClients == nil && got.Totals.Queries > 0 {
			t.Errorf("%s: Stats = %+v, %v", name, got, err)
		}
	}

	c := first(t)
	const z, blocked = "sdk-stats.test", "ads.sdk-stats.example"
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	zone(t, c, z)
	if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: z, Name: "asked." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.4.4.4"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.BlockName(ctx, blocked); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.UnblockName(ctx, blocked) })
	for _, name := range []string{"asked." + z, "asked." + z, "asked." + z, "nothing." + z, blocked} {
		if _, err := c.Resolve(ctx, technitium.ResolveQuery{Via: "127.0.0.1", Name: name}); err != nil {
			t.Fatal(err)
		}
	}

	// the server counts by the minute, and a minute is in its totals once it is over
	hits := func(list []technitium.TopDomain, name string) int {
		if i := slices.IndexFunc(list, func(d technitium.TopDomain) bool { return d.Name == name }); i >= 0 {
			return list[i].Hits
		}

		return 0
	}
	var got *technitium.Stats
	if !acctest.EventuallyWithin(2*time.Minute, func() bool {
		var err error
		got, err = c.Stats(ctx, technitium.StatsWindow{Type: technitium.StatsLastHour})

		return err == nil && hits(got.TopDomains, "asked."+z) >= 3 && hits(got.TopBlockedDomains, blocked) >= 1
	}) {
		t.Fatalf("the queries never showed in the server's statistics: %+v", got)
	}
	// the names asked for most are of those answered: one that does not exist is in neither list
	if hits(got.TopDomains, "nothing."+z) != 0 || hits(got.TopBlockedDomains, "nothing."+z) != 0 || hits(got.TopDomains, blocked) != 0 {
		t.Errorf("the names asked for most = %+v, and the blocked ones %+v: a name that does not exist, or a blocked one, is now among those answered, which server_stats says they are not", got.TopDomains, got.TopBlockedDomains)
	}
	if n := got.Totals; n.Queries < 4 || n.NoError < 3 || n.NxDomain < 1 || n.Authoritative < 3 || n.Blocked < 1 || n.Clients < 1 || n.Zones < 1 || n.BlockedZones < 1 || n.NoError+n.NxDomain+n.ServerFailure+n.Refused > n.Queries {
		t.Errorf("Totals = %+v", n)
	}
	if i := slices.IndexFunc(got.TopClients, func(cl technitium.TopClient) bool { return cl.Name == "127.0.0.1" }); i < 0 || got.TopClients[i].Hits < 4 || got.TopClients[i].Domain != "localhost" || got.TopClients[i].RateLimited {
		t.Errorf("TopClients = %+v, want the server itself, which asked", got.TopClients)
	}
	if types, protocols := got.QueryTypes(), got.Protocols(); types["A"] < 4 || protocols["Udp"] < 4 {
		t.Errorf("by type = %v, by protocol = %v", types, protocols)
	}

	// a list to a length, and the longer windows, which hold the hour
	top, err := c.TopStats(ctx, technitium.StatsWindow{Type: technitium.StatsLastHour}, technitium.TopDomains, 1)
	if err != nil || len(top.TopDomains) != 1 || top.TopDomains[0].Hits < 3 {
		t.Errorf("the one name asked for most = %+v, %v", top, err)
	}
	if list, err := c.TopStats(ctx, technitium.StatsWindow{}, technitium.TopBlockedDomains, 50); err != nil || hits(list.TopBlockedDomains, blocked) < 1 {
		t.Errorf("the blocked names asked for = %+v, %v", list, err)
	}
	// the longer windows are counted by the hour and the day: when this was
	// written the hour in progress was in none of them, so what was asked a
	// minute ago is in the hour's count alone, which server_stats says
	for _, window := range []string{technitium.StatsLastDay, technitium.StatsLastWeek, technitium.StatsLastMonth, technitium.StatsLastYear} {
		if longer, err := c.Stats(ctx, technitium.StatsWindow{Type: window}); err != nil || longer.Totals.Zones < 1 {
			t.Errorf("%s = %+v, %v", window, longer, err)
		}
	}
	if _, err := c.TopStats(ctx, technitium.StatsWindow{Type: technitium.StatsLastDay}, technitium.TopClients, 5); err != nil {
		t.Errorf("the day's clients: %v", err)
	}
	// a window of one's own is counted in whole days, today among them
	if own, err := c.Stats(ctx, technitium.StatsWindow{Start: time.Now().Add(-24 * time.Hour), End: time.Now().Add(24 * time.Hour)}); err != nil || own.Totals.Queries < 4 {
		t.Errorf("a window of one's own = %+v, %v", own, err)
	}
	if _, err := c.Stats(ctx, technitium.StatsWindow{Type: "LastDecade"}); err == nil {
		t.Error("a window the server keeps none of was answered")
	}
}
