//go:build acceptance

package technitium_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// A server's own lists of blocked and allowed names, and what being on one
// does to a name's answer, most of which the document does not say:
//
//   - a blocked name's answer says it was blocked and by which entry, in an
//     extended error, and a name under the entry is blocked with it
//   - an allowed name is not blocked, whatever blocks it
//   - a name the server's own zone holds is answered from the zone, blocked
//     or not
//   - a name under .test is answered by the server itself as one that does
//     not exist before any list is looked at, so no block shows on it
//   - a cluster's nodes share the two lists
//
// The names are under .example, which is nobody's: an allowed one is looked
// up outside and found not to exist.
func TestBlocking(t *testing.T) {
	t.Parallel()

	c := first(t)
	const entry, zoned = "ads.sdk-blocked.example", "sdk-blockzone.example"
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	t.Cleanup(func() {
		for _, name := range []string{entry, "held." + zoned, "ads.sdk-blocked.test"} {
			_ = c.UnblockName(ctx, name)
			_ = c.UnallowName(ctx, name)
		}
	})
	blocked := func(name string) *technitium.Block {
		t.Helper()
		answer, err := c.Resolve(ctx, technitium.ResolveQuery{Name: name})
		if err != nil {
			t.Fatal(err)
		}

		return answer.Blocked()
	}

	for _, name := range world.Names() {
		if _, err := server(t, name).BlockedNames(ctx); err != nil {
			t.Errorf("%s: BlockedNames: %v", name, err)
		}
		if _, err := server(t, name).AllowedNames(ctx); err != nil {
			t.Errorf("%s: AllowedNames: %v", name, err)
		}
	}

	// blocked: listed, and said in the answer for the name and for one under it
	if err := c.BlockName(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if err := c.BlockName(ctx, entry); err != nil {
		t.Errorf("blocking a name that is blocked = %v: the server said nothing of it when this was written", err)
	}
	if names, err := c.BlockedNames(ctx); err != nil || !slices.Contains(names, entry) {
		t.Errorf("BlockedNames = %v, %v, want %s among them", names, err, entry)
	}
	for _, name := range []string{entry, "x." + entry} {
		if got := blocked(name); got == nil || got.Source != technitium.BlockedZone || got.Entry != entry || got.List != "" {
			t.Errorf("%s is blocked by %+v, want the server's own entry %s: the server no longer says in its answer why it blocked a name, which dns_resolve and block_check read", name, got, entry)
		}
	}
	answer, err := c.Resolve(ctx, technitium.ResolveQuery{Name: entry})
	if err != nil || answer.RCode != "NxDomain" || len(answer.Answer) != 0 {
		t.Errorf("a blocked name's answer = %+v, %v, want that it does not exist, as a new server answers one", answer, err)
	}
	// asked for its TXT record, the server answers with why it is blocked
	if answer, err = c.Resolve(ctx, technitium.ResolveQuery{Name: entry, Type: "TXT"}); err != nil || len(answer.Answer) != 1 || answer.Answer[0].Value() != "source=blocked-zone; domain="+entry {
		t.Errorf("a blocked name's TXT = %+v, %v, want the server's word on why it is blocked", answer, err)
	}

	// a cluster's nodes share the list, a while after it changes; two servers on their own do not
	switch world.Topology {
	case testenv.Pair:
		if names, err := server(t, world.Second).BlockedNames(ctx); err != nil || slices.Contains(names, entry) {
			t.Errorf("%s, which knows nothing of %s, has its blocked names: %v, %v", world.Second, world.First, names, err)
		}
	case testenv.Cluster:
		second := server(t, world.Second)
		if !acctest.EventuallyWithin(2*time.Minute, func() bool {
			names, listErr := second.BlockedNames(ctx)

			return listErr == nil && slices.Contains(names, entry)
		}) {
			t.Errorf("%s never took the name blocked on %s: a cluster's nodes no longer share the list, which block_list says they do", world.Second, world.First)
		}
		// blocked on the second node, a name goes to the primary, which the
		// second then copies it back from: it is on the first at once, and on
		// the node that was asked a while later
		const viaSecond = "ads2.sdk-blocked.example"
		t.Cleanup(func() { _ = c.UnblockName(ctx, viaSecond) })
		if err := second.BlockName(ctx, viaSecond); err != nil {
			t.Fatal(err)
		}
		if names, err := c.BlockedNames(ctx); err != nil || !slices.Contains(names, viaSecond) {
			t.Errorf("a name blocked on %s is not on %s at once: %v, %v: a secondary node no longer sends the change to the primary, which block_set counts on", world.Second, world.First, names, err)
		}
		asked := time.Now()
		if !acctest.EventuallyWithin(2*time.Minute, func() bool {
			names, listErr := second.BlockedNames(ctx)

			return listErr == nil && slices.Contains(names, viaSecond)
		}) {
			t.Errorf("%s never had the name that was blocked on it", world.Second)
		}
		t.Logf("%s had the name it was asked to block %s after the primary did", world.Second, time.Since(asked).Round(time.Second))
	default:
	}

	// allowed as well: not blocked
	if err := c.AllowName(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if names, err := c.AllowedNames(ctx); err != nil || !slices.Contains(names, entry) {
		t.Errorf("AllowedNames = %v, %v, want %s among them", names, err, entry)
	}
	if got := blocked("x." + entry); got != nil {
		t.Errorf("a name both blocked and allowed is blocked by %+v: the allowed list no longer wins, which block_check says it does", got)
	}
	if err := c.UnallowName(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if got := blocked("x." + entry); got == nil {
		t.Error("a name taken off the allowed list is not blocked again")
	}

	// a name the server's own zone holds is answered from it, blocked or not
	zone(t, c, zoned)
	if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: zoned, Name: "held." + zoned, Type: "A", Data: technitium.RData{"ipAddress": "10.3.3.3"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.BlockName(ctx, "held."+zoned); err != nil {
		t.Fatal(err)
	}
	if answer, err = c.Resolve(ctx, technitium.ResolveQuery{Name: "held." + zoned}); err != nil || answer.Blocked() != nil || !answer.Authoritative || len(answer.Answer) != 1 || answer.Answer[0].Value() != "10.3.3.3" {
		t.Errorf("a blocked name the server's own zone holds = %+v, %v: the block now applies to it, and audit_blocking says such an entry does nothing", answer, err)
	}

	// a name under .test is the server's own to refuse, before any list
	if err := c.BlockName(ctx, "ads.sdk-blocked.test"); err != nil {
		t.Fatal(err)
	}
	if answer, err = c.Resolve(ctx, technitium.ResolveQuery{Name: "ads.sdk-blocked.test"}); err != nil || answer.Blocked() != nil || answer.RCode != "NxDomain" {
		t.Errorf("a blocked name under .test = %+v, %v: a block now shows on one, where the server used to answer for .test itself first", answer, err)
	}

	// taken off, and taken off again
	for range 2 {
		if err := c.UnblockName(ctx, entry); err != nil {
			t.Errorf("unblocking: %v", err)
		}
		if err := c.UnallowName(ctx, entry); err != nil {
			t.Errorf("unallowing: %v", err)
		}
	}
	if names, err := c.BlockedNames(ctx); err != nil || slices.Contains(names, entry) {
		t.Errorf("after it was taken off, BlockedNames = %v, %v", names, err)
	}
	if got := blocked(entry); got != nil {
		t.Errorf("a name taken off the list is still blocked: %+v", got)
	}
}

// blockingSettled waits for a cluster's second node to have blocking as a
// new server does - on, with no pause and no lists - once a test has put the
// first back so: the tests that follow read the second node's settings, which
// take a while to follow the first's.
func blockingSettled(ctx context.Context, t *testing.T) {
	t.Helper()

	if world.Topology != testenv.Cluster {
		return
	}
	second := server(t, world.Second)
	settled := func() bool {
		got, err := second.Settings(ctx)

		return err == nil && got.EnableBlocking && got.TemporaryDisableBlockingTill == "" && len(got.BlockListURLs) == 0
	}
	// the primary tells the second node of a change at once, but a word that was lost is not said again until the node's next fetch, a quarter of an hour away: a node that has not followed in a while is asked to fetch now
	if acctest.EventuallyWithin(30*time.Second, settled) {
		return
	}
	if err := second.ResyncCluster(ctx); err != nil {
		t.Logf("%s asked to fetch the configuration: %v", world.Second, err)
	}
	if !acctest.EventuallyWithin(2*time.Minute, settled) {
		t.Errorf("%s never took back the blocking settings %s was left with", world.Second, world.First)
	}
}

// Blocking switched off, paused and given lists to fetch: what each does to a
// blocked name's answer and to the settings, and that a cluster's nodes take
// each from the primary.
//
// It does not run beside the other tests: while blocking is off nothing they
// block is blocked.
//
//nolint:paralleltest // it switches the server's blocking off and on, under any test running beside it
func TestBlockingSwitched(t *testing.T) {
	c := first(t)
	const entry, list = "ads.sdk-switched.example", "http://127.0.0.1:9/sdk-no-such-list.txt"
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	t.Cleanup(func() {
		_, _ = c.SetBlocking(ctx, true)
		_, _ = c.SetBlockLists(ctx, nil)
		_ = c.UnblockName(ctx, entry)
		blockingSettled(ctx, t)
	})
	blocked := func() bool {
		t.Helper()
		answer, err := c.Resolve(ctx, technitium.ResolveQuery{Name: entry})
		if err != nil {
			t.Fatal(err)
		}

		return answer.Blocked() != nil
	}
	if err := c.BlockName(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if !blocked() {
		t.Fatal("a blocked name is not blocked before anything was switched")
	}

	// paused: off, with the time it comes back on
	till, err := c.PauseBlocking(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if back, ok := technitium.ParseTime(till); !ok || time.Until(back) < time.Minute || time.Until(back) > 3*time.Minute {
		t.Errorf("a pause of two minutes ends at %q", till)
	}
	got, err := c.Settings(ctx)
	if err != nil || got.TemporaryDisableBlockingTill != till || got.EnableBlocking {
		t.Errorf("the settings in a pause = blocking %v until %q, %v, want it off until %s: block_list tells a pause from off by the time alone", got.EnableBlocking, got.TemporaryDisableBlockingTill, err, till)
	}
	if blocked() {
		t.Error("a name is blocked while blocking is paused")
	}
	if world.Topology == testenv.Cluster && !acctest.EventuallyWithin(time.Minute, func() bool {
		second, readErr := server(t, world.Second).Settings(ctx)

		return readErr == nil && second.TemporaryDisableBlockingTill != ""
	}) {
		t.Errorf("%s never took the pause %s was given: a pause is no longer the whole cluster's", world.Second, world.First)
	}

	// switched on, the pause is over
	if got, err = c.SetBlocking(ctx, true); err != nil || !got.EnableBlocking || got.TemporaryDisableBlockingTill != "" {
		t.Errorf("switched on in a pause = blocking %v until %q, %v", got.EnableBlocking, got.TemporaryDisableBlockingTill, err)
	}
	if !blocked() {
		t.Error("a name is not blocked after blocking was switched back on")
	}
	// off, and on again. Switched off after a pause was ended, the server gives the pause's time again, though nothing is left to switch blocking back on: block_switch says so
	if got, err = c.SetBlocking(ctx, false); err != nil || got.EnableBlocking || blocked() {
		t.Errorf("switched off = blocking %v, %v, and the name blocked: %v", got.EnableBlocking, err, blocked())
	}
	if got.TemporaryDisableBlockingTill != till {
		t.Errorf("switched off after a pause was ended, the server gives %q for when the pause ends, where it gave the old time %s when this was written: block_switch need no longer explain it", got.TemporaryDisableBlockingTill, till)
	}
	if got, err = c.SetBlocking(ctx, true); err != nil || !got.EnableBlocking || got.BlockingType == "" || !got.DNSSECValidation {
		t.Errorf("switched on = %+v, %v: the one setting sent no longer leaves the rest as they were", got, err)
	}

	// a list to fetch, which there is nothing at: set, asked for, and holding no names
	if got, err = c.SetBlockLists(ctx, []string{list}); err != nil || !slices.Equal(got.BlockListURLs, []string{list}) || got.BlockListUpdateIntervalHours == 0 || !got.EnableBlocking {
		t.Errorf("SetBlockLists = %v every %dh, %v", got.BlockListURLs, got.BlockListUpdateIntervalHours, err)
	}
	if err := c.UpdateBlockLists(ctx); err != nil {
		t.Errorf("UpdateBlockLists: %v", err)
	}
	// a list not fetched since it was set, or since a fetch was asked for, is due at the server's "never" and a day: a time that is none
	if got, err = c.Settings(ctx); err != nil || got.BlockListNextUpdatedOn == "" {
		t.Errorf("with a list set, the next fetch is at %q, %v", got.BlockListNextUpdatedOn, err)
	} else if due, ok := technitium.ParseTime(got.BlockListNextUpdatedOn); ok {
		t.Errorf("a list that cannot be fetched is next due at %s: the server no longer gives its never for it, by which block_list and audit_blocking tell lists that have not been fetched", due)
	}
	if stats, err := c.Stats(ctx, technitium.StatsWindow{}); err != nil || stats.Totals.BlockListZones != 0 {
		t.Errorf("a list that cannot be fetched holds %d names, %v", stats.Totals.BlockListZones, err)
	}
	if got, err = c.SetBlockLists(ctx, nil); err != nil || len(got.BlockListURLs) != 0 {
		t.Errorf("the lists cleared = %v, %v", got.BlockListURLs, err)
	}
}
