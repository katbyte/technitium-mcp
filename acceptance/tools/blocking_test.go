//go:build acceptance

package tools_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// The blocking fixtures, on the first server: a name it blocks, a name under
// that one it allows all the same, and a blocked name that its own zone
// answers for, which is the mistake the audit is there to find. The names
// are under .example, which is nobody's: a server answers for .test itself
// before it looks at any list, so nothing under .test can be seen blocked.
const (
	blockedName = "ads.acc-blocked.example"
	allowedName = "good." + blockedName
	heldName    = "emby.van." + sharedZone
	// the names the test of the changes puts on the lists and takes off again
	changedName = "tmp.acc-changed.example"
	viaSecond   = "tmp2.acc-changed.example"
)

// askedTimes is how often the fixtures ask the first server for one of its
// own names through its DNS port, and how often for the blocked one: what
// its statistics then have to show.
const askedTimes = 3

// makeBlocking puts the fixtures on the first server's lists, and asks it
// for a name of its own and for a blocked one as a client does, through its
// DNS port, so its statistics have something in them by the time they are
// read. In a cluster the second node has the lists once it has copied them.
func makeBlocking(ctx context.Context, first *technitium.Client) error {
	for _, name := range []string{blockedName, heldName} {
		if err := first.BlockName(ctx, name); err != nil {
			return fmt.Errorf("%s: blocking %s: %w", world.First, name, err)
		}
	}
	if err := first.AllowName(ctx, allowedName); err != nil {
		return fmt.Errorf("%s: allowing %s: %w", world.First, allowedName, err)
	}
	for range askedTimes {
		if _, err := first.Resolve(ctx, technitium.ResolveQuery{Via: "127.0.0.1", Name: heldName}); err != nil {
			return fmt.Errorf("%s: asking for %s: %w", world.First, heldName, err)
		}
	}
	if _, err := first.Resolve(ctx, technitium.ResolveQuery{Via: "127.0.0.1", Name: "x." + blockedName}); err != nil {
		return fmt.Errorf("%s: asking for a blocked name: %w", world.First, err)
	}
	if !clustered() {
		return nil
	}

	second, err := world.Client(world.Second)
	if err != nil {
		return err
	}
	if !acctest.EventuallyWithin(2*time.Minute, func() bool {
		blocked, blockedErr := second.BlockedNames(ctx)
		allowed, allowedErr := second.AllowedNames(ctx)

		return blockedErr == nil && allowedErr == nil && slices.Contains(blocked, blockedName) && slices.Contains(blocked, heldName) && slices.Contains(allowed, allowedName)
	}) {
		return fmt.Errorf("the cluster never gave %s the names blocked on %s", world.Second, world.First)
	}

	return nil
}

// removeBlocking takes the suite's names off every server's lists, and
// leaves blocking on with no lists to fetch, as a new server has it.
func removeBlocking(ctx context.Context) error {
	var errs []error
	for _, srv := range world.Set.Every() {
		for _, name := range []string{blockedName, heldName, allowedName, changedName, viaSecond} {
			errs = append(errs, srv.Client.UnblockName(ctx, name), srv.Client.UnallowName(ctx, name))
		}
		if _, err := srv.Client.SetBlocking(ctx, true); err != nil {
			errs = append(errs, err)
		}
		if _, err := srv.Client.SetBlockLists(ctx, nil); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// check is block_check's verdict for one name on one server.
func check(t *testing.T, checks []map[string]any, name, server string) map[string]any {
	t.Helper()

	for _, c := range checks {
		if c["name"] == name && c["server"] == server {
			if c["error"] != nil {
				t.Fatalf("%s could not be asked for %s: %v", server, name, c["error"])
			}

			return c
		}
	}
	t.Fatalf("no check of %s on %s among %v", name, server, checks)

	return nil
}

// What the servers block: a name is said to be blocked and by which entry,
// an allowed one and one a zone answers for are said not to be and why, the
// lists are set side by side, the audit finds the entry that does nothing
// and, of servers on their own, that they do not block alike; and then a
// name is put on a list and taken off, on the first server and in a cluster
// on its second node, which sends the change to the first.
func TestBlocking(t *testing.T) {
	t.Parallel()

	servers := names(t)
	out := suite.Call(t, "block_check", map[string]any{"names": []string{"x." + blockedName, allowedName, heldName}})
	checks := acctest.Rows(t, out["checks"], "checks")
	if len(checks) != 3*len(servers) || out["failed"] != nil {
		t.Fatalf("checks = %v", checks)
	}

	// the servers that have the lists: the first, and in a cluster the second with it
	listed := []string{world.First}
	if clustered() {
		listed = servers
	}
	for _, server := range listed {
		if c := check(t, checks, "x."+blockedName, server); !acctest.BoolOf(c["blocked"]) || c["by"] != "own_list" || c["entry"] != blockedName || c["list"] != nil || c["why"] != nil || c["answer"] != "NxDomain" {
			t.Errorf("a name under a blocked one, on %s = %v", server, c)
		}
		if c := check(t, checks, allowedName, server); acctest.BoolOf(c["blocked"]) || c["allowed"] != allowedName || c["listed"] != blockedName || c["why"] != "the allowed entry "+allowedName+" wins over it" {
			t.Errorf("the allowed name on %s = %v", server, c)
		}
		if c := check(t, checks, heldName, server); acctest.BoolOf(c["blocked"]) || c["listed"] != heldName || c["why"] != server+" answers the name from its own zone "+sharedZone+", and no list is looked at for a name a zone here holds" || c["answer"] != "NoError 10.0.0.4" {
			t.Errorf("the blocked name a zone answers for, on %s = %v", server, c)
		}
	}
	if world.Topology == testenv.Pair {
		for _, name := range []string{"x." + blockedName, allowedName, heldName} {
			if c := check(t, checks, name, world.Second); acctest.BoolOf(c["blocked"]) || c["listed"] != nil || c["allowed"] != nil || c["why"] != nil {
				t.Errorf("%s on %s, which has no lists = %v", name, world.Second, c)
			}
		}
	}

	// dns_resolve says the same of a name it is asked to resolve
	resolved := suite.Call(t, "dns_resolve", map[string]any{"name": "x." + blockedName})
	rows := acctest.Rows(t, resolved["answers"], "answers")
	if first := rowFor(t, rows, "server", world.First); first["blocked"] != "by its own list of blocked names: the entry "+blockedName || first["result"] != "NxDomain" {
		t.Errorf("the blocked name resolved on %s = %v", world.First, first)
	}
	if world.Topology == testenv.Pair && (rowFor(t, rows, "server", world.Second)["blocked"] != nil || !acctest.BoolOf(resolved["differ"])) {
		t.Errorf("the blocked name resolved on two servers of which one blocks it = %v", resolved)
	}

	// the lists, side by side. In a cluster the second node takes the primary's lists when it is told of a change or next fetches the configuration: one that has not followed in a while is asked to fetch now
	if clustered() {
		first, second := mustClient(t, world.First), mustClient(t, world.Second)
		ctx := t.Context()
		together := func() bool {
			blocked1, err1 := first.BlockedNames(ctx)
			blocked2, err2 := second.BlockedNames(ctx)
			allowed1, err3 := first.AllowedNames(ctx)
			allowed2, err4 := second.AllowedNames(ctx)
			for _, names := range [][]string{blocked1, blocked2, allowed1, allowed2} {
				slices.Sort(names)
			}

			return errors.Join(err1, err2, err3, err4) == nil && slices.Equal(blocked1, blocked2) && slices.Equal(allowed1, allowed2)
		}
		if !acctest.EventuallyWithin(30*time.Second, together) {
			if err := second.ResyncCluster(ctx); err != nil {
				t.Logf("%s asked to fetch the configuration: %v", world.Second, err)
			}
			if !acctest.EventuallyWithin(2*time.Minute, together) {
				t.Errorf("%s never took the lists %s has", world.Second, world.First)
			}
		}
	}
	lists := suite.Call(t, "block_list", map[string]any{"find": "acc"})
	for _, row := range acctest.Rows(t, lists["servers"], "servers") {
		if row["blocking"] != "on" || row["answers"] != "NxDomain" || row["lists"] != nil || row["error"] != nil {
			t.Errorf("how %s blocks = %v", row["server"], row)
		}
		want := 0
		if slices.Contains(listed, acctest.Str(row["server"])) {
			want = 2
		}
		if acctest.Num(t, row["blocked"], "blocked") < want || acctest.Num(t, row["allowed"], "allowed") < want/2 {
			t.Errorf("%s has %v names blocked and %v allowed, want %d and %d of the suite's", row["server"], row["blocked"], row["allowed"], want, want/2)
		}
	}
	entries := acctest.Rows(t, lists["entries"], "entries")
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, acctest.Str(e["name"])+" "+acctest.Str(e["list"])+" "+strings.Join(acctest.Texts(e["only_on"]), ","))
	}
	alone := ""
	if world.Topology == testenv.Pair {
		alone = world.First
	}
	if want := []string{blockedName + " blocked " + alone, allowedName + " allowed " + alone, heldName + " blocked " + alone}; !slices.Equal(got, want) {
		t.Errorf("the suite's entries = %q, want %q", got, want)
	}
	if differ := acctest.Texts(lists["differ"]); (world.Topology == testenv.Pair) != slices.Equal(differ, []string{"blocked", "allowed"}) || (world.Topology != testenv.Pair && len(differ) != 0) {
		t.Errorf("in the %s topology the servers' lists differ in %v", world.Topology, differ)
	}

	// the audit: the entry a zone answers for, and for servers on their own the lists they do not share
	wrong, counts := findings(t, "audit_blocking", map[string]any{"zone": "*"})
	never := one(t, wrong, "entry_never_applies", heldName)
	if !strings.Contains(acctest.Str(never["detail"]), heldName+" is on the blocked list, and the zone "+sharedZone+", held here, answers for the name") || never["zone"] != sharedZone || acctest.Str(never["fix"]) == "" {
		t.Errorf("the entry that blocks nothing = %v", never)
	}
	if on := acctest.Texts(never["servers"]); (world.Topology == testenv.Pair) != slices.Equal(on, []string{world.First}) || (world.Topology != testenv.Pair && len(on) != 0) {
		t.Errorf("the entry that blocks nothing is on %v", on)
	}
	want := 1
	if world.Topology == testenv.Pair {
		want = 3
		if acctest.NumOr0(counts["blocking_differs"]) != 2 || !slices.ContainsFunc(wrong, func(f map[string]any) bool {
			return strings.Contains(acctest.Str(f["detail"]), "2 names are on the blocked list of one of "+world.First+" and "+world.Second+" and not the other")
		}) {
			t.Errorf("two servers that do not block alike = %v", wrong)
		}
	}
	if len(wrong) != want {
		t.Errorf("audit_blocking found %d things (%v), want %d: %v", len(wrong), counts, want, wrong)
	}

	first, err := world.Client(world.First)
	if err != nil {
		t.Fatal(err)
	}
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	has := func(name string) bool {
		t.Helper()
		blocked, err := first.BlockedNames(ctx)
		if err != nil {
			t.Fatal(err)
		}

		return slices.Contains(blocked, name)
	}

	// a name blocked: a dry run changes nothing, then it is added, read back, and blocked when asked for
	dry := suite.Call(t, "block_set", on(map[string]any{"name": changedName, "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have added " + changedName + " to the blocked list of " + world.First}) || dry["now"] != nil || has(changedName) {
		t.Errorf("a dry run = %v, and the name is on the list: %v", dry, has(changedName))
	}
	set := suite.Call(t, "block_set", on(map[string]any{"name": strings.ToUpper(changedName) + "."}))
	if now := acctest.Object(t, set["now"], "now"); set["server"] != world.First || set["list"] != "blocked" || set["name"] != changedName || !acctest.BoolOf(set["changed"]) || !acctest.BoolOf(now["blocked"]) || now["entry"] != changedName || !has(changedName) {
		t.Errorf("blocked = %v", set)
	}
	if again := suite.Call(t, "block_set", on(map[string]any{"name": changedName})); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 {
		t.Errorf("blocked again = %v", again)
	}
	if under := suite.Call(t, "block_set", on(map[string]any{"name": "x." + changedName})); acctest.BoolOf(under["changed"]) || !strings.Contains(acctest.Str(under["note"]), "by the entry above it, "+changedName) || has("x."+changedName) {
		t.Errorf("a name under a blocked one = %v", under)
	}
	// allowed as well: it is on both lists, and the allowed one wins
	allowed := suite.Call(t, "block_set", on(map[string]any{"name": changedName, "list": "allowed"}))
	if now := acctest.Object(t, allowed["now"], "now"); acctest.BoolOf(now["blocked"]) || now["allowed"] != changedName || now["listed"] != changedName || now["why"] != "the allowed entry "+changedName+" wins over it" {
		t.Errorf("allowed as well = %v", allowed)
	}

	// taken off: named exactly, and the answer says how the name stands afterwards
	if msg := suite.CallErr(t, "block_delete", on(map[string]any{"name": "x." + changedName})); !strings.Contains(msg, "it is on the list by the entry above it, "+changedName) || !strings.Contains(msg, "Nothing was removed") {
		t.Errorf("removing a name an entry above stands for = %q", msg)
	}
	unallowed := suite.Call(t, "block_delete", on(map[string]any{"name": changedName, "list": "allowed"}))
	if now := acctest.Object(t, unallowed["now"], "now"); !acctest.BoolOf(now["blocked"]) || now["entry"] != changedName || now["allowed"] != nil {
		t.Errorf("after its allowed entry went = %v", unallowed)
	}
	dry = suite.Call(t, "block_delete", on(map[string]any{"name": changedName, "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have removed " + changedName + " from the blocked list of " + world.First}) || !has(changedName) {
		t.Errorf("a dry run of a removal = %v", dry)
	}
	gone := suite.Call(t, "block_delete", on(map[string]any{"name": changedName}))
	if now := acctest.Object(t, gone["now"], "now"); acctest.BoolOf(now["blocked"]) || now["listed"] != nil || has(changedName) {
		t.Errorf("taken off = %v", gone)
	}
	if msg := suite.CallErr(t, "block_delete", on(map[string]any{"name": changedName})); !strings.Contains(msg, changedName+" is not an entry of the blocked list of "+world.First) {
		t.Errorf("taken off again = %q", msg)
	}

	if !clustered() {
		return
	}
	// on the cluster's second node: the change goes to the first, and the second has it when it has copied it back
	t.Cleanup(func() { _ = first.UnblockName(ctx, viaSecond) })
	via := suite.Call(t, "block_set", map[string]any{"server": world.Second, "name": viaSecond})
	if !strings.Contains(acctest.Str(via["note"]), world.Second+" is a secondary node of a cluster: the change went to the cluster's primary, and "+world.Second+" has copied it back") || !acctest.BoolOf(acctest.Object(t, via["now"], "now")["blocked"]) || !has(viaSecond) {
		t.Errorf("a name blocked on the second node = %v, and the first has it: %v", via, has(viaSecond))
	}
	off := suite.Call(t, "block_delete", map[string]any{"server": world.Second, "name": viaSecond})
	if acctest.BoolOf(acctest.Object(t, off["now"], "now")["blocked"]) || has(viaSecond) {
		t.Errorf("taken off on the second node = %v, and the first still has it: %v", off, has(viaSecond))
	}
}

// Blocking paused, and given a list that cannot be fetched: each is said by
// block_list and by block_check, and found by the audit.
//
// It does not run beside the other tests: while blocking is paused nothing
// they block is blocked.
//
//nolint:paralleltest // it pauses the servers' blocking, under any test running beside it
func TestBlockingSwitchedOff(t *testing.T) {
	names(t)
	first, err := world.Client(world.First)
	if err != nil {
		t.Fatal(err)
	}
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	// every node of a cluster takes these from the first, a while after it
	settled := func(what string, is func(s *technitium.Settings) bool) {
		t.Helper()
		if !clustered() {
			return
		}
		second, clientErr := world.Client(world.Second)
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		if !acctest.EventuallyWithin(2*time.Minute, func() bool {
			got, readErr := second.Settings(ctx)

			return readErr == nil && is(got)
		}) {
			t.Fatalf("%s never had its blocking %s, as %s does", world.Second, what, world.First)
		}
	}
	t.Cleanup(func() {
		_, _ = first.SetBlocking(ctx, true)
		_, _ = first.SetBlockLists(ctx, nil)
		settled("back as it was", func(s *technitium.Settings) bool {
			return s.EnableBlocking && s.TemporaryDisableBlockingTill == "" && len(s.BlockListURLs) == 0
		})
	})

	// paused: a dry run pauses nothing, and then it is, with when it ends
	dry := suite.Call(t, "block_switch", on(map[string]any{"to": "paused", "minutes": 5, "dry_run": true}))
	if got, err := first.Settings(ctx); err != nil || !got.EnableBlocking || len(acctest.Strs(t, dry["changes"], "changes")) != 1 || dry["after"] != nil {
		t.Errorf("a dry run of a pause = %v, and blocking is on: %v, %v", dry, got.EnableBlocking, err)
	}
	paused := suite.Call(t, "block_switch", on(map[string]any{"to": "paused", "minutes": 5}))
	if before, after := acctest.Object(t, paused["before"], "before"), acctest.Object(t, paused["after"], "after"); before["blocking"] != "on" || after["blocking"] != "paused" || !strings.HasSuffix(acctest.Str(after["paused_until"]), "Z") || !acctest.BoolOf(paused["changed"]) {
		t.Errorf("paused = %v", paused)
	}
	got, err := first.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	until := mustUTC(t, got.TemporaryDisableBlockingTill)
	if acctest.Object(t, paused["after"], "after")["paused_until"] != until {
		t.Errorf("paused until %v, and the server says %s", acctest.Object(t, paused["after"], "after")["paused_until"], until)
	}
	settled("paused", func(s *technitium.Settings) bool { return s.TemporaryDisableBlockingTill != "" })

	row := rowFor(t, acctest.Rows(t, suite.Call(t, "block_list", nil)["servers"], "servers"), "server", world.First)
	if row["blocking"] != "paused" || row["paused_until"] != until {
		t.Errorf("paused, %s = %v, want it paused until %s", world.First, row, until)
	}
	checks := acctest.Rows(t, suite.Call(t, "block_check", map[string]any{"names": []string{"x." + blockedName}, "server": world.First})["checks"], "checks")
	if c := check(t, checks, "x."+blockedName, world.First); acctest.BoolOf(c["blocked"]) || c["listed"] != blockedName || c["why"] != "blocking is paused on "+world.First+" until "+until {
		t.Errorf("a blocked name while blocking is paused = %v", c)
	}
	wrong, _ := findings(t, "audit_blocking", map[string]any{"zone": "*", "problems": []string{"blocking_paused", "blocking_off"}})
	if len(wrong) != 1 || wrong[0]["problem"] != "blocking_paused" || wrong[0]["detail"] != "blocking is paused until "+until+": nothing is blocked till then" {
		t.Errorf("the audit of a pause = %v", wrong)
	}
	if on := acctest.Texts(wrong[0]["servers"]); (world.Topology == testenv.Pair) != slices.Equal(on, []string{world.First}) {
		t.Errorf("the pause is on %v, in the %s topology", on, world.Topology)
	}

	// switched off, which a pause is not; and back on, which ends either
	switched := suite.Call(t, "block_switch", on(map[string]any{"to": "off"}))
	if acctest.Object(t, switched["before"], "before")["blocking"] != "paused" || acctest.Object(t, switched["after"], "after")["blocking"] != "off" {
		t.Errorf("switched off in a pause = %v", switched)
	}
	switched = suite.Call(t, "block_switch", on(map[string]any{"to": "on"}))
	if got, err = first.Settings(ctx); err != nil || !got.EnableBlocking || got.TemporaryDisableBlockingTill != "" || acctest.Object(t, switched["after"], "after")["blocking"] != "on" {
		t.Errorf("switched on = %v, and the server has blocking on: %v, %v", switched, got.EnableBlocking, err)
	}
	if again := suite.Call(t, "block_switch", on(map[string]any{"to": "on"})); acctest.BoolOf(again["changed"]) {
		t.Errorf("switched on again = %v", again)
	}

	// a list nothing is at: a dry run sets none; added and asked for, it is fetched and holds nothing
	const list = "http://127.0.0.1:9/acc-no-such-list.txt"
	dry = suite.Call(t, "block_lists_set", on(map[string]any{"add": []string{list}, "dry_run": true}))
	if got, err = first.Settings(ctx); err != nil || len(got.BlockListURLs) != 0 || len(acctest.Strs(t, dry["changes"], "changes")) != 1 {
		t.Errorf("a dry run of a list = %v, and the server fetches %v, %v", dry, got.BlockListURLs, err)
	}
	added := suite.Call(t, "block_lists_set", on(map[string]any{"add": []string{list}, "fetch": true}))
	if after := acctest.Object(t, added["after"], "after"); len(acctest.Strs(t, added["before"], "before")) != 0 || len(acctest.Strs(t, added["changes"], "changes")) != 2 || !slices.Equal(acctest.Texts(after["lists"]), []string{list}) {
		t.Errorf("a list added = %v", added)
	}
	if msg := suite.CallErr(t, "block_lists_set", on(map[string]any{"remove": []string{"http://127.0.0.1:9/acc-another.txt"}})); !strings.Contains(msg, "fetches no list at http://127.0.0.1:9/acc-another.txt: it fetches "+list) {
		t.Errorf("a list that is not fetched, taken off = %q", msg)
	}
	settled("on with a list", func(s *technitium.Settings) bool { return s.EnableBlocking && len(s.BlockListURLs) == 1 })
	row = rowFor(t, acctest.Rows(t, suite.Call(t, "block_list", nil)["servers"], "servers"), "server", world.First)
	if row["blocking"] != "on" || !slices.Equal(acctest.Texts(row["lists"]), []string{list}) || row["lists_every"] != "24h" || row["lists_next"] != nil || acctest.Num(t, row["list_names"], "list_names") != 0 || !strings.Contains(acctest.Str(row["note"]), "the lists have not been fetched since they were set") {
		t.Errorf("with a list that cannot be fetched, %s = %v", world.First, row)
	}
	wrong, counts := findings(t, "audit_blocking", map[string]any{"zone": "*", "problems": []string{"lists_empty", "lists_not_fetched"}})
	if len(wrong) != 2 || acctest.NumOr0(counts["lists_empty"]) != 1 || acctest.NumOr0(counts["lists_not_fetched"]) != 1 || !slices.ContainsFunc(wrong, func(f map[string]any) bool {
		return strings.Contains(acctest.Str(f["detail"]), "the 1 block lists fetched hold no names between them: none has loaded, so nothing of theirs is blocked. The lists: "+list)
	}) {
		t.Errorf("the audit of a list that cannot be fetched = %v", wrong)
	}

	// the whole set, given empty: there are none again
	cleared := suite.Call(t, "block_lists_set", on(map[string]any{"lists": []string{}}))
	if got, err = first.Settings(ctx); err != nil || len(got.BlockListURLs) != 0 || acctest.Object(t, cleared["after"], "after")["lists"] != nil || !slices.Equal(acctest.Strs(t, cleared["before"], "before"), []string{list}) {
		t.Errorf("the lists cleared = %v, and the server fetches %v, %v", cleared, got.BlockListURLs, err)
	}
}

// mustUTC is a time the server gave as the tools give one.
func mustUTC(t *testing.T, serverTime string) string {
	t.Helper()

	at, ok := technitium.ParseTime(serverTime)
	if !ok {
		t.Fatalf("%q is no time", serverTime)
	}

	return at.UTC().Format(time.RFC3339)
}

// server_stats counts what the fixtures asked the first server through its
// DNS port: its own name answered from its zone, and a blocked one refused,
// from the one client that asked.
func TestServerStats(t *testing.T) {
	t.Parallel()

	servers := names(t)
	queries := func(list any, name string) int {
		for _, row := range acctest.RowsOf(list) {
			if row["name"] == name || row["address"] == name {
				return acctest.NumOr0(row["queries"])
			}
		}

		return 0
	}
	// the server counts by the minute, and a minute is in its totals once it is over
	var out, first map[string]any
	if !acctest.EventuallyWithin(2*time.Minute, func() bool {
		var err error
		if out, err = suite.Invoke("server_stats", nil); err != nil {
			return false
		}
		rows := acctest.RowsOf(out["servers"])
		if len(rows) != len(servers) {
			return false
		}
		first = rows[0]

		return queries(first["top_domains"], heldName) >= askedTimes && queries(first["top_blocked"], "x."+blockedName) >= 1
	}) {
		t.Fatalf("what the fixtures asked never showed in server_stats: %v", out)
	}
	if out["window"] != "hour" || !strings.Contains(acctest.Str(out["note"]), "the minute in progress is not in yet") || first["server"] != world.First || first["error"] != nil {
		t.Errorf("the answer = %v", out)
	}
	if acctest.Num(t, first["queries"], "queries") < askedTimes+1 || acctest.Num(t, first["no_error"], "no_error") < askedTimes || acctest.Num(t, first["authoritative"], "authoritative") < askedTimes || acctest.Num(t, first["blocked"], "blocked") < 1 || acctest.Num(t, first["clients"], "clients") < 1 || acctest.Num(t, first["zones"], "zones") < 3 {
		t.Errorf("%s's counts = %v", world.First, first)
	}
	if acctest.Decimal(t, first["blocked_percent"], "blocked_percent") <= 0 || first["nx_domain_percent"] == nil || first["server_failure_percent"] == nil {
		t.Errorf("%s's parts = %v blocked, %v no such name, %v failed", world.First, first["blocked_percent"], first["nx_domain_percent"], first["server_failure_percent"])
	}
	// the server itself is the client that asked
	if queries(first["top_clients"], "127.0.0.1") < askedTimes+1 || acctest.NumOr0(acctest.Object(t, first["types"], "types")["A"]) < askedTimes+1 || acctest.NumOr0(acctest.Object(t, first["protocols"], "protocols")["Udp"]) < askedTimes+1 {
		t.Errorf("who asked %s, for what and how = %v, %v, %v", world.First, first["top_clients"], first["types"], first["protocols"])
	}

	// the one that leads each list; the longer windows; and a window of one's own, which holds today
	few := rowFor(t, acctest.Rows(t, suite.Call(t, "server_stats", map[string]any{"top": 1})["servers"], "servers"), "server", world.First)
	if len(acctest.Rows(t, few["top_domains"], "top_domains")) != 1 || len(acctest.Rows(t, few["top_clients"], "top_clients")) != 1 {
		t.Errorf("the one that leads each list = %v", few)
	}
	more := rowFor(t, acctest.Rows(t, suite.Call(t, "server_stats", map[string]any{"top": 25, "server": world.First})["servers"], "servers"), "server", world.First)
	if queries(more["top_domains"], heldName) < askedTimes || queries(more["top_blocked"], "x."+blockedName) < 1 {
		t.Errorf("twenty-five of each list = %v", more)
	}
	for _, window := range []string{"day", "week", "month", "year"} {
		longer := suite.Call(t, "server_stats", map[string]any{"window": window})
		if rows := acctest.Rows(t, longer["servers"], "servers"); len(rows) != len(servers) || rows[0]["error"] != nil || longer["window"] != window || !strings.Contains(acctest.Str(longer["note"]), "the hour in progress is not in it") {
			t.Errorf("the %s = %v", window, longer)
		}
	}
	today := time.Now().UTC()
	own := suite.Call(t, "server_stats", map[string]any{"from": today.Add(-24 * time.Hour).Format(time.DateOnly), "to": today.Add(24 * time.Hour).Format(time.RFC3339), "server": world.First})
	if row := acctest.Rows(t, own["servers"], "servers")[0]; acctest.Num(t, row["queries"], "queries") <= askedTimes || !strings.Contains(acctest.Str(own["window"]), " to ") {
		t.Errorf("a window of one's own = %v", own)
	}
	if msg := suite.CallErr(t, "server_stats", map[string]any{"window": "decade"}); !strings.Contains(msg, "it takes hour, day, week, month or year") {
		t.Errorf("a window there is none of = %q", msg)
	}
}

// log_search reads what the fixtures asked the first server through its DNS
// port out of the log its app keeps: listed with who asked and what they
// were told, narrowed by each filter, and counted by who asked.
func TestLogSearch(t *testing.T) {
	t.Parallel()

	servers := names(t)
	// the app writes what it is given a moment after
	var out map[string]any
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		var err error
		out, err = suite.Invoke("log_search", map[string]any{"name": heldName, "client": "127.0.0.1", "type": "A", "server": world.First})

		return err == nil && acctest.NumOr0(out["total"]) >= askedTimes
	}) {
		t.Fatalf("what the fixtures asked never showed in log_search: %v", out)
	}
	rows := acctest.Rows(t, out["queries"], "queries")
	if len(rows) < askedTimes || out["counts"] != nil {
		t.Fatalf("the queries for %s = %v", heldName, out)
	}
	for _, row := range rows {
		if row["server"] != world.First || row["client"] != "127.0.0.1" || row["name"] != heldName || row["type"] != "A" || row["result"] != "NoError" || row["source"] != "Authoritative" || row["protocol"] != "Udp" || row["answer"] != "A 10.0.0.4" || !recent(t, row["time"], time.Hour) {
			t.Errorf("a query for %s = %v", heldName, row)
		}
	}
	logs := acctest.Rows(t, out["logs"], "logs")
	if len(logs) != 1 || logs[0]["server"] != world.First || !strings.HasPrefix(acctest.Str(logs[0]["app"]), "Query Logs (Sqlite) ") || logs[0]["keeps"] != "the last 7 days, at most 10000 queries" || acctest.Num(t, logs[0]["matched"], "matched") != acctest.Num(t, out["total"], "total") || logs[0]["error"] != nil || logs[0]["note"] != nil {
		t.Errorf("the log = %v", logs)
	}

	// every server's log, each said: the blocked name was asked of the first alone
	blocked := suite.Call(t, "log_search", map[string]any{"source": "blocked", "name": "*." + blockedName, "last": "1h"})
	if logs = acctest.Rows(t, blocked["logs"], "logs"); len(logs) != len(servers) || acctest.Num(t, rowFor(t, logs, "server", world.First)["matched"], "matched") < 1 {
		t.Fatalf("the blocked queries = %v", blocked)
	}
	if got := acctest.Rows(t, blocked["queries"], "queries"); len(got) < 1 || got[0]["name"] != "x."+blockedName || got[0]["result"] != "NxDomain" || got[0]["source"] != "Blocked" || got[0]["answer"] != nil {
		t.Errorf("a blocked query = %v", got)
	}

	// counted: who asks for the name, and what the one that asks is told
	counted := suite.Call(t, "log_search", map[string]any{"name": heldName, "count_by": "client", "server": world.First})
	if counts := acctest.Rows(t, counted["counts"], "counts"); len(counts) < 1 || counts[0]["value"] != "127.0.0.1" || acctest.Num(t, counts[0]["queries"], "queries") < askedTimes || counted["queries"] != nil || counts[0]["on"] != nil {
		t.Errorf("who asked for %s = %v", heldName, counted)
	}
	byResult := acctest.Rows(t, suite.Call(t, "log_search", map[string]any{"client": "127.0.0.1", "count_by": "result"})["counts"], "counts")
	if i := slices.IndexFunc(byResult, func(c map[string]any) bool { return c["value"] == "NoError" }); i < 0 || acctest.Num(t, byResult[i]["queries"], "queries") < askedTimes {
		t.Errorf("how the server's own queries were answered = %v", byResult)
	}

	// a few at a time, the oldest first, and a time nothing was asked in
	paged := suite.Call(t, "log_search", map[string]any{"name": heldName, "server": world.First, "limit": 2, "oldest_first": true})
	if got := acctest.Rows(t, paged["queries"], "queries"); len(got) != 2 || acctest.Str(got[0]["time"]) > acctest.Str(got[1]["time"]) || !strings.Contains(acctest.Str(paged["note"]), "read on with offset 2") {
		t.Errorf("the two oldest = %v", paged)
	}
	if none := suite.Call(t, "log_search", map[string]any{"since": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}); acctest.Num(t, none["total"], "total") != 0 || none["queries"] != nil {
		t.Errorf("the queries of an hour that has not come = %v", none)
	}
	if msg := suite.CallErr(t, "log_search", map[string]any{"result": "missing"}); !strings.Contains(msg, "it takes FormatError, NoError") {
		t.Errorf("a result there is none of = %q", msg)
	}
}
