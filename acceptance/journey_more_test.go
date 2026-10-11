//go:build integration

package acceptance

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/go-kt/mcp/registry"
	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sessionAs is another client session on the first server alone, under a
// token of its own and with the tools the options register: what somebody
// who is not the administrator, or who was not given every switch, has.
func sessionAs(t *testing.T, token string, opts tools.Options) *acctest.Suite {
	t.Helper()

	set, err := servers.New([]string{mustClient(t, world.First).BaseURL()}, []string{token})
	if err != nil {
		t.Fatal(err)
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "technitium", Version: "journey"}, nil)
	if _, err := tools.RegisterAll(srv, set, opts); err != nil {
		t.Fatal(err)
	}
	session, err := acctest.Connect(context.WithoutCancel(t.Context()), srv)
	if err != nil {
		t.Fatal(err)
	}

	return session
}

// everything is every tool, with leave to change and to delete.
var everything = tools.Options{Toolsets: []string{registry.All}, EnableWrite: true, EnableDelete: true}

// A mistake undone from a backup: a zone is backed up, deleted, and put back
// whole from the file, with the record it had.
//
//nolint:paralleltest // it deletes a zone and restores the server's zones from a backup, over whatever a test beside it made
func TestJourneyAMistakeUndoneFromABackup(t *testing.T) {
	journeyZones(t, restoredZone)
	first := world.First
	dir := t.TempDir()
	suite.Call(t, "record_set", on(map[string]any{"name": "kept." + restoredZone, "type": "A", "value": "10.69.0.1", "comment": "worth keeping"}))

	// a backup is of what the server has written to disk, which lags a change by a few seconds: one is taken until it holds the zone with its record
	var backup string
	n := 0
	holds := func(files []string) bool {
		return slices.ContainsFunc(files, func(file string) bool { return strings.Contains(file, restoredZone) })
	}
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		n++
		taken, err := suite.Invoke("settings_backup", on(map[string]any{"path": filepath.Join(dir, fmt.Sprintf("try-%d.zip", n)), "parts": []string{"zones"}}))
		if err != nil || !holds(acctest.Texts(taken["files"])) {
			return false
		}
		backup = acctest.Str(taken["path"])
		// the zone's file is written with its SOA alone at first: it is the one with the record once it has grown past the others like it
		restored, _ := suite.Invoke("settings_restore", on(map[string]any{"path": backup, "parts": []string{"zones"}, "dry_run": true}))

		return holds(acctest.Texts(restored["files"])) && n > 2
	}) {
		t.Fatal("the zone just made never reached a backup")
	}

	// the mistake, and its undoing
	suite.Call(t, "zone_delete", on(map[string]any{"zone": restoredZone}))
	if zones, err := mustClient(t, first).Zones(t.Context(), technitium.ZoneFilter{}); err != nil || slices.ContainsFunc(zones, func(z technitium.Zone) bool { return z.Name == restoredZone }) {
		t.Fatalf("the zone was deleted and the server still holds it, %v", err)
	}
	if restored := suite.Call(t, "settings_restore", on(map[string]any{"path": backup, "parts": []string{"zones"}})); !acctest.BoolOf(restored["changed"]) {
		t.Errorf("restored = %v", restored)
	}
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		at, err := mustClient(t, first).RecordsAt(t.Context(), "kept."+restoredZone, restoredZone)

		return err == nil && len(at.Records) == 1 && at.Records[0].Value() == "10.69.0.1" && at.Records[0].Comments == "worth keeping"
	}) {
		t.Error("the zone restored from the backup does not have the record it had")
	}
	// and the tools see it again as it was
	if got := recordValues(t, restoredZone, "kept."+restoredZone, "A"); !slices.Equal(got, []string{"10.69.0.1"}) {
		t.Errorf("zone_records of the zone that was restored = %v", got)
	}
}

// A token that may only look, and at one zone: what each kind of tool says
// to somebody who is not the administrator. Reads give what the account may
// see and no more, changes are refused in the server's own words, and what
// only an administrator may read says so without anything breaking.
func TestJourneyATokenThatMayOnlyLook(t *testing.T) {
	t.Parallel()

	names(t)
	const user = "acc-j-viewer"
	_, _ = suite.Invoke("user_delete", on(map[string]any{"username": user}))
	suite.Call(t, "user_set", on(map[string]any{"username": user, "new_password": suite.Secret("an acceptance passw0rd")}))
	t.Cleanup(func() {
		_, _ = suite.Invoke("access_set", on(map[string]any{"zone": firstZone, "remove_users": []string{user}}))
		_, _ = suite.Invoke("user_delete", on(map[string]any{"username": user}))
	})
	viewer := sessionAs(t, acctest.Str(suite.Call(t, "token_create", on(map[string]any{"username": user, "token_name": "acc-j-viewer"}))["token"]), everything) //nolint:gosec // G101: the token is made by the server in the run and kept nowhere
	zonesSeen := func() []string {
		t.Helper()
		rows := acctest.Rows(t, viewer.Call(t, "zone_list", nil)["zones"], "zones")
		seen := make([]string, 0, len(rows))
		for _, row := range rows {
			seen = append(seen, acctest.Str(row["zone"]))
		}

		return seen
	}

	// who it is, and that it may view the zones and change none; the zones it is shown are the ones it was given, which is none
	own := acctest.Rows(t, viewer.Call(t, "account_get", nil)["servers"], "servers")[0]
	if own["username"] != user || len(acctest.Strs(t, own["groups"], "groups")) != 0 {
		t.Errorf("the viewer's own account = %v", own)
	}
	if seen := zonesSeen(); len(seen) != 0 {
		t.Errorf("an account given no zone sees %v", seen)
	}

	// given one zone to view, it sees that zone and its records, and no other
	suite.Call(t, "access_set", on(map[string]any{"zone": firstZone, "users": []map[string]any{{"name": user, "view": true}}}))
	if seen := zonesSeen(); !slices.Equal(seen, []string{firstZone}) {
		t.Errorf("an account given one zone sees %v", seen)
	}
	if records := viewer.Call(t, "zone_records", map[string]any{"zone": firstZone}); acctest.Num(t, records["total"], "total") == 0 {
		t.Errorf("the zone it may view has no records for it: %v", records)
	}

	// a change is refused by the server, in its words, and nothing is changed
	before := onServer(t, world.First, firstZone, "acc-j-refused."+firstZone, "A")
	if msg := viewer.CallErr(t, "record_set", map[string]any{"name": "acc-j-refused." + firstZone, "type": "A", "value": "10.69.0.9"}); !strings.Contains(msg, "Access was denied") {
		t.Errorf("a change by an account that may only look = %q", msg)
	}
	if after := onServer(t, world.First, firstZone, "acc-j-refused."+firstZone, "A"); !slices.Equal(after, before) {
		t.Errorf("a refused change left %v on the server", after)
	}
	// a dry run says what would be asked and asks nothing, so it is the asking that is refused: the zone is still there
	if dry := viewer.Call(t, "zone_delete", map[string]any{"zone": firstZone, "dry_run": true}); len(acctest.Strs(t, dry["changes"], "changes")) != 1 {
		t.Errorf("a dry run of deleting the zone it may view = %v", dry)
	}
	if msg := viewer.CallErr(t, "zone_delete", map[string]any{"zone": firstZone}); !strings.Contains(msg, "Access was denied") {
		t.Errorf("deleting a zone it may only view = %q", msg)
	}
	if seen := zonesSeen(); !slices.Equal(seen, []string{firstZone}) {
		t.Fatalf("after a deletion that was refused the zones it sees are %v", seen)
	}

	// what only an administrator may read is refused the same way, tool by tool, and the session goes on working after each
	for _, tool := range []string{"user_list", "session_list", "settings_get", "access_get", "cluster_get"} {
		if msg := viewer.CallErr(t, tool, nil); !strings.Contains(msg, "Access was denied") {
			t.Errorf("%s by an account that may only look = %q", tool, msg)
		}
	}
	// the server's own log is every account's to read, as the server comes: the Everyone group may view the Logs section
	if files := acctest.Rows(t, viewer.Call(t, "log_files", nil)["servers"], "servers"); len(files) != 1 || files[0]["error"] != nil {
		t.Errorf("the log files as an account that may only look sees them = %v", files)
	}
	// an audit reads what it may and says what it was not given
	audited := viewer.Call(t, "audit_targets", map[string]any{"zone": firstZone})
	if acctest.Num(t, audited["zones"], "zones") != 1 || audited["failed"] != nil {
		t.Errorf("an audit by an account that sees one zone = %v", audited)
	}
	if seen := zonesSeen(); !slices.Equal(seen, []string{firstZone}) {
		t.Errorf("after the refusals the session sees %v", seen)
	}
}

// A session that was not given every switch has only the tools the switches
// allow, whatever the token may do: nothing that changes without
// --enable-write, and nothing that deletes without --enable-delete.
func TestJourneyAnAdministratorWithoutTheSwitches(t *testing.T) {
	t.Parallel()

	names(t)
	_, token := firstServer(t)
	reads := sessionAs(t, token, tools.Options{Toolsets: []string{registry.All}}).ToolNames(t)
	writes := sessionAs(t, token, tools.Options{Toolsets: []string{registry.All}, EnableWrite: true}).ToolNames(t)
	all := suite.ToolNames(t)

	for _, tool := range []string{"record_set", "zone_create", "settings_set", "user_set", "cluster_join", "app_install", "block_switch", "dhcp_scope_set"} {
		if slices.Contains(reads, tool) || !slices.Contains(writes, tool) {
			t.Errorf("%s: registered with nothing switched on: %v; with --enable-write: %v", tool, slices.Contains(reads, tool), slices.Contains(writes, tool))
		}
	}
	for _, tool := range []string{"record_delete", "zone_delete", "user_delete", "settings_restore", "cluster_delete", "log_delete", "stats_delete", "block_flush", "dhcp_scope_delete", "app_delete", "session_delete", "dnssec_unsign"} {
		if slices.Contains(reads, tool) || slices.Contains(writes, tool) || !slices.Contains(all, tool) {
			t.Errorf("%s: registered with nothing switched on: %v; with --enable-write alone: %v; with both: %v", tool, slices.Contains(reads, tool), slices.Contains(writes, tool), slices.Contains(all, tool))
		}
	}
	if len(reads) >= len(writes) || len(writes) >= len(all) {
		t.Errorf("%d tools read, %d with writes, %d with deletes: each switch should add some", len(reads), len(writes), len(all))
	}
}

// Calls at once: many records set in one zone by many callers while others
// read it, and every one lands - then all deleted at once, and none is left.
//
//nolint:paralleltest // it makes and deletes a zone, which a test reading every zone beside it would list and then not find
func TestJourneyCallsAtOnce(t *testing.T) {
	journeyZones(t, busyZone)
	const callers = 12
	together := func(call func(i int) error) []error {
		var wg sync.WaitGroup
		errs := make([]error, callers)
		for i := range callers {
			wg.Go(func() { errs[i] = call(i) })
		}
		wg.Wait()

		return slices.DeleteFunc(errs, func(err error) bool { return err == nil })
	}
	host := func(i int) string { return fmt.Sprintf("h%02d.%s", i, busyZone) }

	if errs := together(func(i int) error {
		// every third caller only reads, while the rest write
		if i%3 == 0 {
			_, err := suite.Invoke("zone_records", on(map[string]any{"zone": busyZone}))

			return err
		}
		_, err := suite.Invoke("record_set", on(map[string]any{"name": host(i), "type": "A", "value": fmt.Sprintf("10.70.0.%d", i)}))

		return err
	}); len(errs) != 0 {
		t.Fatalf("%d of %d calls made at once failed: %v", len(errs), callers, errs)
	}
	for i := range callers {
		if got := onServer(t, world.First, busyZone, host(i), "A"); i%3 != 0 && !slices.Equal(got, []string{fmt.Sprintf("10.70.0.%d", i)}) {
			t.Errorf("the server has %s at %v after the calls made at once", host(i), got)
		}
	}
	if got := suite.Call(t, "zone_records", on(map[string]any{"zone": busyZone, "types": []string{"A"}})); acctest.Num(t, got["total"], "total") != callers-callers/3 {
		t.Errorf("zone_records counts %v A records, want the %d that were set", got["total"], callers-callers/3)
	}

	if errs := together(func(i int) error {
		if i%3 == 0 {
			_, err := suite.Invoke("record_find", on(map[string]any{"name": "h*." + busyZone}))

			return err
		}
		_, err := suite.Invoke("record_delete", on(map[string]any{"name": host(i), "type": "A"}))

		return err
	}); len(errs) != 0 {
		t.Fatalf("%d of %d deletions made at once failed: %v", len(errs), callers, errs)
	}
	if got := suite.Call(t, "zone_records", on(map[string]any{"zone": busyZone, "types": []string{"A"}})); acctest.Num(t, got["total"], "total") != 0 {
		t.Errorf("after every record was deleted zone_records counts %v", got["total"])
	}
}

// A write made twice changes nothing the second time, and says so: the same
// call again finds things as it left them.
//
//nolint:paralleltest // it makes and deletes a zone, which a test reading every zone beside it would list and then not find
func TestJourneyWritesDoneTwice(t *testing.T) {
	journeyZones(t, busyZone)
	const user, group = "acc-j-twice", "acc-j-twice-group"
	for tool, args := range map[string]map[string]any{"user_delete": {"username": user}, "group_delete": {"group": group}, "block_delete": {"name": "twice.acc-j.example"}} {
		_, _ = suite.Invoke(tool, on(args))
		t.Cleanup(func() { _, _ = suite.Invoke(tool, on(args)) })
	}
	t.Cleanup(func() {
		_, _ = suite.Invoke("settings_set", on(map[string]any{"settings": map[string]string{"cachePrefetchTrigger": "9"}}))
	})

	for _, write := range []struct {
		tool string
		args map[string]any
	}{
		{"record_set", map[string]any{"name": "twice." + busyZone, "type": "A", "value": "10.70.1.1", "ttl": 900, "comment": "set twice"}},
		{"record_set", map[string]any{"name": "alias." + busyZone, "type": "CNAME", "value": "twice." + busyZone}},
		{"zone_edit", map[string]any{"zone": busyZone, "transfer": "Deny", "notify": "None"}},
		{"zone_convert", map[string]any{"zone": busyZone, "type": "Primary"}},
		{"zone_create", map[string]any{"zone": busyZone}},
		{"block_set", map[string]any{"name": "twice.acc-j.example"}},
		{"user_set", map[string]any{"username": user, "new_password": suite.Secret("an acceptance passw0rd"), "display_name": "Twice"}},
		{"group_set", map[string]any{"group": group, "description": "made twice", "members": []string{user}}},
		{"user_set", map[string]any{"username": user, "groups": []string{group}, "display_name": "Twice", "session_timeout_seconds": 1500}},
		{"access_set", map[string]any{"zone": busyZone, "groups": []map[string]any{{"name": group, "view": true, "modify": true}}}},
		{"settings_set", map[string]any{"settings": map[string]string{"cachePrefetchTrigger": "12"}}},
	} {
		first := suite.Call(t, write.tool, on(write.args))
		// a password is the one thing set that cannot be seen to be the same, so a call that carries one is made again without it
		delete(write.args, "new_password")
		second := suite.Call(t, write.tool, on(write.args))
		if acctest.BoolOf(second["changed"]) || len(acctest.Texts(second["changes"])) != 0 {
			t.Errorf("%s %v a second time = %v, want nothing changed (the first time: %v)", write.tool, write.args, second["changes"], first["changes"])
		}
	}
	if got := onServer(t, world.First, busyZone, "twice."+busyZone, "A"); !slices.Equal(got, []string{"10.70.1.1"}) {
		t.Errorf("the record set twice is on the server as %v", got)
	}
}

// heldByServer is everything a server holds, as one text to compare before
// and after: its zones to the serial, its settings, its lists, its scopes,
// its groups and accounts, its apps, its permissions and its keys.
func heldByServer(t *testing.T, c *technitium.Client) string {
	t.Helper()

	ctx := t.Context()
	zones, err := c.Zones(ctx, technitium.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}
	said := make([]string, 0, len(zones)+16)
	for _, z := range zones {
		said = append(said, fmt.Sprintf("zone %s %s serial %d disabled %v %s", z.Name, z.Type, z.SOASerial, z.Disabled, z.DNSSECStatus))
	}
	settings, err := c.AllSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// when the lists were last fetched and are next due moves by itself
	for _, moving := range []string{"blockListNextUpdatedOn", "uptimestamp"} {
		delete(settings, moving)
	}
	said = append(said, fmt.Sprintf("settings %v", settings))
	for what, read := range map[string]func() (any, error){
		"blocked": func() (any, error) { return c.BlockedNames(ctx) },
		"allowed": func() (any, error) { return c.AllowedNames(ctx) },
		"scopes":  func() (any, error) { return c.Scopes(ctx) },
		"groups":  func() (any, error) { return c.Groups(ctx) },
		"apps":    func() (any, error) { return c.Apps(ctx) },
		"access":  func() (any, error) { return c.Permissions(ctx) },
		"keys":    func() (any, error) { return c.TSIGKeyNames(ctx) },
		"sso":     func() (any, error) { return c.SSO(ctx, false) },
	} {
		got, readErr := read()
		if readErr != nil {
			t.Fatalf("reading the server's %s: %v", what, readErr)
		}
		said = append(said, fmt.Sprintf("%s %+v", what, got))
	}
	users, err := c.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		said = append(said, fmt.Sprintf("user %s disabled %v", u.Username, u.Disabled))
	}
	slices.Sort(said)

	return strings.Join(said, "\n")
}

// Reads change nothing: every tool that only reads is called, and the server
// holds afterwards exactly what it held before - its zones to the serial,
// its settings, its lists, its scopes, its accounts and its apps.
//
//nolint:paralleltest // it compares everything the server holds before and after, which a test changing something beside it would upset
func TestJourneyReadsChangeNothing(t *testing.T) {
	names(t)
	first := world.First
	c := mustClient(t, first)
	held := func() string { return heldByServer(t, c) }

	// what each read tool is asked, where it needs asking something; the rest are called with nothing
	args := map[string]map[string]any{
		"zone_records":    {"zone": firstZone},
		"zone_get":        {"zone": firstZone},
		"zone_export":     on(map[string]any{"zone": firstZone}),
		"record_find":     {"name": "*." + firstZone},
		"dns_resolve":     {"name": "www." + firstZone},
		"cache_get":       {"name": "www." + firstZone},
		"audit_names":     {"names": []string{"www." + firstZone}},
		"audit_split":     {"resolvers": []string{world.Address(first)}, "zone": firstZone},
		"block_check":     {"names": []string{"ads." + firstZone}},
		"dnssec_get":      {"zone": firstZone},
		"user_get":        {"username": "admin"},
		"access_get":      {"zone": firstZone},
		"app_config_get":  {"name": "Query Logs (Sqlite)"},
		"log_export":      {"last": "1h", "limit": 5},
		"log_search":      {"last": "1h", "limit": 5},
		"settings_backup": on(map[string]any{"path": t.TempDir(), "parts": []string{"dns_settings"}}),
		"app_list":        {"store": true},
		"server_metrics":  {"prometheus": true},
	}
	if world.Address(first) == "" {
		delete(args, "audit_split")
	}
	described, err := tools.Describe(tools.Options{Toolsets: []string{registry.All}})
	if err != nil {
		t.Fatal(err)
	}
	before := held()
	called := 0
	for _, tool := range described {
		if _, err := suite.Invoke(tool.Name, args[tool.Name]); err != nil {
			t.Errorf("%s, which only reads, could not be called: %v", tool.Name, err)
		}
		called++
	}
	if called < 45 {
		t.Fatalf("%d tools that only read were called, and there are over fifty", called)
	}
	if after := held(); after != before {
		t.Errorf("the server does not hold what it held before %d tools that only read were called:\nbefore:\n%s\nafter:\n%s", called, before, after)
	}
}

// Two servers that are meant to agree, brought into line: a record one has
// and the other has not is found, put right, and found no more. On servers
// that share nothing each is given it; in a cluster the copy may not be
// changed, says where the change belongs, and gets it from there.
//
//nolint:paralleltest // it makes and deletes a zone, which a test reading every zone beside it would list and then not find
func TestJourneyTwoServersBroughtIntoLine(t *testing.T) {
	names(t)
	if alone() {
		t.Skip("one server has no other to agree with")
	}
	first, second := world.First, world.Second
	host := "late." + bothZone
	// every server is asked: what they do not hold alike is between them
	between := func() []map[string]any {
		t.Helper()

		return acctest.Rows(t, suite.Call(t, "audit_servers", map[string]any{"zone": bothZone, "limit": 1000})["findings"], "findings")
	}
	// whether the record is among what the servers do not hold alike: two primaries of one zone always differ in the NS record each names itself in
	differs := func() bool {
		t.Helper()

		return slices.ContainsFunc(between(), func(f map[string]any) bool {
			return f["problem"] == "records_differ" && strings.Contains(acctest.Str(f["detail"]), host)
		})
	}

	if clustered() {
		// a member of the cluster's catalog is made on the primary and given to the other node
		ctx := context.WithoutCancel(t.Context())
		for _, srv := range world.Set.Every() {
			_ = srv.Client.DeleteZone(ctx, bothZone)
		}
		t.Cleanup(func() { _ = mustClient(t, first).DeleteZone(ctx, bothZone) })
		suite.Call(t, "zone_create", map[string]any{"server": first, "zone": bothZone, "catalog": testenv.ClusterCatalog})
		if !acctest.EventuallyWithin(2*time.Minute, func() bool { return holdsCopy(ctx, bothZone) }) {
			t.Fatalf("the cluster never gave %s its copy of %s", second, bothZone)
		}

		// the copy is not the place to change it, and the refusal says where is
		if msg := suite.CallErr(t, "record_set", map[string]any{"server": second, "name": host, "type": "A", "value": "10.71.0.1"}); !strings.Contains(msg, first) {
			t.Errorf("a change asked of the copy = %q, want it to name %s, which holds the zone as its own", msg, first)
		}
		suite.Call(t, "record_set", map[string]any{"server": first, "name": host, "type": "A", "value": "10.71.0.1"})
		if !acctest.EventuallyWithin(2*time.Minute, func() bool { return slices.Equal(onServer(t, second, bothZone, host, "A"), []string{"10.71.0.1"}) }) {
			t.Fatalf("the record made on the primary never reached the copy: %v", onServer(t, second, bothZone, host, "A"))
		}
		if differs() {
			t.Errorf("audit_servers says the nodes differ in %s once the copy has caught up: %v", bothZone, between())
		}

		return
	}

	// servers that share nothing: each is given the zone, and a record one has alone is what the audit finds
	ctx := context.WithoutCancel(t.Context())
	t.Cleanup(func() {
		for _, srv := range world.Set.Every() {
			_ = srv.Client.DeleteZone(ctx, bothZone)
		}
	})
	for _, server := range []string{first, second} {
		_ = mustClient(t, server).DeleteZone(ctx, bothZone)
		suite.Call(t, "zone_create", map[string]any{"server": server, "zone": bothZone})
	}
	suite.Call(t, "record_set", map[string]any{"server": first, "name": host, "type": "A", "value": "10.71.0.1"})
	if !differs() {
		t.Fatalf("audit_servers finds no difference in %s, and %s has a record %s has not: %v", bothZone, first, second, between())
	}
	if only := acctest.Rows(t, suite.Call(t, "zone_records", map[string]any{"zone": bothZone, "name": host})["records"], "records"); len(only) != 1 || !slices.Equal(acctest.Strs(t, only[0]["only_on"], "only_on"), []string{first}) {
		t.Errorf("zone_records of the record one server has alone = %v", only)
	}
	suite.Call(t, "record_set", map[string]any{"server": second, "name": host, "type": "A", "value": "10.71.0.1"})
	if got := onServer(t, second, bothZone, host, "A"); !slices.Equal(got, []string{"10.71.0.1"}) || differs() {
		t.Errorf("once both were given the record the second server has %v, and audit_servers says %v", got, between())
	}
}
