//go:build integration

package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// on a server, the rows of an answer that sets the servers side by side.
func rowOn(t *testing.T, answer map[string]any, server string) map[string]any {
	t.Helper()

	return rowFor(t, acctest.Rows(t, answer["servers"], "servers"), "server", server)
}

// Every setting by name, a few changed and put back, and a transfer key
// added and taken away beside whatever keys there are.
//
// It does not run beside the other tests: it writes settings the tests of
// blocking read whole.
//
//nolint:paralleltest // it writes the server's settings and its transfer keys, which a test beside it would read part way
func TestSettingsByName(t *testing.T) {
	names(t)
	first := world.First
	setting := func(name string) map[string]any {
		t.Helper()
		rows := acctest.Rows(t, suite.Call(t, "settings_get", map[string]any{"name": name})["settings"], "settings")

		return rowFor(t, rows, "name", name)
	}

	// all of them, and some by a pattern; nothing secret among them
	all := suite.Call(t, "settings_get", on(map[string]any{}))
	rows := acctest.Rows(t, all["settings"], "settings")
	if len(rows) < 80 || acctest.Num(t, all["differ"], "differ") != 0 {
		t.Fatalf("settings_get = %d settings, %v of them differing on one server", len(rows), all["differ"])
	}
	for _, row := range rows {
		if lower := strings.ToLower(acctest.Str(row["name"])); strings.HasSuffix(lower, "password") || strings.HasSuffix(lower, "secret") {
			t.Errorf("settings_get gives %s", row["name"])
		}
	}
	if cache := acctest.Rows(t, suite.Call(t, "settings_get", map[string]any{"name": "cache*Ttl"})["settings"], "settings"); len(cache) < 3 || !strings.HasPrefix(acctest.Str(cache[0]["name"]), "cache") {
		t.Errorf("the settings named cache*Ttl = %v", cache)
	}
	if none := suite.Call(t, "settings_get", map[string]any{"name": "acc-no-such"}); len(acctest.Rows(t, none["settings"], "settings")) != 0 || none["note"] == nil {
		t.Errorf("a pattern that matches nothing = %v", none)
	}
	// two servers on their own are each named for themselves, which is the one setting sure to differ
	if !alone() && !clustered() {
		domain := setting("dnsServerDomain")
		if domain["value"] != nil || len(acctest.Object(t, domain["values"], "values")) != 2 {
			t.Errorf("the servers' own names = %v, want one each", domain)
		}
		if differing := acctest.Rows(t, suite.Call(t, "settings_get", map[string]any{"differ_only": true})["settings"], "settings"); len(differing) == 0 || len(differing) >= len(rows) {
			t.Errorf("the settings that differ = %d of %d", len(differing), len(rows))
		}
	}

	// changed by name: a dry run changes nothing; then they are as asked, read back; and again there is nothing to do
	want := map[string]string{"cachePrefetchTrigger": "11", "serveStaleTtl": "86400"}
	t.Cleanup(func() {
		_, _ = suite.Invoke("settings_set", on(map[string]any{"settings": map[string]string{"cachePrefetchTrigger": "9", "serveStaleTtl": "259200"}}))
	})
	dry := suite.Call(t, "settings_set", on(map[string]any{"settings": want, "dry_run": true}))
	if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != 2 || got[0] != `would have set cachePrefetchTrigger on `+first+` from "9" to "11"` || dry["after"] != nil {
		t.Errorf("a dry run of settings = %v", dry)
	}
	set := suite.Call(t, "settings_set", on(map[string]any{"settings": want}))
	if after := acctest.Object(t, set["after"], "after"); acctest.Num(t, after["cachePrefetchTrigger"], "cachePrefetchTrigger") != 11 || acctest.Num(t, after["serveStaleTtl"], "serveStaleTtl") != 86400 || set["note"] != nil {
		t.Errorf("set = %v", set)
	}
	if again := suite.Call(t, "settings_set", on(map[string]any{"settings": want})); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 {
		t.Errorf("set to what they are = %v", again)
	}
	// a list is written with commas and cleared with false
	listed := suite.Call(t, "settings_set", on(map[string]any{"settings": map[string]string{"qpmLimitBypassList": "10.6.6.0/24,10.6.7.1"}}))
	if got := acctest.Texts(acctest.Object(t, listed["after"], "after")["qpmLimitBypassList"]); !slices.Equal(got, []string{"10.6.6.0/24", "10.6.7.1"}) {
		t.Errorf("a list set = %v", listed)
	}
	if cleared := suite.Call(t, "settings_set", on(map[string]any{"settings": map[string]string{"qpmLimitBypassList": "false"}})); len(acctest.Texts(acctest.Object(t, cleared["after"], "after")["qpmLimitBypassList"])) != 0 {
		t.Errorf("a list cleared = %v", cleared)
	}
	for msg, settings := range map[string]map[string]string{`no setting named "cachePrefetchTriger"`: {"cachePrefetchTriger": "9"}, "tsig_key_set adds or changes one": {"tsigKeys": "false"}} {
		if got := suite.CallErr(t, "settings_set", on(map[string]any{"settings": settings})); !strings.Contains(got, msg) {
			t.Errorf("settings_set %v = %q, want %q in it", settings, got, msg)
		}
	}

	// a setting a later version of the server brought is refused by name before anything is sent, as 15.5 lacks one 15.6 has: the server would say ok and pass it over
	has := map[string]bool{}
	for _, row := range rows {
		has[acctest.Str(row["name"])] = true
	}
	for _, name := range technitium.SettingNames {
		if has[name] || slices.Contains(technitium.SettingsNeverRead, name) {
			continue
		}

		if got := suite.CallErr(t, "settings_set", on(map[string]any{"settings": map[string]string{name: "true"}})); !strings.Contains(got, "which has no setting named "+name) {
			t.Errorf("settings_set with %s, which this server lacks = %q", name, got)
		}
	}

	// a transfer key: added beside the ones there are - a cluster has one of its own - changed, and taken away
	before := acctest.Strs(t, suite.Call(t, "tsig_key_delete", on(map[string]any{"name": "acc-key.test"}))["keys"], "keys")
	if (len(before) > 0) != clustered() {
		t.Errorf("the keys before one was added = %v: only a cluster has one of its own", before)
	}
	dry = suite.Call(t, "tsig_key_set", on(map[string]any{"name": "acc-key.test", "shared_secret": suite.Secret("YWNjZXB0YW5jZS1hY2NlcHRhbmNl"), "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have added the transfer key acc-key.test (hmac-sha256) to " + first}) || !slices.Equal(acctest.Strs(t, dry["keys"], "keys"), before) {
		t.Errorf("a dry run of adding a key = %v", dry)
	}
	added := suite.Call(t, "tsig_key_set", on(map[string]any{"name": "ACC-key.test.", "shared_secret": suite.Secret("YWNjZXB0YW5jZS1hY2NlcHRhbmNl")}))
	if keys := acctest.Strs(t, added["keys"], "keys"); len(keys) != len(before)+1 || !slices.Contains(keys, "acc-key.test") || added["note"] != nil || strings.Contains(acctest.Str(added["changes"]), "YWNj") {
		t.Errorf("a key added = %v", added)
	}
	t.Cleanup(func() { _, _ = suite.Invoke("tsig_key_delete", on(map[string]any{"name": "acc-key.test"})) })
	if changed := suite.Call(t, "tsig_key_set", on(map[string]any{"name": "acc-key.test", "shared_secret": suite.Secret("Y2hhbmdlZC1jaGFuZ2VkLWNoYW5nZWQ="), "algorithm": "HMAC-SHA512"})); !strings.HasPrefix(acctest.Strs(t, changed["changes"], "changes")[0], "changed the transfer key acc-key.test (hmac-sha512)") || len(acctest.Strs(t, changed["keys"], "keys")) != len(before)+1 {
		t.Errorf("the key changed = %v", changed)
	}
	// asked of the one server, since on two that share nothing the other has no such key and the setting differs
	mine := func(k map[string]any) bool {
		return k["keyName"] == "acc-key.test" && k["algorithmName"] == "hmac-sha512" && len(k) == 2
	}
	if keys := acctest.RowsOf(acctest.Rows(t, suite.Call(t, "settings_get", on(map[string]any{"name": "tsigKeys"}))["settings"], "settings")[0]["value"]); !slices.ContainsFunc(keys, mine) {
		t.Errorf("the keys as settings_get gives them = %v, want the new one by its name and algorithm alone", keys)
	}
	if !alone() && !clustered() {
		if differ := setting("tsigKeys"); differ["value"] != nil || len(acctest.Object(t, differ["values"], "values")) != 2 {
			t.Errorf("the keys of two servers of which one has a key the other has not = %v", differ)
		}
	}
	if gone := suite.Call(t, "tsig_key_delete", on(map[string]any{"name": "acc-key.test"})); !slices.Equal(acctest.Strs(t, gone["keys"], "keys"), before) || !acctest.BoolOf(gone["changed"]) {
		t.Errorf("the key taken away = %v", gone)
	}
	if nothing := suite.Call(t, "tsig_key_delete", on(map[string]any{"name": "acc-key.test"})); acctest.BoolOf(nothing["changed"]) {
		t.Errorf("a key taken away twice = %v", nothing)
	}
	if clustered() {
		if msg := suite.CallErr(t, "tsig_key_delete", on(map[string]any{"name": before[0]})); !strings.Contains(msg, "Cannot remove TSIG key") {
			t.Errorf("the cluster's own key taken away = %q", msg)
		}
	}
}

// A backup written to a file, and a part of the server put back from it.
//
// It does not run beside the other tests: it writes over the allowed names.
//
//nolint:paralleltest // it restores the server's allowed names from a backup, over whatever a test beside it put there
func TestBackupAndRestore(t *testing.T) {
	names(t)
	first := world.First
	dir := t.TempDir()
	const kept, lost = "kept.acc-backup.example", "lost.acc-backup.example"
	// neither name is left on any server: a list restored on a cluster's primary reaches its other node by the node fetching again, so it is asked to and waited for
	clean := func() {
		ctx := context.WithoutCancel(t.Context())
		left := func() bool {
			for _, srv := range world.Set.Every() {
				names, err := srv.Client.AllowedNames(ctx)
				if err != nil || slices.Contains(names, kept) || slices.Contains(names, lost) {
					return true
				}
			}

			return false
		}
		for _, name := range []string{kept, lost} {
			_ = mustClient(t, first).UnallowName(ctx, name)
		}
		if clustered() {
			_ = mustClient(t, world.Second).ResyncCluster(ctx)
		}
		if !acctest.EventuallyWithin(2*time.Minute, func() bool { return !left() }) {
			t.Error("a name the backup test allowed is still on a server's list")
		}
	}
	clean()
	t.Cleanup(clean)
	allowedSize := func(backup map[string]any) string {
		t.Helper()
		for _, file := range acctest.Strs(t, backup["files"], "files") {
			if strings.HasPrefix(file, "allowed.config ") {
				return file
			}
		}
		t.Fatalf("the backup has no allowed.config among %v", backup["files"])

		return ""
	}

	// into a folder the file is named for the server and the time; it is the owner's alone to read, and is never written over
	empty := suite.Call(t, "settings_backup", on(map[string]any{"path": dir, "parts": []string{"allowed_names", "dns_settings"}}))
	path := acctest.Str(empty["path"])
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 || int(info.Size()) != acctest.Num(t, empty["bytes"], "bytes") || !strings.HasPrefix(filepath.Base(path), "technitium-"+first+"-") || !slices.Equal(acctest.Strs(t, empty["parts"], "parts"), []string{"allowed_names", "dns_settings"}) {
		t.Fatalf("settings_backup = %v, and the file %v, %v", empty, info, err)
	}
	if msg := suite.CallErr(t, "settings_backup", on(map[string]any{"path": path, "parts": []string{"allowed_names"}})); !strings.Contains(msg, "file exists") {
		t.Errorf("a backup over a file that is there = %q", msg)
	}
	for msg, args := range map[string]map[string]any{`part "everything"`: {"path": dir, "parts": []string{"everything"}}, "which parts of the server": {"path": dir, "parts": []string{" "}}, "a file is named ending .zip": {"path": filepath.Join(dir, "backup.tar"), "parts": []string{"all"}}} {
		if got := suite.CallErr(t, "settings_backup", on(args)); !strings.Contains(got, msg) {
			t.Errorf("settings_backup %v = %q, want %q in it", args, got, msg)
		}
	}
	if whole := suite.Call(t, "settings_backup", on(map[string]any{"path": filepath.Join(dir, "whole.zip"), "parts": []string{"all"}})); acctest.Num(t, whole["bytes"], "bytes") <= acctest.Num(t, empty["bytes"], "bytes") || len(acctest.Strs(t, whole["parts"], "parts")) != 13 {
		t.Errorf("a backup of everything = %v bytes beside %v for two parts", whole["bytes"], empty["bytes"])
	}

	// a backup is of what the server has written to disk, which lags a change by a few seconds: one is taken until it has the name just allowed
	suite.Call(t, "block_set", on(map[string]any{"name": kept, "list": "allowed"}))
	var backup string
	n := 0
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		n++
		taken, takeErr := suite.Invoke("settings_backup", on(map[string]any{"path": filepath.Join(dir, "try-"+strings.Repeat("i", n)+".zip"), "parts": []string{"allowed_names"}}))
		if takeErr != nil {
			return false
		}
		backup = acctest.Str(taken["path"])

		return allowedSize(taken) != allowedSize(empty)
	}) {
		t.Fatal("the name just allowed never reached a backup")
	}

	// what changed after the backup is undone by restoring it: a dry run lists what the backup holds and changes nothing
	suite.Call(t, "block_set", on(map[string]any{"name": lost, "list": "allowed"}))
	suite.Call(t, "block_delete", on(map[string]any{"name": kept, "list": "allowed"}))
	allowed := func() []string {
		t.Helper()
		names, listErr := mustClient(t, first).AllowedNames(t.Context())
		if listErr != nil {
			t.Fatal(listErr)
		}

		return names
	}
	dry := suite.Call(t, "settings_restore", on(map[string]any{"path": backup, "parts": []string{"allowed_names"}, "delete_existing": true, "dry_run": true}))
	if len(acctest.Strs(t, dry["files"], "files")) != 1 || !strings.HasPrefix(acctest.Strs(t, dry["changes"], "changes")[0], "would have restored allowed_names on "+first) || slices.Contains(allowed(), kept) {
		t.Errorf("a dry run of a restore = %v", dry)
	}
	restored := suite.Call(t, "settings_restore", on(map[string]any{"path": backup, "parts": []string{"allowed_names"}, "delete_existing": true}))
	if got := allowed(); !acctest.BoolOf(restored["changed"]) || !slices.Contains(got, kept) || slices.Contains(got, lost) {
		t.Errorf("restored = %v, and the allowed names are %v", restored, got)
	}
	notZip := filepath.Join(dir, "not.zip")
	if err := os.WriteFile(notZip, []byte("not a zip file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if msg := suite.CallErr(t, "settings_restore", on(map[string]any{"path": notZip, "parts": []string{"allowed_names"}})); !strings.Contains(msg, "is no zip file") {
		t.Errorf("something that is no backup, restored = %q", msg)
	}
	if msg := suite.CallErr(t, "settings_restore", on(map[string]any{"path": filepath.Join(dir, "nothing.zip"), "parts": []string{"all"}})); !strings.Contains(msg, "reading the backup") {
		t.Errorf("a backup that is not there, restored = %q", msg)
	}
}

// The server's own log read and deleted, its counters since it started, and
// its statistics deleted.
//
// It does not run beside the other tests: it deletes log files and every
// statistic.
//
//nolint:paralleltest // it deletes the server's log files and its statistics, which the tests beside it count on
func TestLogsAndStatsKept(t *testing.T) {
	names(t)
	first := world.First

	// its health and its counters: every server is up and resolves, and counts in Prometheus's form when asked
	metrics := suite.Call(t, "server_metrics", map[string]any{"prometheus": true})
	for _, name := range world.Names() {
		row := rowOn(t, metrics, name)
		if !acctest.BoolOf(row["healthy"]) || row["unhealthy"] != nil || acctest.Num(t, row["uptime_seconds"], "uptime_seconds") <= 0 || !recent(t, row["up_since"], 24*time.Hour) || !strings.Contains(acctest.Str(row["prometheus"]), "queries_total ") {
			t.Errorf("server_metrics for %s = %v", name, row)
		}
	}
	if row := rowOn(t, suite.Call(t, "server_metrics", on(map[string]any{"check": "localhost"})), first); !acctest.BoolOf(row["healthy"]) || row["prometheus"] != nil {
		t.Errorf("server_metrics checking a name = %v", row)
	}

	// something to be logged, then the log: listed, its end read, and only its lines with some text in them
	suite.Call(t, "record_set", on(map[string]any{"name": "acc-logged." + firstZone, "type": "TXT", "value": "written to the log"}))
	t.Cleanup(func() {
		_, _ = suite.Invoke("record_delete", on(map[string]any{"name": "acc-logged." + firstZone, "type": "TXT"}))
	})
	var files []map[string]any
	if !acctest.EventuallyWithin(30*time.Second, func() bool {
		files = acctest.Rows(t, rowOn(t, suite.Call(t, "log_files", on(map[string]any{})), first)["files"], "files")

		return len(files) > 0
	}) {
		t.Fatal("the server has no log file though something was just done on it")
	}
	today := acctest.Str(files[0]["file"])
	if _, err := time.Parse("2006-01-02", today); err != nil || files[0]["size"] == nil {
		t.Errorf("log_files = %v", files)
	}
	read := rowOn(t, suite.Call(t, "log_read", on(map[string]any{"contains": "ACC-LOGGED"})), first)
	if lines := acctest.Strs(t, read["lines"], "lines"); read["file"] != today || len(lines) == 0 || !strings.Contains(lines[len(lines)-1], "acc-logged."+firstZone) || acctest.Num(t, read["matched"], "matched") != len(lines) || acctest.Num(t, read["of"], "of") < len(lines) {
		t.Errorf("log_read for what was just done = %v", read)
	}
	if tail := rowOn(t, suite.Call(t, "log_read", on(map[string]any{"file": today, "lines": 3})), first); len(acctest.Strs(t, tail["lines"], "lines")) > 3 || acctest.Num(t, tail["matched"], "matched") != acctest.Num(t, tail["of"], "of") {
		t.Errorf("the last three lines = %v", tail)
	}
	if msg := suite.CallErr(t, "log_read", map[string]any{"file": "1999-01-01"}); !strings.Contains(msg, "Could not find file") {
		t.Errorf("a log file no server has, read = %q", msg)
	}

	// deleted: a dry run deletes nothing; a file that is not there is said to be; then today's, and all
	if msg := suite.CallErr(t, "log_delete", on(map[string]any{})); !strings.Contains(msg, "one of the two") {
		t.Errorf("log_delete with nothing named = %q", msg)
	}
	dry := suite.Call(t, "log_delete", on(map[string]any{"file": today, "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have deleted the log file " + today + " of " + first}) || acctest.Num(t, dry["left"], "left") != len(files) {
		t.Errorf("a dry run of deleting a log file = %v", dry)
	}
	if nothing := suite.Call(t, "log_delete", on(map[string]any{"file": "1999-01-01"})); acctest.BoolOf(nothing["changed"]) || nothing["note"] == nil {
		t.Errorf("a log file that is not there, deleted = %v", nothing)
	}
	if deleted := suite.Call(t, "log_delete", on(map[string]any{"file": today})); !acctest.BoolOf(deleted["changed"]) {
		t.Errorf("deleted = %v", deleted)
	}
	// the server starts the day's file again as soon as it has something to write, which the deletion is: what was in it is gone
	if again := rowOn(t, suite.Call(t, "log_read", on(map[string]any{"contains": "acc-logged"})), first); len(acctest.Strs(t, again["lines"], "lines")) != 0 {
		t.Errorf("the log file that was deleted still has what was in it: %v", again)
	}
	if all := suite.Call(t, "log_delete", on(map[string]any{"all": true})); !acctest.BoolOf(all["changed"]) || acctest.Num(t, all["left"], "left") > 1 {
		t.Errorf("all deleted = %v", all)
	}

	// the statistics: a dry run says how much would go, then they are gone
	dry = suite.Call(t, "stats_delete", on(map[string]any{"dry_run": true}))
	if len(acctest.Strs(t, dry["changes"], "changes")) != 1 || !strings.HasPrefix(acctest.Strs(t, dry["changes"], "changes")[0], "would have deleted every statistic "+first+" kept") {
		t.Errorf("a dry run of deleting the statistics = %v", dry)
	}
	if deleted := suite.Call(t, "stats_delete", on(map[string]any{})); !acctest.BoolOf(deleted["changed"]) {
		t.Errorf("the statistics deleted = %v", deleted)
	}
	if after := suite.Call(t, "stats_delete", on(map[string]any{"dry_run": true})); acctest.Num(t, after["queries"], "queries") > 5 {
		t.Errorf("once deleted the statistics still count %v queries", after["queries"])
	}
}

// The log of queries as CSV, for what a search of it finds.
func TestLogExport(t *testing.T) {
	t.Parallel()

	names(t)
	first := world.First
	name := "www." + firstZone
	suite.Call(t, "dns_resolve", on(map[string]any{"name": name}))

	var row map[string]any
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		row = rowOn(t, suite.Call(t, "log_export", on(map[string]any{"name": name, "last": "1h", "limit": 2})), first)

		return acctest.Num(t, row["of"], "of") > 0
	}) {
		t.Fatalf("the export never had the query just made: %v", row)
	}
	lines := strings.Split(acctest.Str(row["csv"]), "\n")
	if !strings.HasPrefix(lines[0], "RowNumber,Timestamp,ClientIpAddress,") || len(lines) != acctest.Num(t, row["rows"], "rows")+1 || len(lines) > 3 || !strings.Contains(lines[1], name) || acctest.Num(t, row["rows"], "rows") > acctest.Num(t, row["of"], "of") {
		t.Errorf("log_export = %v", row)
	}
	if none := rowOn(t, suite.Call(t, "log_export", on(map[string]any{"name": "acc-never-asked.test"})), first); acctest.Num(t, none["of"], "of") != 0 || acctest.Num(t, none["rows"], "rows") != 0 || strings.Count(acctest.Str(none["csv"]), "\n") != 0 {
		t.Errorf("an export of nothing = %v", none)
	}
	if msg := suite.CallErr(t, "log_export", map[string]any{"result": "Maybe"}); !strings.Contains(msg, `result "Maybe"`) {
		t.Errorf("a result that is none = %q", msg)
	}
	if msg := suite.CallErr(t, "log_export", map[string]any{"last": "1h", "since": "2026-01-01"}); !strings.Contains(msg, "not both") {
		t.Errorf("last and since at once = %q", msg)
	}
}

// An app installed from the store, configured, and taken off again.
//
// It does not run beside the other tests: one of them counts the apps.
//
//nolint:paralleltest // it installs and removes an app, which a test listing the apps beside it would count
func TestApps(t *testing.T) {
	names(t)
	first := world.First
	const app = "What Is My Dns"
	_, _ = suite.Invoke("app_delete", on(map[string]any{"name": app}))
	t.Cleanup(func() { _, _ = suite.Invoke("app_delete", on(map[string]any{"name": app})) })
	installed := func(args map[string]any) []map[string]any {
		t.Helper()

		return acctest.Rows(t, rowOn(t, suite.Call(t, "app_list", on(args)), first)["installed"], "installed")
	}

	// what is installed, and with the store what else there is
	if apps := installed(map[string]any{}); len(apps) != 1 || !acctest.BoolOf(apps[0]["logs_queries"]) || apps[0]["version"] == nil || len(acctest.Strs(t, apps[0]["does"], "does")) == 0 {
		t.Fatalf("app_list = %v, want the one app scripts/testenv.sh installs", apps)
	}
	withStore := rowOn(t, suite.Call(t, "app_list", on(map[string]any{"store": true})), first)
	store := acctest.Rows(t, withStore["store"], "store")
	if withStore["store_note"] != nil || len(store) < 5 || entry(store, app) == nil || entry(store, "Query Logs (Sqlite)") != nil {
		t.Fatalf("the store = %d apps, with a note %v", len(store), withStore["store_note"])
	}

	// installed by name from the store: a dry run installs nothing; then it is there, and again there is nothing to do
	dry := suite.Call(t, "app_install", on(map[string]any{"name": strings.ToLower(app), "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have installed the app " + app + " on " + first + " from the store"}) || len(installed(map[string]any{})) != 1 {
		t.Errorf("a dry run of installing = %v", dry)
	}
	done := suite.Call(t, "app_install", on(map[string]any{"name": app}))
	if after := acctest.Object(t, done["after"], "after"); after["name"] != app || after["version"] != entry(store, app)["version"] || len(installed(map[string]any{})) != 2 {
		t.Errorf("installed = %v", done)
	}
	if again := suite.Call(t, "app_install", on(map[string]any{"name": app})); acctest.BoolOf(again["changed"]) || again["note"] == nil {
		t.Errorf("installed twice = %v", again)
	}
	for msg, args := range map[string]map[string]any{"the store has no app named": {"name": "Acc No Such App"}, "only over https://": {"name": app, "url": "http://example.com/app.zip"}, "not both": {"name": app, "url": "https://example.com/app.zip", "path": "/tmp/app.zip"}, "reading the app's zip file": {"name": app, "path": filepath.Join(t.TempDir(), "nothing.zip")}} {
		if got := suite.CallErr(t, "app_install", on(args)); !strings.Contains(got, msg) {
			t.Errorf("app_install %v = %q, want %q in it", args, got, msg)
		}
	}
	// what is no zip file is not sent: the server would keep the wreck
	notZip := filepath.Join(t.TempDir(), "not.zip")
	if err := os.WriteFile(notZip, []byte("not a zip file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if msg := suite.CallErr(t, "app_install", on(map[string]any{"name": "Acc Not An App", "path": notZip})); !strings.Contains(msg, "is no zip file") || len(installed(map[string]any{})) != 2 {
		t.Errorf("something that is no zip file, installed = %q", msg)
	}

	// its configuration: read on every server that has it, written whole and read back, with what it was in the answer
	logs := suite.Call(t, "app_config_get", map[string]any{"name": "Query Logs (Sqlite)"})
	if config := acctest.Object(t, rowOn(t, logs, first)["config"], "config"); config["enableLogging"] != any(true) || acctest.BoolOf(logs["differ"]) {
		t.Errorf("the configuration of the app that logs queries = %v", logs)
	}
	was := suite.Call(t, "app_config_set", on(map[string]any{"name": app, "config": `{"made":"by the acceptance suite"}`}))
	if !acctest.BoolOf(was["changed"]) || was["note"] != nil {
		t.Errorf("the configuration written = %v", was)
	}
	if config := rowOn(t, suite.Call(t, "app_config_get", on(map[string]any{"name": app})), first)["config"]; acctest.Object(t, config, "config")["made"] != "by the acceptance suite" {
		t.Errorf("the configuration read back = %v", config)
	}
	if same := suite.Call(t, "app_config_set", on(map[string]any{"name": app, "config": `{"made":"by the acceptance suite"}`})); acctest.BoolOf(same["changed"]) {
		t.Errorf("the same configuration written again = %v", same)
	}
	if msg := suite.CallErr(t, "app_config_set", on(map[string]any{"name": app, "config": "{not json"})); !strings.Contains(msg, "is JSON and what was given is not") {
		t.Errorf("a configuration that is not JSON = %q", msg)
	}
	if msg := suite.CallErr(t, "app_config_get", map[string]any{"name": "Acc No Such App"}); !strings.Contains(msg, "no server asked has an app named") {
		t.Errorf("the configuration of an app that is not installed = %q", msg)
	}

	// taken off: a dry run takes nothing; then it is gone, and a second time there is nothing to uninstall
	dry = suite.Call(t, "app_delete", on(map[string]any{"name": app, "dry_run": true}))
	if len(acctest.Strs(t, dry["changes"], "changes")) != 1 || len(installed(map[string]any{})) != 2 {
		t.Errorf("a dry run of uninstalling = %v", dry)
	}
	if gone := suite.Call(t, "app_delete", on(map[string]any{"name": app})); !acctest.BoolOf(gone["changed"]) || acctest.Object(t, gone["was"], "was")["name"] != app || gone["note"] != nil || len(installed(map[string]any{})) != 1 {
		t.Errorf("uninstalled = %v", gone)
	}
	if nothing := suite.Call(t, "app_delete", on(map[string]any{"name": app})); acctest.BoolOf(nothing["changed"]) || nothing["note"] == nil {
		t.Errorf("uninstalled twice = %v", nothing)
	}
	if warned := suite.Call(t, "app_delete", on(map[string]any{"name": "Query Logs (Sqlite)", "dry_run": true})); !strings.Contains(acctest.Str(warned["note"]), "kept the log of queries") {
		t.Errorf("a dry run of uninstalling the app that logs queries = %v", warned)
	}
}

// Many names added to a list at once, the list walked as a tree, and
// emptied.
//
// It does not run beside the other tests: it empties both lists.
//
//nolint:paralleltest // it empties the server's blocked and allowed lists, which a test of blocking beside it relies on
func TestListsImportedAndEmptied(t *testing.T) {
	names(t)
	first := world.First
	lists := func() (blocked, allowed []string) {
		t.Helper()
		blocked, err := mustClient(t, first).BlockedNames(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if allowed, err = mustClient(t, first).AllowedNames(t.Context()); err != nil {
			t.Fatal(err)
		}

		return blocked, allowed
	}
	blockedBefore, allowedBefore := lists()
	t.Cleanup(func() {
		_, _ = suite.Invoke("block_flush", on(map[string]any{"list": "blocked"}))
		_, _ = suite.Invoke("block_flush", on(map[string]any{"list": "allowed"}))
		if len(blockedBefore) > 0 {
			_, _ = suite.Invoke("block_import", on(map[string]any{"names": blockedBefore}))
		}
		if len(allowedBefore) > 0 {
			_, _ = suite.Invoke("block_import", on(map[string]any{"list": "allowed", "names": allowedBefore}))
		}
	})

	// added: a dry run adds nothing; then the new ones are there, and the ones that were are said to have been
	names := []string{"ads.acc-listed.example", "Track.acc-listed.example.", "ads.acc-listed.example"}
	dry := suite.Call(t, "block_import", on(map[string]any{"names": names, "dry_run": true}))
	if blocked, _ := lists(); !slices.Equal(acctest.Strs(t, dry["added"], "added"), []string{"ads.acc-listed.example", "track.acc-listed.example"}) || len(blocked) != len(blockedBefore) || acctest.Num(t, dry["total"], "total") != len(blockedBefore)+2 {
		t.Errorf("a dry run of adding names = %v", dry)
	}
	added := suite.Call(t, "block_import", on(map[string]any{"names": names}))
	if blocked, _ := lists(); len(acctest.Strs(t, added["added"], "added")) != 2 || added["list"] != "blocked" || !slices.Contains(blocked, "ads.acc-listed.example") || !slices.Contains(blocked, "track.acc-listed.example") {
		t.Errorf("added = %v", added)
	}
	again := suite.Call(t, "block_import", on(map[string]any{"names": []string{"ads.acc-listed.example", "more.acc-listed.example"}}))
	if !slices.Equal(acctest.Strs(t, again["added"], "added"), []string{"more.acc-listed.example"}) || !slices.Equal(acctest.Strs(t, again["already"], "already"), []string{"ads.acc-listed.example"}) {
		t.Errorf("added again with one more = %v", again)
	}
	suite.Call(t, "block_import", on(map[string]any{"list": "allowed", "names": []string{"good.acc-listed.example"}}))
	for msg, args := range map[string]map[string]any{"which names": {"names": []string{" "}}, "is no domain name": {"names": []string{"two words.example"}}, `list "greylist"`: {"list": "greylist", "names": []string{"x.example"}}} {
		if got := suite.CallErr(t, "block_import", on(args)); !strings.Contains(got, msg) {
			t.Errorf("block_import %v = %q, want %q in it", args, got, msg)
		}
	}

	// as a tree: under the name they share are the three, each written whole; a listed name is said to be
	tree := rowOn(t, suite.Call(t, "block_tree", on(map[string]any{"under": "acc-listed.example"})), first)
	if tree["at"] != "acc-listed.example" || acctest.BoolOf(tree["listed"]) || !slices.Equal(acctest.Strs(t, tree["below"], "below"), []string{"ads.acc-listed.example", "more.acc-listed.example", "track.acc-listed.example"}) {
		t.Errorf("block_tree = %v", tree)
	}
	if at := rowOn(t, suite.Call(t, "block_tree", on(map[string]any{"under": "ads.acc-listed.example"})), first); !acctest.BoolOf(at["listed"]) || len(acctest.Strs(t, at["below"], "below")) != 0 {
		t.Errorf("at a listed name = %v", at)
	}
	if good := rowOn(t, suite.Call(t, "block_tree", on(map[string]any{"list": "allowed", "under": "good.acc-listed.example"})), first); !acctest.BoolOf(good["listed"]) {
		t.Errorf("at an allowed name = %v", good)
	}

	// emptied: a dry run says how many would go; then the list is empty, the other is not, and a second time there is nothing to do
	dry = suite.Call(t, "block_flush", on(map[string]any{"list": "blocked", "dry_run": true}))
	if blocked, _ := lists(); acctest.Num(t, dry["removed"], "removed") != len(blocked) || len(blocked) != len(blockedBefore)+3 {
		t.Errorf("a dry run of emptying the blocked names = %v", dry)
	}
	flushed := suite.Call(t, "block_flush", on(map[string]any{"list": "blocked"}))
	if blocked, allowed := lists(); !acctest.BoolOf(flushed["changed"]) || len(blocked) != 0 || !slices.Contains(allowed, "good.acc-listed.example") {
		t.Errorf("emptied = %v, leaving %v blocked and %v allowed", flushed, blocked, allowed)
	}
	if nothing := suite.Call(t, "block_flush", on(map[string]any{"list": "blocked"})); acctest.BoolOf(nothing["changed"]) {
		t.Errorf("emptied twice = %v", nothing)
	}
	if emptied := suite.Call(t, "block_flush", on(map[string]any{"list": "allowed"})); acctest.Num(t, emptied["removed"], "removed") != len(allowedBefore)+1 {
		t.Errorf("the allowed names emptied = %v", emptied)
	}
	if msg := suite.CallErr(t, "block_flush", on(map[string]any{"list": " "})); !strings.Contains(msg, "which list") {
		t.Errorf("block_flush with no list = %q", msg)
	}
}

// The audits of what the servers say of themselves: their cluster, their
// accounts, their queries and their apps.
func TestAuditsOfTheServersThemselves(t *testing.T) {
	t.Parallel()

	names(t)
	findings := func(tool string, args map[string]any) []map[string]any {
		t.Helper()
		out := suite.Call(t, tool, args)
		if out["failed"] != nil {
			t.Errorf("%s could not ask every server: %v", tool, out["failed"])
		}

		return acctest.Rows(t, out["findings"], "findings")
	}

	// servers in no cluster have nothing to find, and a cluster just made is whole
	if found := findings("audit_cluster", nil); len(found) != 0 {
		t.Errorf("audit_cluster = %v", found)
	}

	// the administrator the servers come with signs in with a password alone, which is said once for the servers it is so on
	admin := one(t, findings("audit_access", nil), "admin_no_two_factor", "admin")
	if !strings.Contains(acctest.Str(admin["detail"]), "the administrator admin signs in with a password alone") || admin["servers"] != nil {
		t.Errorf("the administrator's finding = %v", admin)
	}

	// every server runs the one app scripts/testenv.sh installs, so none runs what another does not
	for _, f := range findings("audit_apps", nil) {
		if f["problem"] == "app_only_on" || f["problem"] == "app_versions_differ" {
			t.Errorf("audit_apps found %v, and the servers were set up alike", f)
		}
	}

	// a name asked for often that does not exist is found once the log has it; every server resolves and keeps a log
	missing := "acc-never-made." + firstZone
	for range 6 {
		suite.Call(t, "dns_resolve", on(map[string]any{"name": missing}))
	}
	var found []map[string]any
	isMissing := func(f map[string]any) bool { return f["problem"] == "name_not_found" && f["name"] == missing }
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		found = findings("audit_queries", map[string]any{"problems": []string{"name_not_found", "not_resolving", "no_query_log"}})

		return slices.ContainsFunc(found, isMissing)
	}) {
		t.Fatalf("audit_queries never found the name asked for six times: %v", found)
	}
	for _, f := range found {
		switch {
		case isMissing(f):
			if f["zone"] != firstZone || !strings.Contains(acctest.Str(f["detail"]), "does not exist in "+firstZone) {
				t.Errorf("the name that does not exist = %v", f)
			}
		case f["problem"] != "name_not_found":
			t.Errorf("audit_queries found %v on servers that resolve and keep a log", f)
		default:
		}
	}
}
