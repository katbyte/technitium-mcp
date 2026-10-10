//go:build integration

package integration

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// The server's own log: a file for today, read whole and in part, and
// deleted, alone and with every other.
//
// It does not run beside the other tests: it deletes every log file there is.
//
//nolint:paralleltest // it deletes the server's log files, which a test reading one beside it would not find
func TestLogFiles(t *testing.T) {
	c := first(t)
	ctx := t.Context()

	// something to be logged: a zone made and deleted is written to today's file
	zone(t, c, "logged.it.test")
	var today technitium.LogFile
	if !acctest.EventuallyWithin(30*time.Second, func() bool {
		files, err := c.LogFiles(ctx)
		if err != nil || len(files) == 0 {
			return false
		}
		today = files[0]

		return true
	}) {
		t.Fatal("the server has no log file though something was just done on it")
	}
	if _, err := time.Parse("2006-01-02", today.FileName); err != nil || today.Size == "" {
		t.Errorf("the newest log file = %+v, want one named for a day", today)
	}
	text, err := c.DownloadLog(ctx, today.FileName, 0)
	if err != nil || !strings.Contains(text, "logged.it.test") {
		t.Errorf("DownloadLog = %d characters without the zone just made, %v", len(text), err)
	}
	if part, err := c.DownloadLog(ctx, today.FileName, 1); err != nil || part == "" {
		t.Errorf("the first megabyte = %d characters, %v", len(part), err)
	}
	if _, err := c.DownloadLog(ctx, "1999-01-01", 0); err == nil {
		t.Error("a log file that is not there was read")
	}

	// a log file that is not there is deleted without a word
	if err := c.DeleteLog(ctx, "1999-01-01"); err != nil {
		t.Errorf("deleting a log file that is not there = %v: the server now says so", err)
	}
	if err := c.DeleteLog(ctx, today.FileName); err != nil {
		t.Errorf("DeleteLog = %v", err)
	}
	// the server begins the day's file again as soon as it has something to write, which deleting one is
	if again, err := c.DownloadLog(ctx, today.FileName, 0); err == nil && strings.Contains(again, "logged.it.test") {
		t.Error("the log file that was deleted still has what was in it")
	}
	if err := c.DeleteAllLogs(ctx); err != nil {
		t.Errorf("DeleteAllLogs = %v", err)
	}
	if files, err := c.LogFiles(ctx); err != nil || len(files) > 1 {
		t.Errorf("after every log file was deleted there are %+v, %v", files, err)
	}
}

// The log of queries exported whole as CSV, for what a search of it finds a
// page of.
func TestQueryLogExport(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	z := "export-" + string(world.Topology) + ".it.test"
	zone(t, c, z)
	if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: z, Name: "www." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.8.8.1"}}); err != nil {
		t.Fatal(err)
	}
	apps, err := c.Apps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var q technitium.LogQuery
	for _, app := range apps {
		if classPath, ok := app.QueryLog(); ok {
			q = technitium.LogQuery{App: app.Name, ClassPath: classPath, Name: "www." + z}
		}
	}
	if q.App == "" {
		t.Fatalf("no app keeps a log of queries among %+v: scripts/testenv.sh installs one", apps)
	}
	if _, err := c.Resolve(ctx, technitium.ResolveQuery{Via: "127.0.0.1", Name: "www." + z, Type: "A"}); err != nil {
		t.Fatal(err)
	}

	var csv string
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		csv, err = c.ExportQueryLog(ctx, q)

		return err == nil && strings.Contains(csv, "www."+z)
	}) {
		t.Fatalf("the export never had the query just made: %q, %v", csv, err)
	}
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "RowNumber,Timestamp,ClientIpAddress,") || !strings.Contains(lines[0], ",Domain,Type,") || !strings.Contains(lines[1], "www."+z) || !strings.Contains(lines[1], "A 10.8.8.1") {
		t.Errorf("the export = %q, want a line of headings and the query under it", csv)
	}
	if _, err := c.ExportQueryLog(ctx, technitium.LogQuery{App: "No Such App", ClassPath: "No.Such"}); err == nil {
		t.Error("the log of an app that is not installed was exported")
	}
}

// The server's own two lists as trees, added to many names at a time, and
// emptied.
//
// It does not run beside the other tests: it empties both lists.
//
//nolint:paralleltest // it empties the server's blocked and allowed lists, which a test of blocking beside it relies on
func TestListsImportedAndFlushed(t *testing.T) {
	c := first(t)
	ctx := t.Context()
	blockedBefore, err := c.BlockedNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	allowedBefore, err := c.AllowedNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.FlushBlocked(noCancel(t))
		_ = c.FlushAllowed(noCancel(t))
		if len(blockedBefore) > 0 {
			_ = c.ImportBlocked(noCancel(t), blockedBefore)
		}
		if len(allowedBefore) > 0 {
			_ = c.ImportAllowed(noCancel(t), allowedBefore)
		}
	})

	if err := c.ImportBlocked(ctx, []string{"ads.listed.example", "track.listed.example", "ads.listed.example"}); err != nil {
		t.Fatalf("ImportBlocked = %v", err)
	}
	if err := c.ImportAllowed(ctx, []string{"good.listed.example"}); err != nil {
		t.Fatalf("ImportAllowed = %v", err)
	}
	if names, err := c.BlockedNames(ctx); err != nil || !slices.Contains(names, "ads.listed.example") || !slices.Contains(names, "track.listed.example") || len(names) != len(blockedBefore)+2 {
		t.Errorf("the blocked names once two were imported = %v, %v", names, err)
	}

	// as a tree: the names under a name that are listed or lead to listed names, each written whole, and at a listed name the records it is answered with
	isSOA := func(r technitium.Record) bool { return r.Type == "SOA" }
	under, err := c.BlockedUnder(ctx, "listed.example")
	if err != nil || under.Domain != "listed.example" || !slices.Equal(under.Zones, []string{"ads.listed.example", "track.listed.example"}) || len(under.Records) != 0 {
		t.Errorf("BlockedUnder = %+v, %v", under, err)
	}
	at, err := c.BlockedUnder(ctx, "ads.listed.example")
	if err != nil || at.Domain != "ads.listed.example" || len(at.Zones) != 0 || !slices.ContainsFunc(at.Records, isSOA) {
		t.Errorf("at a blocked name = %+v, %v", at, err)
	}
	// asked for a name that only leads on to one other, the server answers for the first place below it where there is more: from the root that is where the test's names part, when nothing else is listed
	if root, err := c.BlockedUnder(ctx, ""); err != nil || (len(blockedBefore) == 0 && root.Domain != "listed.example") {
		t.Errorf("the root of the blocked names = %+v, %v", root, err)
	}
	if allowed, err := c.AllowedUnder(ctx, "listed.example"); err != nil || (len(allowedBefore) == 0 && (allowed.Domain != "good.listed.example" || !slices.ContainsFunc(allowed.Records, isSOA))) {
		t.Errorf("AllowedUnder = %+v, %v", allowed, err)
	}

	if err := c.FlushBlocked(ctx); err != nil {
		t.Errorf("FlushBlocked = %v", err)
	}
	if names, err := c.BlockedNames(ctx); err != nil || len(names) != 0 {
		t.Errorf("the blocked names once flushed = %v, %v", names, err)
	}
	if names, err := c.AllowedNames(ctx); err != nil || !slices.Contains(names, "good.listed.example") {
		t.Errorf("flushing the blocked names took the allowed ones too: %v, %v", names, err)
	}
	if err := c.FlushAllowed(ctx); err != nil {
		t.Errorf("FlushAllowed = %v", err)
	}
	if names, err := c.AllowedNames(ctx); err != nil || len(names) != 0 {
		t.Errorf("the allowed names once flushed = %v, %v", names, err)
	}
}

// What the server has counted since it started, both ways it gives it, and
// its statistics deleted.
//
// It does not run beside the other tests: it deletes every statistic.
//
//nolint:paralleltest // it deletes the server's statistics, which a test counting queries beside it relies on
func TestMetricsAndStatsDeleted(t *testing.T) {
	c := first(t)
	ctx := t.Context()

	if err := c.HealthCheck(ctx, "", ""); err != nil {
		t.Errorf("HealthCheck = %v", err)
	}
	if err := c.HealthCheck(ctx, "localhost", "AAAA"); err != nil {
		t.Errorf("HealthCheck for a name and a type = %v", err)
	}

	got, err := c.Metrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if started, ok := technitium.ParseTime(got.UpSince); !ok || time.Since(started) < 0 || got.UptimeSeconds <= 0 {
		t.Errorf("Metrics = %+v, want a server that started a while ago", got)
	}
	text, err := c.MetricsText(ctx)
	// the counters are named queries_total and so on, where the API document shows total_queries
	if err != nil || !strings.Contains(text, "uptime_seconds ") || !strings.Contains(text, "queries_total ") || !strings.Contains(text, "# TYPE ") {
		t.Errorf("MetricsText = %q, %v", text, err)
	}

	if err := c.DeleteAllStats(ctx); err != nil {
		t.Fatalf("DeleteAllStats = %v", err)
	}
	stats, err := c.Stats(ctx, technitium.StatsWindow{Type: "LastDay"})
	if err != nil || stats.Totals.Queries > 5 {
		t.Errorf("a day's statistics once all were deleted = %+v, %v", stats.Totals, err)
	}
}

// An app installed from an address and from its file, updated both ways,
// its configuration written, and taken off again.
//
// It does not run beside the other tests: one of them counts the apps.
//
//nolint:paralleltest // it installs and removes an app, which a test listing the apps beside it would count
func TestAppsInstalledAndRemoved(t *testing.T) {
	c := first(t)
	ctx := t.Context()
	const name = "What Is My Dns"

	store, err := c.StoreApps(ctx)
	if err != nil {
		t.Fatalf("StoreApps = %v: the server asks its maker's site for the list", err)
	}
	i := slices.IndexFunc(store, func(a technitium.StoreApp) bool { return a.Name == name })
	if i < 0 || store[i].Version == "" || store[i].Size == "" || !strings.HasPrefix(store[i].URL, "https://") || store[i].Installed {
		t.Fatalf("the store's %s = %+v among %d apps", name, store, len(store))
	}
	if !slices.ContainsFunc(store, func(a technitium.StoreApp) bool { return a.Installed && a.InstalledVersion != "" }) {
		t.Errorf("no app in the store is said to be installed, and scripts/testenv.sh installs one: %+v", store)
	}
	installed := func() *technitium.App {
		t.Helper()
		apps, listErr := c.Apps(ctx)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if at := slices.IndexFunc(apps, func(a technitium.App) bool { return a.Name == name }); at >= 0 {
			return &apps[at]
		}

		return nil
	}
	_ = c.UninstallApp(ctx, name)
	t.Cleanup(func() { _ = c.UninstallApp(noCancel(t), name) })

	// the server fetches it itself
	app, err := c.InstallAppFrom(ctx, name, store[i].URL)
	if err != nil || app.Name != name || app.Version != store[i].Version || len(app.Parts) == 0 || installed() == nil {
		t.Fatalf("InstallAppFrom = %+v, %v", app, err)
	}
	if _, err := c.InstallAppFrom(ctx, name, store[i].URL); err == nil {
		t.Error("an app was installed twice")
	}
	if app, err = c.UpdateAppFrom(ctx, name, store[i].URL); err != nil || app.Name != name {
		t.Errorf("UpdateAppFrom = %+v, %v", app, err)
	}

	// its configuration is text of its own, written and read back
	if err := c.SetAppConfig(ctx, name, `{"made":"by the SDK suite"}`); err != nil {
		t.Errorf("SetAppConfig = %v", err)
	}
	if config, err := c.AppConfig(ctx, name); err != nil || !strings.Contains(config, "by the SDK suite") {
		t.Errorf("the configuration read back = %q, %v", config, err)
	}

	if err := c.UninstallApp(ctx, name); err != nil || installed() != nil {
		t.Errorf("UninstallApp = %v, and the app is %+v", err, installed())
	}
	// an app that is not installed is uninstalled without a word
	if err := c.UninstallApp(ctx, name); err != nil {
		t.Errorf("uninstalling an app that is not installed = %v: the server now says so", err)
	}

	// and from its zip file, sent to the server
	appZip := fetch(t, store[i].URL)
	if app, err = c.InstallApp(ctx, name, appZip); err != nil || app.Name != name || app.Version != store[i].Version || installed() == nil {
		t.Fatalf("InstallApp = %+v, %v", app, err)
	}
	if app, err = c.UpdateApp(ctx, name, appZip); err != nil || app.Name != name {
		t.Errorf("UpdateApp = %+v, %v", app, err)
	}
	if _, err := c.UpdateApp(ctx, "Not Installed", appZip); err == nil {
		t.Error("an app that is not installed was updated")
	}
	// what is no zip file is not sent at all: the server keeps what it is sent as an app before it finds it cannot read it, and the folder it leaves stops another server joining its cluster (api-defs/README.md)
	if _, err := c.InstallApp(ctx, "Not An App", []byte("not a zip file")); err == nil || installedNamed(t, c, "Not An App") {
		t.Errorf("something that is no zip file was installed as an app: %v", err)
	}
}

// installedNamed reports whether the server lists an app under a name.
func installedNamed(t *testing.T, c *technitium.Client, name string) bool {
	t.Helper()

	apps, err := c.Apps(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	return slices.ContainsFunc(apps, func(a technitium.App) bool { return a.Name == name })
}

// fetch reads what is at an address.
func fetch(t *testing.T, address string) []byte {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, address, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetching %s: %v", address, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fetching %s: %s, %v", address, resp.Status, err)
	}

	return raw
}

// olderThan reports whether a server's version, as its settings give it, is
// before the one named.
func olderThan(version any, major, minor int) bool {
	var has [2]int
	if n, _ := fmt.Sscanf(fmt.Sprint(version), "%d.%d", &has[0], &has[1]); n != 2 {
		return false
	}

	return has[0] < major || (has[0] == major && has[1] < minor)
}

// Every setting by the API's own name: read without what is secret, set a
// few at a time, a name that is no setting refused, and one a later version
// brought refused where the server would pass it over.
//
// It does not run beside the other tests: it sets the server's transfer
// keys as one list, and settings other tests read.
//
//nolint:paralleltest // it writes the server's settings and its transfer keys whole, which a test beside it would read part way
func TestAllSettings(t *testing.T) {
	ready(t)
	c := first(t)
	ctx := t.Context()

	before, err := c.AllSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before["version"] == "" || before["dnsServerDomain"] != world.Domain(world.First) || len(before) < 80 {
		t.Errorf("AllSettings = %d settings for %v", len(before), before["dnsServerDomain"])
	}
	for name := range before {
		if lower := strings.ToLower(name); strings.HasSuffix(lower, "password") || strings.HasSuffix(lower, "secret") {
			t.Errorf("AllSettings gives %s", name)
		}
	}
	// the settings this client names are ones the server has, but for the few it takes and never gives back under the same name - the two certificate passwords and the proxy, which it gives as one thing - and any a later version than its own brought
	var lacking []string
	for _, name := range technitium.SettingNames {
		_, has := before[name]
		neverRead := slices.Contains(technitium.SettingsNeverRead, name)
		if has && neverRead {
			t.Errorf("AllSettings gives %s, which the server is held never to give back", name)
		}
		if !has && !neverRead {
			lacking = append(lacking, name)
		}
	}

	// 15.6 brought one setting, which a server before it lacks
	var broughtLater []string
	if olderThan(before["version"], 15, 6) {
		broughtLater = []string{"enableCachePrefetch"}
	}
	if !slices.Equal(lacking, broughtLater) {
		t.Errorf("the settings version %v of the server lacks = %v, want %v", before["version"], lacking, broughtLater)
	}

	// one it lacks, the server says ok to and passes over, which the client makes an error
	for _, name := range lacking {
		if _, err := c.SetSettings(ctx, map[string]string{name: "true"}); err == nil || !strings.Contains(err.Error(), "said ok and has no setting named "+name) {
			t.Errorf("SetSettings with %s, which version %v lacks = %v", name, before["version"], err)
		}
	}

	was, isNumber := before["cachePrefetchTrigger"].(float64)
	if !isNumber {
		t.Fatalf("cachePrefetchTrigger = %v, want a number", before["cachePrefetchTrigger"])
	}
	t.Cleanup(func() {
		_, _ = c.SetSettings(noCancel(t), map[string]string{"cachePrefetchTrigger": "9", "serveStaleTtl": "259200"})
		_ = c.DeleteTSIGKey(noCancel(t), "it-key.test")
	})
	after, err := c.SetSettings(ctx, map[string]string{"cachePrefetchTrigger": "11", "serveStaleTtl": "86400"})
	if err != nil {
		t.Fatalf("SetSettings = %v", err)
	}
	if after["cachePrefetchTrigger"] != float64(11) || was == 11 || after["serveStaleTtl"] != float64(86400) || after["dnsServerDomain"] != before["dnsServerDomain"] {
		t.Errorf("after two settings were set = trigger %v (was %v), stale %v", after["cachePrefetchTrigger"], was, after["serveStaleTtl"])
	}
	if _, err := c.SetSettings(ctx, map[string]string{"noSuchSetting": "1"}); err == nil {
		t.Error("a setting that is not one was set")
	}

	// a transfer key added beside the ones there are - a cluster has one of its own - then changed, and taken away
	keysBefore, err := c.TSIGKeyNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if clustered := world.Topology == testenv.Cluster; (len(keysBefore) > 0) != clustered {
		t.Errorf("the keys before one was added = %v in the %s topology: only a cluster has one of its own", keysBefore, world.Topology)
	}
	if err := c.SetTSIGKey(ctx, "it-key.test", "aXQtc2VjcmV0LWl0LXNlY3JldA==", ""); err != nil {
		t.Fatalf("SetTSIGKey = %v", err)
	}
	names, err := c.TSIGKeyNames(ctx)
	if err != nil || !slices.Contains(names, "it-key.test") || len(names) != len(keysBefore)+1 {
		t.Errorf("TSIGKeyNames = %v, %v, beside the %v there were", names, err, keysBefore)
	}
	now, err := c.AllSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var added map[string]any
	keys, isList := now["tsigKeys"].([]any)
	for _, k := range keys {
		if key, isObject := k.(map[string]any); isObject && key["keyName"] == "it-key.test" {
			added = key
		}
	}
	if !isList || added["algorithmName"] != "hmac-sha256" || len(added) != 2 {
		t.Errorf("the keys as they are read back = %v, want the new one by its name and algorithm and no more", now["tsigKeys"])
	}
	if err := c.SetTSIGKey(ctx, "it-key.test", "Y2hhbmdlZC1jaGFuZ2VkLWNoYW5nZWQ=", "hmac-sha512"); err != nil {
		t.Errorf("the key changed = %v", err)
	}
	if typed, err := c.Settings(ctx); err != nil || !slices.ContainsFunc(typed.TSIGKeys, func(k technitium.TSIGKey) bool { return k.Name == "it-key.test" && k.Algorithm == "hmac-sha512" }) || len(typed.TSIGKeys) != len(keysBefore)+1 {
		t.Errorf("the settings read by type have the keys %+v, %v", typed.TSIGKeys, err)
	}
	if err := c.DeleteTSIGKey(ctx, "it-key.test"); err != nil {
		t.Errorf("DeleteTSIGKey = %v", err)
	}
	if names, err = c.TSIGKeyNames(ctx); err != nil || !slices.Equal(names, keysBefore) {
		t.Errorf("the keys once the new one was taken away = %v, %v, want %v", names, err, keysBefore)
	}
	// the key a cluster's own catalog is transferred with is not the server's to lose
	if len(keysBefore) > 0 {
		if err := c.DeleteTSIGKey(ctx, keysBefore[0]); err == nil || !strings.Contains(err.Error(), "Cannot remove TSIG key") {
			t.Errorf("the cluster's own key taken away = %v", err)
		}
	}
}

// A backup of a part of the server, and that part put back from it.
//
// It does not run beside the other tests: it writes over the allowed names.
//
//nolint:paralleltest // it restores the server's allowed names from a backup, over whatever a test beside it put there
func TestBackupAndRestore(t *testing.T) {
	c := first(t)
	ctx := t.Context()
	const kept, lost = "kept.backup.example", "lost.backup.example"
	t.Cleanup(func() {
		_ = c.UnallowName(noCancel(t), kept)
		_ = c.UnallowName(noCancel(t), lost)
	})

	// a backup is of what the server has written to disk, and it writes a change to a list a few seconds after it is made: one taken at once does not have the name just allowed
	allowedIn := func(backup []byte) uint64 {
		t.Helper()
		files, readErr := zip.NewReader(bytes.NewReader(backup), int64(len(backup)))
		if readErr != nil {
			t.Fatalf("the backup is no zip file: %v", readErr)
		}
		for _, f := range files.File {
			if f.Name == "allowed.config" {
				return f.UncompressedSize64
			}
		}
		t.Fatalf("the backup has no allowed.config among its %d files", len(files.File))

		return 0
	}
	empty, err := c.Backup(ctx, technitium.BackupItems{AllowedZones: true, DNSSettings: true})
	if err != nil || !bytes.HasPrefix(empty, []byte("PK")) {
		t.Fatalf("Backup = %d bytes, %v", len(empty), err)
	}
	if err := c.AllowName(ctx, kept); err != nil {
		t.Fatal(err)
	}
	var backup []byte
	if !acctest.EventuallyWithin(time.Minute, func() bool {
		backup, err = c.Backup(ctx, technitium.BackupItems{AllowedZones: true, DNSSettings: true})

		return err == nil && allowedIn(backup) > allowedIn(empty)
	}) {
		t.Fatalf("the name just allowed never reached a backup: %v", err)
	}
	if whole, err := c.Backup(ctx, technitium.Everything()); err != nil || len(whole) <= len(backup) {
		t.Errorf("a backup of everything = %d bytes beside %d for two parts, %v", len(whole), len(backup), err)
	}

	// what changed after the backup is undone by restoring it: the name added is gone, the name removed is back
	if err := c.AllowName(ctx, lost); err != nil {
		t.Fatal(err)
	}
	if err := c.UnallowName(ctx, kept); err != nil {
		t.Fatal(err)
	}
	settings, err := c.Restore(ctx, technitium.BackupItems{AllowedZones: true}, true, backup)
	if err != nil || settings.Domain != world.Domain(world.First) {
		t.Fatalf("Restore = %+v, %v", settings, err)
	}
	if names, err := c.AllowedNames(ctx); err != nil || !slices.Contains(names, kept) || slices.Contains(names, lost) {
		t.Errorf("the allowed names once the backup was restored = %v, %v", names, err)
	}
	if _, err := c.Restore(ctx, technitium.BackupItems{AllowedZones: true}, false, []byte("not a zip file")); err == nil {
		t.Error("something that is no backup was restored")
	}
}

// A call passed on to another node of a cluster is answered for that node;
// a server in no cluster has no node to pass one on to.
func TestOnNode(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	if world.Topology != testenv.Cluster {
		// a server in no cluster passes the node over without a word and answers for itself
		other := c.OnNode("ns9.nowhere.test")
		through, err := other.Apps(ctx)
		mine, mineErr := c.Apps(ctx)
		if err != nil || mineErr != nil || len(through) == 0 || len(through) != len(mine) || other.Node() != "ns9.nowhere.test" {
			t.Errorf("a server in no cluster asked for the apps of the node %s = %d beside its own %d, %v: it answered for itself when this was written", other.Node(), len(through), len(mine), err)
		}

		return
	}

	// asked of the primary for the secondary, the settings name the secondary
	second := world.Domain(world.Second)
	through := c.OnNode(second)
	stats, err := through.Stats(ctx, technitium.StatsWindow{Type: "LastHour"})
	if err != nil {
		t.Fatalf("the secondary's statistics through the primary = %v", err)
	}
	direct, err := server(t, world.Second).Stats(ctx, technitium.StatsWindow{Type: "LastHour"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Totals.Zones != direct.Totals.Zones || through.Node() != second {
		t.Errorf("the secondary's zones counted through the primary = %d and asked of it = %d", stats.Totals.Zones, direct.Totals.Zones)
	}
	if _, err := c.OnNode("ns9."+testenv.ClusterDomain).Zones(ctx, technitium.ZoneFilter{}); err == nil {
		t.Error("a call was passed on to a node the cluster does not have")
	}
}
