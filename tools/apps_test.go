package tools

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// What the store offers: a newer Split Horizon than dock has, the log app in
// the version dock has, and an app nobody has installed.
const storeApps = `{"storeApps":[{"name":"Split Horizon","version":"1.1","description":"Different answers for public and private networks.","url":"https://download.example.org/SplitHorizonApp.zip","size":"11 KB","installed":true,"installedVersion":"1.0","updateAvailable":true},{"name":"Query Logs (Sqlite)","version":"8","url":"https://download.example.org/QueryLogsSqliteApp.zip","size":"1 MB","installed":true,"installedVersion":"8","updateAvailable":false},{"name":"Wild IP","version":"1.0","description":"Answers for an address written in a name.","url":"https://download.example.org/WildIpApp.zip","size":"9 KB","installed":false}]}`

// appsPair is the pair with two apps on dock, none on rpi, and a store only
// dock can reach.
func appsPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.Answer("apps/list", `{"apps":[`+appJSON("Query Logs (Sqlite)", "8", true)+`,`+appJSON("Split Horizon", "1.0", false)+`]}`)
	p.rpi.Answer("apps/list", `{"apps":[]}`)
	p.dock.Answer("apps/listStoreApps", storeApps)
	p.rpi.Fail("apps/listStoreApps", "error", "Could not reach the app store.")
	p.both("apps/downloadAndInstall", `{"installedApp":`+appJSON("Wild IP", "1.0", false)+`}`)
	p.both("apps/downloadAndUpdate", `{"updatedApp":`+appJSON("Split Horizon", "1.1", false)+`}`)
	p.both("apps/install", `{"installedApp":`+appJSON("Own App", "0.1", false)+`}`)
	p.both("apps/update", `{"updatedApp":`+appJSON("Split Horizon", "1.2", false)+`}`)
	p.both("apps/uninstall", `{}`)
	p.both("apps/config/get", `{"config":"{\"enable\": true}"}`)
	p.both("apps/config/set", `{}`)

	return p
}

// appWrites are how many calls that install, update, configure or uninstall
// an app a server got.
func appWrites(server *technitiumtest.Server) int {
	n := 0
	for _, call := range []string{"downloadAndInstall", "downloadAndUpdate", "install", "update", "uninstall", "config/set"} {
		n += len(server.Requests("apps/" + call))
	}

	return n
}

func TestAppList(t *testing.T) {
	t.Parallel()

	p := appsPair(t)
	suite := p.session(t, Options{})

	rows := acctest.Rows(t, suite.Call(t, "app_list", nil)["servers"], "servers")
	installed := acctest.Rows(t, rows[0]["installed"], "installed")
	if len(installed) != 2 || installed[0]["name"] != "Query Logs (Sqlite)" || !acctest.BoolOf(installed[0]["logs_queries"]) || !slices.Equal(acctest.Strs(t, installed[1]["does"], "does"), []string{"App.SplitHorizon"}) || installed[1]["latest"] != nil || rows[0]["store"] != nil || len(acctest.Rows(t, rows[1]["installed"], "installed")) != 0 || len(p.dock.Requests("apps/listStoreApps")) != 0 {
		t.Errorf("app_list = %v", rows)
	}

	// with the store: the newer version beside the one installed, what else there is, and a store that cannot be asked said so
	rows = acctest.Rows(t, suite.Call(t, "app_list", map[string]any{"store": true})["servers"], "servers")
	installed = acctest.Rows(t, rows[0]["installed"], "installed")
	offered := acctest.Rows(t, rows[0]["store"], "store")
	if installed[0]["latest"] != nil || installed[1]["latest"] != "1.1" || len(offered) != 1 || offered[0]["name"] != "Wild IP" || offered[0]["size"] != "9 KB" {
		t.Errorf("with the store, dock = %v", rows[0])
	}
	if !strings.Contains(acctest.Str(rows[1]["store_note"]), "the store could not be asked: ") || rows[1]["error"] != nil {
		t.Errorf("with the store, rpi = %v", rows[1])
	}
}

// An app comes from the store by its name, from an address the server
// fetches, or from a zip file sent to it; one that is installed is updated.
func TestAppInstall(t *testing.T) {
	t.Parallel()

	p := appsPair(t)
	suite := p.session(t, everything)
	dir := t.TempDir()
	own := filepath.Join(dir, "own.zip")
	if err := os.WriteFile(own, zipOf(t, "OwnApp.dll", "dnsApp.config"), 0o600); err != nil {
		t.Fatal(err)
	}
	notZip := filepath.Join(dir, "notes.zip")
	if err := os.WriteFile(notZip, []byte("not a zip at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	dry := suite.Call(t, "app_install", map[string]any{"server": "dock", "name": "wild ip", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have installed the app Wild IP on dock from the store"}) || dry["after"] != nil || appWrites(p.dock) != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	fresh := suite.Call(t, "app_install", map[string]any{"server": "dock", "name": "wild ip"})
	if asked := p.dock.Last("apps/downloadAndInstall"); asked.Params.Get("name") != "Wild IP" || asked.Params.Get("url") != "https://download.example.org/WildIpApp.zip" || acctest.Object(t, fresh["after"], "after")["version"] != "1.0" {
		t.Errorf("installed from the store = %v, asked with %v", fresh, asked.Params)
	}
	updated := suite.Call(t, "app_install", map[string]any{"server": "dock", "name": "split horizon"})
	if asked := p.dock.Last("apps/downloadAndUpdate"); asked.Params.Get("name") != "Split Horizon" || asked.Params.Get("url") != "https://download.example.org/SplitHorizonApp.zip" || !slices.Equal(acctest.Strs(t, updated["changes"], "changes"), []string{"updated the app Split Horizon on dock from the store, keeping its configuration"}) {
		t.Errorf("updated from the store = %v, asked with %v", updated, asked.Params)
	}
	sent := appWrites(p.dock)
	if same := suite.Call(t, "app_install", map[string]any{"server": "dock", "name": "Query Logs (Sqlite)"}); acctest.BoolOf(same["changed"]) || !strings.Contains(acctest.Str(same["note"]), "the store's version of the app already") || appWrites(p.dock) != sent {
		t.Errorf("the version it has = %v", same)
	}

	// from an address, and from a file: sent as a file, under the name asked for
	suite.Call(t, "app_install", map[string]any{"server": "dock", "name": "Own App", "url": "https://apps.example.org/own.zip"})
	if asked := p.dock.Last("apps/downloadAndInstall"); asked.Params.Get("name") != "Own App" || asked.Params.Get("url") != "https://apps.example.org/own.zip" || len(p.dock.Requests("apps/listStoreApps")) != 4 {
		t.Errorf("installed from an address with %v, the store asked %d times", asked.Params, len(p.dock.Requests("apps/listStoreApps")))
	}
	suite.Call(t, "app_install", map[string]any{"server": "rpi", "name": "Own App", "path": own})
	if asked := p.rpi.Last("apps/install"); len(asked.File) == 0 || asked.Params.Get("name") != "Own App" || len(p.rpi.Requests("apps/listStoreApps")) != 0 {
		t.Errorf("installed from a file with %v, %d bytes", asked.Params, len(asked.File))
	}
	suite.Call(t, "app_install", map[string]any{"server": "dock", "name": "Split Horizon", "path": own})
	if asked := p.dock.Last("apps/update"); len(asked.File) == 0 || asked.Params.Get("name") != "Split Horizon" {
		t.Errorf("updated from a file with %v, %d bytes", asked.Params, len(asked.File))
	}

	sent = appWrites(p.dock) + appWrites(p.rpi)
	for msg, args := range map[string]map[string]any{
		"which app":                            {"server": "dock", "name": " "},
		"not both":                             {"server": "dock", "name": "Own App", "url": "https://apps.example.org/own.zip", "path": own},
		"only over https://":                   {"server": "dock", "name": "Own App", "url": "http://apps.example.org/own.zip"},
		`the store has no app named "Nothing"`: {"server": "dock", "name": "Nothing"},
		"rpi could not ask the store for the app":       {"server": "rpi", "name": "Wild IP"},
		"is no zip file, which is what an app comes as": {"server": "dock", "name": "Own App", "path": notZip},
		"reading the app's zip file":                    {"server": "dock", "name": "Own App", "path": filepath.Join(dir, "missing.zip")},
	} {
		if got := suite.CallErr(t, "app_install", args); !strings.Contains(got, msg) {
			t.Errorf("app_install %v = %q, want %q in it", args, got, msg)
		}
	}
	if now := appWrites(p.dock) + appWrites(p.rpi); now != sent {
		t.Errorf("%d refused installs reached a server", now-sent)
	}
}

// An app's configuration is read as JSON where it is JSON, written whole
// with what it was given back, and refused when it would break the app.
func TestAppConfig(t *testing.T) {
	t.Parallel()

	p := appsPair(t)
	suite := p.session(t, everything)

	got := suite.Call(t, "app_config_get", map[string]any{"name": "split horizon"})
	rows := acctest.Rows(t, got["servers"], "servers")
	if !acctest.BoolOf(acctest.Object(t, rows[0]["config"], "config")["enable"]) || !acctest.BoolOf(rows[1]["missing"]) || acctest.BoolOf(got["differ"]) || p.dock.Last("apps/config/get").Params.Get("name") != "Split Horizon" || len(p.rpi.Requests("apps/config/get")) != 0 {
		t.Errorf("app_config_get = %v", got)
	}
	if msg := suite.CallErr(t, "app_config_get", map[string]any{"name": "Nothing"}); !strings.Contains(msg, "no server asked has an app named Nothing installed") {
		t.Errorf("an app nobody has = %q", msg)
	}
	// text that is not JSON is given as the text it is, and an app with none has no config at all
	p.dock.Answer("apps/config/get", `{"config":"# a list\n10.0.0.0/8"}`)
	if text := acctest.Rows(t, suite.Call(t, "app_config_get", map[string]any{"server": "dock", "name": "Split Horizon"})["servers"], "servers")[0]; text["config"] != "# a list\n10.0.0.0/8" {
		t.Errorf("a configuration that is text = %v", text)
	}
	p.dock.Answer("apps/config/get", `{"config":null}`)
	if none := acctest.Rows(t, suite.Call(t, "app_config_get", map[string]any{"server": "dock", "name": "Split Horizon"})["servers"], "servers")[0]; none["config"] != nil || acctest.BoolOf(none["missing"]) {
		t.Errorf("an app with no configuration = %v", none)
	}

	p.dock.Answer("apps/config/get", `{"config":"{\"enable\": true}"}`)
	if same := suite.Call(t, "app_config_set", map[string]any{"server": "dock", "name": "Split Horizon", "config": " {\"enable\": true}\n"}); acctest.BoolOf(same["changed"]) || !strings.Contains(acctest.Str(same["note"]), "that configuration already") || appWrites(p.dock) != 0 {
		t.Errorf("set to what it is = %v", same)
	}
	dry := suite.Call(t, "app_config_set", map[string]any{"server": "dock", "name": "split horizon", "config": `{"enable":false}`, "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have set the configuration of the app Split Horizon on dock, 16 characters in place of 16"}) || dry["before"] != `{"enable": true}` || appWrites(p.dock) != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	// written, and read back: a server that says ok and still has the old one is said to
	set := suite.Call(t, "app_config_set", map[string]any{"server": "dock", "name": "Split Horizon", "config": `{"enable":false}`})
	if asked := p.dock.Last("apps/config/set"); asked.Params.Get("name") != "Split Horizon" || asked.Params.Get("config") != `{"enable":false}` || !strings.Contains(acctest.Str(set["note"]), "reads back otherwise") || set["before"] != `{"enable": true}` {
		t.Errorf("set = %v, asked with %v", set, asked.Params)
	}
	p.dock.Then("apps/config/set", func(technitiumtest.Request) {
		p.dock.Answer("apps/config/get", `{"config":"{\"enable\":false}"}`)
	})
	if set = suite.Call(t, "app_config_set", map[string]any{"server": "dock", "name": "Split Horizon", "config": `{"enable":false}`}); set["note"] != nil || !acctest.BoolOf(set["changed"]) {
		t.Errorf("set and read back = %v", set)
	}

	sent := appWrites(p.dock) + appWrites(p.rpi)
	for msg, args := range map[string]map[string]any{
		"is JSON and what was given is not":  {"server": "dock", "name": "Split Horizon", "config": `{"enable":`},
		"rpi has no app named Split Horizon": {"server": "rpi", "name": "Split Horizon", "config": `{}`},
		"which app":                          {"server": "dock", "name": "", "config": `{}`},
	} {
		if got := suite.CallErr(t, "app_config_set", args); !strings.Contains(got, msg) {
			t.Errorf("app_config_set %v = %q, want %q in it", args, got, msg)
		}
	}
	if now := appWrites(p.dock) + appWrites(p.rpi); now != sent {
		t.Errorf("%d refused changes reached a server", now-sent)
	}
}

// An app is uninstalled by the name the server has it under, with what goes
// with it said, and a server that says ok and still has it is not believed.
func TestAppDelete(t *testing.T) {
	t.Parallel()

	p := appsPair(t)
	suite := p.session(t, everything)

	if nothing := suite.Call(t, "app_delete", map[string]any{"server": "rpi", "name": "Split Horizon"}); acctest.BoolOf(nothing["changed"]) || !strings.Contains(acctest.Str(nothing["note"]), "nothing to uninstall") || appWrites(p.rpi) != 0 {
		t.Errorf("an app that is not installed, uninstalled = %v", nothing)
	}
	dry := suite.Call(t, "app_delete", map[string]any{"server": "dock", "name": "query logs (sqlite)", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have uninstalled the app Query Logs (Sqlite) 8 from dock"}) || !strings.Contains(acctest.Str(dry["note"]), "kept the log of queries") || appWrites(p.dock) != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	if msg := suite.CallErr(t, "app_delete", map[string]any{"server": "dock", "name": "Split Horizon"}); !strings.Contains(msg, "the server said ok and dock still has the app Split Horizon installed") || p.dock.Last("apps/uninstall").Params.Get("name") != "Split Horizon" {
		t.Errorf("an uninstall that did not take = %q", msg)
	}
	p.dock.Then("apps/uninstall", func(technitiumtest.Request) {
		p.dock.Answer("apps/list", `{"apps":[`+appJSON("Query Logs (Sqlite)", "8", true)+`]}`)
	})
	gone := suite.Call(t, "app_delete", map[string]any{"server": "dock", "name": "split horizon"})
	if was := acctest.Object(t, gone["was"], "was"); was["version"] != "1.0" || gone["note"] != nil || !slices.Equal(acctest.Strs(t, gone["changes"], "changes"), []string{"uninstalled the app Split Horizon 1.0 from dock"}) {
		t.Errorf("uninstalled = %v", gone)
	}
}
