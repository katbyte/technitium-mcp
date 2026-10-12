package tools

import (
	"archive/zip"
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// The settings two servers have: alike but for the cache's size and their
// own names, with a password and a key's secret among dock's.
const (
	dockEverySetting = `{"version":"15.6","dnsServerDomain":"dock.example","forwarders":["9.9.9.9","1.1.1.1"],"cacheMaximumRecordTtl":10000,"enableBlocking":true,"webServiceHttpPort":5380,"proxy":{"type":"Http","address":"192.0.2.1","password":"pr0xy-5ecre7"},"tsigKeys":[{"keyName":"cluster-catalog.example","sharedSecret":"Y2x1c3Rlcg==","algorithmName":"hmac-sha256"},{"keyName":"old.example","sharedSecret":"b2xk","algorithmName":"hmac-sha512"}]}`
	rpiEverySetting  = `{"version":"15.6","dnsServerDomain":"rpi.example","forwarders":["9.9.9.9","1.1.1.1"],"cacheMaximumRecordTtl":20000,"enableBlocking":true,"webServiceHttpPort":5380,"tsigKeys":[]}`
)

// settingsPair is the pair with their settings and their transfer keys.
func settingsPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.Answer("settings/get", dockEverySetting)
	p.dock.Answer("settings/set", dockEverySetting)
	p.dock.Answer("settings/getTsigKeyNames", `{"tsigKeyNames":["cluster-catalog.example","old.example"]}`)
	p.rpi.Answer("settings/get", rpiEverySetting)
	p.rpi.Answer("settings/set", rpiEverySetting)
	p.rpi.Answer("settings/getTsigKeyNames", `{"tsigKeyNames":[]}`)

	return p
}

// zipOf is a zip file holding the files named, each with a few bytes in it.
func zipOf(t *testing.T, names ...string) []byte {
	t.Helper()

	var buf bytes.Buffer
	archive := zip.NewWriter(&buf)
	for _, name := range names {
		f, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("held")); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

// Every setting is given by the name the API knows it under, once where the
// servers agree and side by side where they do not, with nothing secret.
func TestSettingsGet(t *testing.T) {
	t.Parallel()

	p := settingsPair(t)
	suite := p.session(t, Options{})

	all := suite.Call(t, "settings_get", nil)
	rows := map[string]map[string]any{}
	for _, row := range acctest.Rows(t, all["settings"], "settings") {
		rows[acctest.Str(row["name"])] = row
	}
	if acctest.Num(t, all["differ"], "differ") != 4 || len(rows) != 8 || !acctest.BoolOf(rows["enableBlocking"]["value"]) || rows["enableBlocking"]["values"] != nil || acctest.Num(t, acctest.Object(t, rows["cacheMaximumRecordTtl"]["values"], "values")["rpi"], "rpi") != 20000 || rows["cacheMaximumRecordTtl"]["value"] != nil {
		t.Errorf("settings_get = %v", all)
	}
	if text := fmt.Sprint(all); strings.Contains(text, "pr0xy-5ecre7") || strings.Contains(text, "Y2x1c3Rlcg==") || strings.Contains(text, "b2xk") || !strings.Contains(text, "old.example") {
		t.Errorf("settings_get gave a secret, or no key by name: %s", text)
	}

	named := suite.Call(t, "settings_get", map[string]any{"name": "cache*"})
	if got := acctest.Rows(t, named["settings"], "settings"); len(got) != 1 || got[0]["name"] != "cacheMaximumRecordTtl" {
		t.Errorf("by a pattern = %v", got)
	}
	if names := rowNames(acctest.Rows(t, suite.Call(t, "settings_get", map[string]any{"differ_only": true, "name": "e"})["settings"], "settings")); !slices.Equal(names, []string{"cacheMaximumRecordTtl", "dnsServerDomain", "tsigKeys"}) {
		t.Errorf("the ones that differ with an e in the name = %v", names)
	}
	if none := suite.Call(t, "settings_get", map[string]any{"name": "nothing-like-it"}); !strings.Contains(acctest.Str(none["note"]), "no setting matched") {
		t.Errorf("nothing matched = %v", none)
	}

	// one server that cannot be read is said to have failed, and the other's are given
	p.rpi.Fail("settings/get", "error", "Access was denied.")
	one := suite.Call(t, "settings_get", map[string]any{"name": "cacheMaximumRecordTtl"})
	if failed := acctest.Rows(t, one["failed"], "failed"); len(failed) != 1 || failed[0]["server"] != "rpi" || acctest.Num(t, acctest.Rows(t, one["settings"], "settings")[0]["value"], "value") != 10000 {
		t.Errorf("with one server refusing = %v", one)
	}
}

// rowNames are the names of rows that have one.
func rowNames(rows []map[string]any) []string {
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, acctest.Str(row["name"]))
	}

	return names
}

// Only a setting that differs from what the server has is sent, under the
// API's own spelling of its name, and a name it does not know is refused.
func TestSettingsSet(t *testing.T) {
	t.Parallel()

	p := settingsPair(t)
	suite := p.session(t, everything)

	dry := suite.Call(t, "settings_set", map[string]any{"server": "dock", "settings": map[string]string{"CACHEMAXIMUMRECORDTTL": "40000", "enableBlocking": "true", "forwarders": " 9.9.9.9,1.1.1.1 "}, "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{`would have set cacheMaximumRecordTtl on dock from "10000" to "40000"`}) || dry["after"] != nil || len(p.dock.Requests("settings/set")) != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	if same := suite.Call(t, "settings_set", map[string]any{"server": "dock", "settings": map[string]string{"enableBlocking": "true", "forwarders": "9.9.9.9,1.1.1.1"}}); acctest.BoolOf(same["changed"]) || len(acctest.Strs(t, same["changes"], "changes")) != 0 || len(p.dock.Requests("settings/set")) != 0 {
		t.Errorf("set to what they are = %v", same)
	}

	// what the server gives back is what is believed: a value it rewrote is said
	p.dock.Answer("settings/set", strings.Replace(dockEverySetting, `"cacheMaximumRecordTtl":10000`, `"cacheMaximumRecordTtl":30000`, 1))
	set := suite.Call(t, "settings_set", map[string]any{"server": "dock", "settings": map[string]string{"cacheMaximumRecordTtl": "40000", "proxyPassword": "n3w-5ecre7", "webServiceHttpPort": "5381"}})
	asked := p.dock.Last("settings/set")
	if len(asked.Params) != 3 || asked.Params.Get("cacheMaximumRecordTtl") != "40000" || asked.Params.Get("proxyPassword") != "n3w-5ecre7" || asked.Params.Get("webServiceHttpPort") != "5381" {
		t.Errorf("the settings were set with %v", slices.Sorted(maps.Keys(asked.Params)))
	}
	note := acctest.Str(set["note"])
	if got := acctest.Strs(t, set["changes"], "changes"); !slices.Equal(got, []string{`set cacheMaximumRecordTtl on dock from "10000" to "40000"`, "set proxyPassword on dock", `set webServiceHttpPort on dock from "5380" to "5381"`}) || !strings.Contains(note, `cacheMaximumRecordTtl is "30000"`) || !strings.Contains(note, `webServiceHttpPort is "5380"`) || !strings.Contains(note, "restarts part of the server") || strings.Contains(fmt.Sprint(set), "n3w-5ecre7") {
		t.Errorf("set = %v, note %q", got, note)
	}

	sent := len(p.dock.Requests("settings/set"))
	for msg, args := range map[string]map[string]any{
		`there is no setting named "cacheSize"`: {"server": "dock", "settings": map[string]string{"cacheSize": "1"}},
		"tsig_key_set adds or changes one":      {"server": "dock", "settings": map[string]string{"tsigKeys": "false"}},
		"which settings":                        {"server": "dock", "settings": map[string]string{}},
		// a setting a later version of the server brought is refused before anything is sent, the settings beside it too, and by a dry run as well
		"dock runs version 15.6 of the server, which has no setting named enableCachePrefetch": {"server": "dock", "settings": map[string]string{"enableCachePrefetch": "true", "cacheMaximumRecordTtl": "5"}},
		"which has no setting named serveStale: a later version brought it":                    {"server": "dock", "settings": map[string]string{"serveStale": "true"}, "dry_run": true},
	} {
		if got := suite.CallErr(t, "settings_set", args); !strings.Contains(got, msg) {
			t.Errorf("settings_set %v = %q, want %q in it", args["settings"], got, msg)
		}
	}
	if len(p.dock.Requests("settings/set")) != sent {
		t.Error("a change that was refused reached the server")
	}
}

// A transfer key is added or changed with the server's other keys sent back
// as they were, secrets and all, and none of it is in what the tool answers.
func TestTSIGKeyTools(t *testing.T) {
	t.Parallel()

	p := settingsPair(t)
	suite := p.session(t, everything)

	dry := suite.Call(t, "tsig_key_set", map[string]any{"server": "dock", "name": "New.example.", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have added the transfer key new.example (hmac-sha256) to dock"}) || !strings.Contains(acctest.Str(dry["note"]), "made the key's secret up") || len(p.dock.Requests("settings/set")) != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	p.dock.Then("settings/set", func(technitiumtest.Request) {
		p.dock.Answer("settings/getTsigKeyNames", `{"tsigKeyNames":["cluster-catalog.example","old.example","new.example"]}`)
	})
	added := suite.Call(t, "tsig_key_set", map[string]any{"server": "dock", "name": "new.example", "shared_secret": " bmV3 ", "algorithm": "HMAC-SHA512"})
	if asked := p.dock.Last("settings/set"); asked.Params.Get("tsigKeys") != "cluster-catalog.example|Y2x1c3Rlcg==|hmac-sha256|old.example|b2xk|hmac-sha512|new.example|bmV3|hmac-sha512" || len(asked.Params) != 1 || !slices.Contains(acctest.Strs(t, added["keys"], "keys"), "new.example") || added["note"] != nil {
		t.Errorf("added = %v", added)
	}
	if text := fmt.Sprint(added); strings.Contains(text, "bmV3") || strings.Contains(text, "b2xk") {
		t.Errorf("a key's secret is in what the tool answered: %s", text)
	}
	changed := suite.Call(t, "tsig_key_set", map[string]any{"server": "dock", "name": "OLD.example", "shared_secret": "Y2hhbmdlZA=="}) //nolint:gosec // G101: a key made up for the test
	if !slices.Equal(acctest.Strs(t, changed["changes"], "changes"), []string{"changed the transfer key old.example (hmac-sha256) on dock"}) || !strings.Contains(p.dock.Last("settings/set").Params.Get("tsigKeys"), "old.example|Y2hhbmdlZA==|hmac-sha256") {
		t.Errorf("changed = %v", changed)
	}

	// a server that says ok and has no such key is not believed
	p.rpi.Answer("settings/get", rpiEverySetting)
	if msg := suite.CallErr(t, "tsig_key_set", map[string]any{"server": "rpi", "name": "new.example", "shared_secret": "bmV3"}); !strings.Contains(msg, "the server said ok and rpi has no key named new.example") {
		t.Errorf("a key that did not take = %q", msg)
	}
	if msg := suite.CallErr(t, "tsig_key_set", map[string]any{"server": "dock", "name": "two words"}); !strings.Contains(msg, "which key") {
		t.Errorf("a name that is none = %q", msg)
	}

	// taken away: the rest stay, a key that is not there is nothing to do, and the server's refusal is passed on
	sent := len(p.dock.Requests("settings/set"))
	if nothing := suite.Call(t, "tsig_key_delete", map[string]any{"server": "dock", "name": "never.example"}); acctest.BoolOf(nothing["changed"]) || !strings.Contains(acctest.Str(nothing["note"]), "nothing to take away") || len(p.dock.Requests("settings/set")) != sent {
		t.Errorf("a key that is not there, deleted = %v", nothing)
	}
	dry = suite.Call(t, "tsig_key_delete", map[string]any{"server": "dock", "name": "old.example", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have removed the transfer key old.example from dock"}) || len(p.dock.Requests("settings/set")) != sent {
		t.Errorf("a dry run of deleting = %v", dry)
	}
	p.dock.Then("settings/set", func(technitiumtest.Request) {
		p.dock.Answer("settings/getTsigKeyNames", `{"tsigKeyNames":["cluster-catalog.example"]}`)
	})
	gone := suite.Call(t, "tsig_key_delete", map[string]any{"server": "dock", "name": "old.example"})
	if asked := p.dock.Last("settings/set"); asked.Params.Get("tsigKeys") != "cluster-catalog.example|Y2x1c3Rlcg==|hmac-sha256" || !slices.Equal(acctest.Strs(t, gone["keys"], "keys"), []string{"cluster-catalog.example"}) {
		t.Errorf("deleted = %v", gone)
	}
	p.dock.Fail("settings/set", "error", "Cannot remove TSIG key 'cluster-catalog.example' as it is being used by the cluster.")
	if msg := suite.CallErr(t, "tsig_key_delete", map[string]any{"server": "dock", "name": "cluster-catalog.example"}); !strings.Contains(msg, "Cannot remove TSIG key") || strings.Contains(msg, "Y2x1c3Rlcg==") {
		t.Errorf("the cluster's own key, deleted = %q", msg)
	}
}

// A backup is written where it was asked for, for its owner alone, never
// over a file that is there; a restore sends the file with the parts named.
func TestBackupAndRestoreTools(t *testing.T) {
	t.Parallel()

	p := settingsPair(t)
	backup := zipOf(t, "dns.config", "zones/example.com.zone")
	p.dock.AnswerText("settings/backup", string(backup))
	p.dock.Answer("settings/restore", dockEverySetting)
	suite := p.session(t, everything)
	dir := t.TempDir()

	out := suite.Call(t, "settings_backup", map[string]any{"server": "dock", "path": dir, "parts": []string{"Zones", " dns_settings", "zones"}})
	path := acctest.Str(out["path"])
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the backup is not where the tool said: %v", err)
	}
	written, err := os.ReadFile(path) //nolint:gosec // G304: the file the test just had written
	if err != nil {
		t.Fatal(err)
	}
	if asked := p.dock.Last("settings/backup"); filepath.Dir(path) != dir || !strings.HasPrefix(filepath.Base(path), "technitium-dock-") || info.Mode().Perm() != 0o600 || !bytes.Equal(written, backup) || len(asked.Params) != 2 || asked.Params.Get("zones") != "true" || asked.Params.Get("dnsSettings") != "true" {
		t.Errorf("the backup is %s, mode %v, asked for with %v", path, info.Mode().Perm(), asked.Params)
	}
	if !slices.Equal(acctest.Strs(t, out["parts"], "parts"), []string{"zones", "dns_settings"}) || !slices.Equal(acctest.Strs(t, out["files"], "files"), []string{"dns.config (4 bytes)", "zones/example.com.zone (4 bytes)"}) || acctest.Num(t, out["bytes"], "bytes") != len(backup) {
		t.Errorf("settings_backup = %v", out)
	}
	if all := suite.Call(t, "settings_backup", map[string]any{"server": "dock", "path": filepath.Join(dir, "all.zip"), "parts": []string{"all"}}); len(p.dock.Last("settings/backup").Params) != 13 || len(acctest.Strs(t, all["parts"], "parts")) != 13 {
		t.Errorf("everything = %v, asked for with %v", all["parts"], p.dock.Last("settings/backup").Params)
	}

	asked := len(p.dock.Requests("settings/backup"))
	for msg, args := range map[string]map[string]any{
		`part "everything"`:           {"server": "dock", "path": dir, "parts": []string{"everything"}},
		"which parts of the server":   {"server": "dock", "path": dir, "parts": []string{" "}},
		"where to write the backup":   {"server": "dock", "path": " ", "parts": []string{"zones"}},
		"a file is named ending .zip": {"server": "dock", "path": filepath.Join(dir, "backup.tar"), "parts": []string{"zones"}},
	} {
		if got := suite.CallErr(t, "settings_backup", args); !strings.Contains(got, msg) {
			t.Errorf("settings_backup %v = %q, want %q in it", args["parts"], got, msg)
		}
	}
	if len(p.dock.Requests("settings/backup")) != asked {
		t.Error("a backup that was refused was asked of the server")
	}
	// a file that is there is not written over, and an answer that is no zip is written nowhere
	if msg := suite.CallErr(t, "settings_backup", map[string]any{"server": "dock", "path": filepath.Join(dir, "all.zip"), "parts": []string{"zones"}}); !strings.Contains(msg, "writing the backup") {
		t.Errorf("over a file that is there = %q", msg)
	}
	p.dock.AnswerText("settings/backup", "PK\x03\x04 and then nothing a zip has")
	if msg := suite.CallErr(t, "settings_backup", map[string]any{"server": "dock", "path": filepath.Join(dir, "broken.zip"), "parts": []string{"zones"}}); !strings.Contains(msg, "something that is no zip file") {
		t.Errorf("an answer that is no zip = %q", msg)
	}
	if _, err := os.Stat(filepath.Join(dir, "broken.zip")); err == nil {
		t.Error("an answer that is no zip was written to disk")
	}

	// restored: a dry run lists what the file holds and sends nothing
	dry := suite.Call(t, "settings_restore", map[string]any{"server": "dock", "path": path, "parts": []string{"zones"}, "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have restored zones on dock from " + filepath.Base(path) + ", writing over what it has of them"}) || len(acctest.Strs(t, dry["files"], "files")) != 2 || len(p.dock.Requests("settings/restore")) != 0 {
		t.Errorf("a dry run of a restore = %v", dry)
	}
	suite.Call(t, "settings_restore", map[string]any{"server": "dock", "path": path, "parts": []string{"zones", "allowed_names"}, "delete_existing": true})
	if sent := p.dock.Last("settings/restore"); !bytes.Equal(sent.File, backup) || len(sent.Params) != 3 || sent.Params.Get("zones") != "true" || sent.Params.Get("allowedZones") != "true" || sent.Params.Get("deleteExistingFiles") != "true" {
		t.Errorf("restored with %v", sent.Params)
	}

	notZip := filepath.Join(dir, "notes.zip")
	if err := os.WriteFile(notZip, []byte("not a zip at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	for msg, args := range map[string]map[string]any{
		"is no zip file, which is what a backup is": {"server": "dock", "path": notZip, "parts": []string{"zones"}},
		"reading the backup":                        {"server": "dock", "path": filepath.Join(dir, "missing.zip"), "parts": []string{"zones"}},
	} {
		if got := suite.CallErr(t, "settings_restore", args); !strings.Contains(got, msg) {
			t.Errorf("settings_restore %v = %q, want %q in it", args["path"], got, msg)
		}
	}
	if len(p.dock.Requests("settings/restore")) != 1 {
		t.Errorf("%d restores reached the server, want the one", len(p.dock.Requests("settings/restore")))
	}

	// 15.6.1 fails, and then will not start, when a zone it does not hold is put back without the accounts: that restore is refused, and the two that work go
	p.dock.Answer("settings/get", `{"version":"15.6.1"}`)
	p.dock.Answer("zones/list", `{"zones":[{"name":"other.example","type":"Primary"}]}`)
	if got := suite.CallErr(t, "settings_restore", map[string]any{"server": "dock", "path": path, "parts": []string{"zones"}}); !strings.Contains(got, "will not start again") || !strings.Contains(got, "The backup has example.com, which dock does not hold") {
		t.Errorf("a zone 15.6.1 does not hold, put back alone = %q", got)
	}
	if got := suite.CallErr(t, "settings_restore", map[string]any{"server": "dock", "path": path, "parts": []string{"zones"}, "dry_run": true}); !strings.Contains(got, "will not start again") {
		t.Errorf("a dry run of the same = %q", got)
	}
	if len(p.dock.Requests("settings/restore")) != 1 {
		t.Errorf("%d restores reached the server, want the one from before", len(p.dock.Requests("settings/restore")))
	}
	suite.Call(t, "settings_restore", map[string]any{"server": "dock", "path": path, "parts": []string{"zones", "accounts"}})
	p.dock.Answer("zones/list", `{"zones":[{"name":"Example.com","type":"Primary"}]}`)
	suite.Call(t, "settings_restore", map[string]any{"server": "dock", "path": path, "parts": []string{"zones"}})
	if len(p.dock.Requests("settings/restore")) != 3 {
		t.Errorf("%d restores reached the server, want the two that work on 15.6.1 beside the first", len(p.dock.Requests("settings/restore")))
	}

	// a restore of the accounts can end the tool's own token: that is the restore working, and is said
	p.dock.Fail("settings/restore", "invalid-token", "Invalid token or session expired.")
	ended := suite.Call(t, "settings_restore", map[string]any{"server": "dock", "path": path, "parts": []string{"accounts"}})
	if !acctest.BoolOf(ended["changed"]) || !strings.Contains(acctest.Str(ended["note"]), "is no longer taken on the server") {
		t.Errorf("a restore that ended the token = %v", ended)
	}
}

func TestSettingText(t *testing.T) {
	t.Parallel()

	for want, value := range map[string]any{"": nil, "Deny": "Deny", "true": true, "5380": float64(5380), "9.9.9.9,1.1.1.1": []any{"9.9.9.9", "1.1.1.1"}, `{"type":"Http"}`: map[string]any{"type": "Http"}} {
		if got := settingText(value); got != want {
			t.Errorf("settingText(%v) = %q, want %q", value, got, want)
		}
	}
}
