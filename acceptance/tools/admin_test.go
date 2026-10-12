//go:build acceptance

package tools_test

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // G505: the hash a one-time code is defined with (RFC 6238)
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// oneTimeCode is the code an authenticator app shows for a secret now (RFC
// 6238: six digits, a new one every thirty seconds).
func oneTimeCode(t *testing.T, secret string) string {
	t.Helper()

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("the secret is not base32: %v", err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30)) //nolint:gosec // G115: the time is after 1970
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	at := sum[len(sum)-1] & 0x0f

	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[at:at+4])&0x7fffffff)%1000000)
}

// entry finds what an account or a group may do in a list of permissions,
// nil when it is not on it.
func entry(rows []map[string]any, name string) map[string]any {
	if i := slices.IndexFunc(rows, func(row map[string]any) bool { return row["name"] == name }); i >= 0 {
		return rows[i]
	}

	return nil
}

// Accounts, groups, tokens and sessions, from their making to their
// deletion: each change first as a dry run, then read back.
func TestAccountsGroupsAndTokens(t *testing.T) {
	t.Parallel()

	names(t)
	first := world.First
	const user, group, pass = "acc-user", "acc-group", "an acceptance passw0rd"
	for _, left := range []map[string]any{{"tool": "user_delete", "args": map[string]any{"username": user}}, {"tool": "user_delete", "args": map[string]any{"username": user + "-renamed"}}, {"tool": "group_delete", "args": map[string]any{"group": group}}, {"tool": "group_delete", "args": map[string]any{"group": group + "-renamed"}}} {
		args := acctest.Object(t, left["args"], "args")
		_, _ = suite.Invoke(acctest.Str(left["tool"]), on(args))
		t.Cleanup(func() { _, _ = suite.Invoke(acctest.Str(left["tool"]), on(args)) })
	}
	listed := func(name string) map[string]any {
		t.Helper()
		rows := acctest.Rows(t, suite.Call(t, "user_list", nil)["users"], "users")
		if i := slices.IndexFunc(rows, func(row map[string]any) bool { return row["username"] == name }); i >= 0 {
			return rows[i]
		}

		return nil
	}

	// the administrator is on every server, and this tool is not locked out of its own account
	if admin := listed("admin"); admin == nil || len(acctest.Strs(t, admin["on"], "on")) != len(world.Names()) || admin["missing_on"] != nil {
		t.Errorf("the administrator in user_list = %v", admin)
	}
	if msg := suite.CallErr(t, "user_set", on(map[string]any{"username": "admin", "disabled": true})); !strings.Contains(msg, "the account this tool works under") {
		t.Errorf("the tool's own account, switched off = %q", msg)
	}
	if msg := suite.CallErr(t, "user_delete", on(map[string]any{"username": "admin"})); !strings.Contains(msg, "the account this tool works under") {
		t.Errorf("the tool's own account, deleted = %q", msg)
	}

	// an account: not made without a password; a dry run makes nothing; then it is there, in no group
	if msg := suite.CallErr(t, "user_set", on(map[string]any{"username": user})); !strings.Contains(msg, "give new_password") {
		t.Errorf("an account made with no password = %q", msg)
	}
	dry := suite.Call(t, "user_set", on(map[string]any{"username": user, "new_password": suite.Secret(pass), "display_name": "An Acceptance User", "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have made the account " + user + " on " + first}) || dry["after"] != nil || listed(user) != nil {
		t.Errorf("a dry run of making an account = %v", dry)
	}
	made := suite.Call(t, "user_set", on(map[string]any{"username": user, "new_password": suite.Secret(pass), "display_name": "An Acceptance User"}))
	if after := acctest.Object(t, made["after"], "after"); !acctest.BoolOf(made["created"]) || after["username"] != user || after["display_name"] != "An Acceptance User" || len(acctest.Strs(t, after["groups"], "groups")) != 0 || after["disabled"] != nil {
		t.Errorf("made = %v", made)
	}
	if again := suite.Call(t, "user_set", on(map[string]any{"username": user, "display_name": "An Acceptance User"})); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 {
		t.Errorf("set to what it is = %v", again)
	}
	for _, text := range []any{made["changes"], made["after"]} {
		if strings.Contains(fmt.Sprint(text), pass) {
			t.Errorf("the password is in the answer: %v", text)
		}
	}

	// a group: made with the account in it, renamed, and its description cleared
	grouped := suite.Call(t, "group_set", on(map[string]any{"group": group, "description": "made by the acceptance suite", "members": []string{user}}))
	if after := acctest.Object(t, grouped["after"], "after"); !acctest.BoolOf(grouped["created"]) || after["name"] != group || !slices.Equal(acctest.Strs(t, after["members"], "members"), []string{user}) || after["description"] != "made by the acceptance suite" {
		t.Errorf("the group made = %v", grouped)
	}
	renamed := suite.Call(t, "group_set", on(map[string]any{"group": group, "new_name": group + "-renamed", "description": ""}))
	if after := acctest.Object(t, renamed["after"], "after"); after["name"] != group+"-renamed" || after["description"] != nil || len(acctest.Strs(t, renamed["changes"], "changes")) != 2 {
		t.Errorf("the group renamed = %v", renamed)
	}
	groups := acctest.Rows(t, rowFor(t, acctest.Rows(t, suite.Call(t, "group_list", on(map[string]any{}))["servers"], "servers"), "server", first)["groups"], "groups")
	if mine := entry(groups, group+"-renamed"); mine == nil || !slices.Equal(acctest.Strs(t, mine["members"], "members"), []string{user}) || entry(groups, "Administrators") == nil || !slices.Contains(acctest.Strs(t, entry(groups, "Administrators")["members"], "members"), "admin") {
		t.Errorf("group_list = %v", groups)
	}
	if msg := suite.CallErr(t, "group_set", on(map[string]any{"group": "Administrators", "members": []string{user}})); !strings.Contains(msg, "the account this tool works under") {
		t.Errorf("the tool's own account taken out of the administrators = %q", msg)
	}

	// the account's groups are set whole; user_get gives it with them
	set := suite.Call(t, "user_set", on(map[string]any{"username": user, "groups": []string{"DNS Administrators", group + "-renamed"}, "session_timeout_seconds": 1200}))
	if after := acctest.Object(t, set["after"], "after"); !slices.Equal(acctest.Sorted(acctest.Strs(t, after["groups"], "groups")), []string{"DNS Administrators", group + "-renamed"}) || acctest.Num(t, after["session_timeout_seconds"], "session_timeout_seconds") != 1200 || len(acctest.Strs(t, set["changes"], "changes")) != 2 {
		t.Errorf("its groups set = %v", set)
	}

	// a token for it: shown once, named, and it works as the account
	token := suite.Call(t, "token_create", on(map[string]any{"username": user, "token_name": "acc-token"}))
	secret := acctest.Str(token["token"])
	if len(secret) < 32 || token["username"] != user || token["token_name"] != "acc-token" {
		t.Fatalf("token_create = %v", token["note"])
	}
	as, err := technitium.New(mustClient(t, first).BaseURL(), secret)
	if err != nil {
		t.Fatal(err)
	}
	if session, err := as.Session(t.Context()); err != nil || session.Username != user || session.TokenName != "acc-token" {
		t.Errorf("the token's own session = %+v, %v", session, err)
	}
	if msg := suite.CallErr(t, "token_create", on(map[string]any{"username": user, "token_name": "acc-token"})); !strings.Contains(msg, `already has a token named "acc-token"`) {
		t.Errorf("a second token under the same name = %q", msg)
	}
	if msg := suite.CallErr(t, "token_create", on(map[string]any{"username": "acc-nobody", "token_name": "x"})); !strings.Contains(msg, "has no account named acc-nobody") {
		t.Errorf("a token for nobody = %q", msg)
	}

	// the token is among the sessions and in the account, by an id that is not the token; the tool's own is marked, and is not deleted
	sessions := acctest.Rows(t, rowFor(t, acctest.Rows(t, suite.Call(t, "session_list", on(map[string]any{}))["servers"], "servers"), "server", first)["sessions"], "sessions")
	mine := slices.IndexFunc(sessions, func(row map[string]any) bool { return row["token_name"] == "acc-token" })
	current := slices.IndexFunc(sessions, func(row map[string]any) bool { return acctest.BoolOf(row["current"]) })
	if mine < 0 || current < 0 || sessions[mine]["username"] != user || sessions[mine]["type"] != "ApiToken" || !strings.HasPrefix(secret, acctest.Str(sessions[mine]["id"])) || len(acctest.Str(sessions[mine]["id"])) >= len(secret) || strings.Contains(fmt.Sprint(sessions), secret) {
		t.Fatalf("session_list = %d sessions, the new token at %d and the tool's own at %d", len(sessions), mine, current)
	}
	got := rowFor(t, acctest.Rows(t, suite.Call(t, "user_get", on(map[string]any{"username": user}))["servers"], "servers"), "server", first)
	if len(acctest.Rows(t, got["sessions"], "sessions")) != 1 || acctest.Rows(t, got["sessions"], "sessions")[0]["id"] != sessions[mine]["id"] {
		t.Errorf("user_get = %v", got)
	}
	if msg := suite.CallErr(t, "session_delete", on(map[string]any{"id": sessions[current]["id"]})); !strings.Contains(msg, "the token this tool works under") {
		t.Errorf("the tool's own token, deleted = %q", msg)
	}
	dry = suite.Call(t, "session_delete", on(map[string]any{"id": sessions[mine]["id"], "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{`would have deleted the API token "acc-token" of ` + user + " on " + first}) {
		t.Errorf("a dry run of deleting a token = %v", dry)
	}
	if _, err := as.Session(t.Context()); err != nil {
		t.Errorf("the token after a dry run of deleting it: %v", err)
	}
	if ended := suite.Call(t, "session_delete", on(map[string]any{"id": sessions[mine]["id"]})); !acctest.BoolOf(ended["changed"]) || acctest.Object(t, ended["ended"], "ended")["token_name"] != "acc-token" {
		t.Errorf("the token deleted = %v", ended)
	}
	if _, err := as.Session(t.Context()); !technitium.IsInvalidToken(err) {
		t.Errorf("the token once it was deleted = %v, want it refused", err)
	}
	if nothing := suite.Call(t, "session_delete", on(map[string]any{"id": sessions[mine]["id"]})); acctest.BoolOf(nothing["changed"]) {
		t.Errorf("a token deleted twice = %v", nothing)
	}

	// the account as itself: its own name, a second factor begun and switched on with a code, then taken off, and its password
	if msg := suite.CallErr(t, "account_edit", on(map[string]any{"username": user, "password": suite.Secret("not its password"), "display_name": "x"})); !strings.Contains(msg, "signing in") {
		t.Errorf("signed in with a wrong password = %q", msg)
	}
	begun := suite.Call(t, "account_edit", on(map[string]any{"username": user, "password": suite.Secret(pass), "display_name": "Its Own Name", "two_factor": "begin"}))
	totp := acctest.Str(begun["two_factor_secret"])
	if totp == "" || !strings.Contains(acctest.Str(begun["two_factor_uri"]), "secret="+totp) || len(acctest.Strs(t, begun["changes"], "changes")) != 2 || acctest.Object(t, begun["after"], "after")["display_name"] != "Its Own Name" {
		t.Fatalf("a second factor begun = %v", begun["changes"])
	}
	if msg := suite.CallErr(t, "account_edit", on(map[string]any{"username": user, "password": suite.Secret(pass), "two_factor": "enable"})); !strings.Contains(msg, "two_factor_code") {
		t.Errorf("a second factor switched on with no code = %q", msg)
	}
	enabled := suite.Call(t, "account_edit", on(map[string]any{"username": user, "password": suite.Secret(pass), "two_factor": "enable", "two_factor_code": oneTimeCode(t, totp)}))
	if !acctest.BoolOf(acctest.Object(t, enabled["after"], "after")["two_factor"]) {
		t.Errorf("a second factor switched on = %v", enabled)
	}
	if msg := suite.CallErr(t, "account_edit", on(map[string]any{"username": user, "password": suite.Secret(pass), "display_name": "x"})); !strings.Contains(msg, "signing in") {
		t.Errorf("signed in without the second factor = %q", msg)
	}
	off := suite.Call(t, "account_edit", on(map[string]any{"username": user, "password": suite.Secret(pass), "totp": oneTimeCode(t, totp), "two_factor": "disable", "new_password": suite.Secret(pass) + " two", "single_use_token": true}))
	if acctest.Object(t, off["after"], "after")["two_factor"] != nil || len(acctest.Str(off["token"])) < 32 || len(acctest.Strs(t, off["changes"], "changes")) != 3 || strings.Contains(fmt.Sprint(off["changes"]), pass) {
		t.Errorf("the second factor taken off and the password changed = %v", off["changes"])
	}
	if msg := suite.CallErr(t, "account_edit", on(map[string]any{"username": user, "password": suite.Secret(pass), "display_name": "x"})); !strings.Contains(msg, "signing in") {
		t.Errorf("signed in with the old password = %q", msg)
	}

	// the tool's own account, which any token may read
	own := rowFor(t, acctest.Rows(t, suite.Call(t, "account_get", on(map[string]any{}))["servers"], "servers"), "server", first)
	if own["username"] != "admin" || !slices.Contains(acctest.Strs(t, own["groups"], "groups"), "Administrators") || len(acctest.Rows(t, own["sessions"], "sessions")) == 0 {
		t.Errorf("account_get = %v", own)
	}

	// renamed and switched off by the administrator, then deleted with what it had; the group goes too
	changed := suite.Call(t, "user_set", on(map[string]any{"username": user, "new_username": user + "-renamed", "disabled": true, "new_password": suite.Secret(pass)}))
	if after := acctest.Object(t, changed["after"], "after"); after["username"] != user+"-renamed" || !acctest.BoolOf(after["disabled"]) || len(acctest.Strs(t, changed["changes"], "changes")) != 3 {
		t.Errorf("renamed and switched off = %v", changed)
	}
	dry = suite.Call(t, "user_delete", on(map[string]any{"username": user + "-renamed", "dry_run": true}))
	if len(acctest.Strs(t, dry["changes"], "changes")) != 1 || listed(user+"-renamed") == nil {
		t.Errorf("a dry run of deleting an account = %v", dry)
	}
	if deleted := suite.Call(t, "user_delete", on(map[string]any{"username": user + "-renamed"})); !acctest.BoolOf(deleted["changed"]) || listed(user+"-renamed") != nil {
		t.Errorf("deleted = %v", deleted)
	}
	if nothing := suite.Call(t, "user_delete", on(map[string]any{"username": user + "-renamed"})); acctest.BoolOf(nothing["changed"]) {
		t.Errorf("an account deleted twice = %v", nothing)
	}
	if deleted := suite.Call(t, "group_delete", on(map[string]any{"group": group + "-renamed"})); !acctest.BoolOf(deleted["changed"]) || len(acctest.Strs(t, deleted["members"], "members")) != 0 {
		t.Errorf("the group deleted = %v", deleted)
	}
	if nothing := suite.Call(t, "group_delete", on(map[string]any{"group": group + "-renamed"})); acctest.BoolOf(nothing["changed"]) {
		t.Errorf("a group deleted twice = %v", nothing)
	}
	if msg := suite.CallErr(t, "user_get", on(map[string]any{"username": user})); !strings.Contains(msg, "no server asked has an account named "+user) {
		t.Errorf("an account that is gone, read = %q", msg)
	}
}

// Who may do what: read for every section and for one zone, given to an
// account by name, seen to hold when that account asks, and taken away.
func TestAccess(t *testing.T) {
	t.Parallel()

	names(t)
	first := world.First
	const user = "acc-permitted"
	_, _ = suite.Invoke("user_delete", on(map[string]any{"username": user}))
	suite.Call(t, "user_set", on(map[string]any{"username": user, "new_password": suite.Secret("an acceptance passw0rd")}))
	t.Cleanup(func() { _, _ = suite.Invoke("user_delete", on(map[string]any{"username": user})) })
	as, err := technitium.New(mustClient(t, first).BaseURL(), acctest.Str(suite.Call(t, "token_create", on(map[string]any{"username": user, "token_name": "acc-access"}))["token"]))
	if err != nil {
		t.Fatal(err)
	}
	permissions := func(args map[string]any) []map[string]any {
		t.Helper()

		return acctest.Rows(t, rowFor(t, acctest.Rows(t, suite.Call(t, "access_get", on(args))["servers"], "servers"), "server", first)["permissions"], "permissions")
	}

	// every section, with the administrators allowed everything in each
	all := permissions(map[string]any{})
	if len(all) < 10 {
		t.Fatalf("access_get = %d sections", len(all))
	}
	for _, section := range all {
		if admins := entry(acctest.Rows(t, section["groups"], "groups"), "Administrators"); admins == nil || !acctest.BoolOf(admins["view"]) || !acctest.BoolOf(admins["modify"]) || !acctest.BoolOf(admins["delete"]) {
			t.Errorf("the administrators in %v = %v", section["section"], admins)
		}
	}

	// the settings, which only the administrators are given: an account given nothing may not read them; given view by name it may, and may not change them
	if everyone := entry(acctest.Rows(t, permissions(map[string]any{"section": "Settings"})[0]["groups"], "groups"), "Everyone"); everyone != nil {
		t.Fatalf("everyone is given something in Settings, and the test needs a section they are not: %v", everyone)
	}
	if _, err := as.Settings(t.Context()); err == nil {
		t.Error("an account given nothing read the settings")
	}
	dry := suite.Call(t, "access_set", on(map[string]any{"section": "Settings", "users": []map[string]any{{"name": user, "view": true}}, "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have allowed the account " + user + " to view, in the Settings section on " + first}) {
		t.Errorf("a dry run of giving view = %v", dry)
	}
	if entry(acctest.Rows(t, permissions(map[string]any{"section": "Settings"})[0]["users"], "users"), user) != nil {
		t.Error("a dry run gave the account something")
	}
	given := suite.Call(t, "access_set", on(map[string]any{"section": "Settings", "users": []map[string]any{{"name": user, "view": true}}}))
	if mine := entry(acctest.Rows(t, acctest.Object(t, given["after"], "after")["users"], "users"), user); mine == nil || !acctest.BoolOf(mine["view"]) || mine["modify"] != nil || mine["delete"] != nil || entry(acctest.Rows(t, acctest.Object(t, given["after"], "after")["groups"], "groups"), "Administrators") == nil {
		t.Errorf("given view = %v", given)
	}
	t.Cleanup(func() {
		_, _ = suite.Invoke("access_set", on(map[string]any{"section": "Settings", "remove_users": []string{user}}))
	})
	if _, err := as.Settings(t.Context()); err != nil {
		t.Errorf("an account that may view the settings could not read them: %v", err)
	}
	if _, err := as.SetSettings(t.Context(), map[string]string{"cachePrefetchTrigger": "9"}); err == nil {
		t.Error("an account that may only view the settings changed one")
	}
	if again := suite.Call(t, "access_set", on(map[string]any{"section": "Settings", "users": []map[string]any{{"name": user, "view": true}}})); acctest.BoolOf(again["changed"]) {
		t.Errorf("given what it has = %v", again)
	}
	changed := suite.Call(t, "access_set", on(map[string]any{"section": "Settings", "users": []map[string]any{{"name": user, "view": true, "modify": true}}}))
	if !slices.Equal(acctest.Strs(t, changed["changes"], "changes"), []string{"changed what the account " + user + " may do from view to view, modify, in the Settings section on " + first}) {
		t.Errorf("given more = %v", changed)
	}

	// one zone: the account may change its records once it is given the zone, and not before
	zone := permissions(map[string]any{"zone": firstZone})
	if len(zone) != 1 || zone[0]["section"] != "Zones" || zone[0]["zone"] != firstZone || entry(acctest.Rows(t, zone[0]["users"], "users"), "admin") == nil {
		t.Errorf("a zone's permissions = %v", zone)
	}
	if _, err := as.AddRecord(t.Context(), technitium.NewRecord{Zone: firstZone, Name: "acc-access." + firstZone, Type: "TXT", Data: technitium.RData{"text": "no"}}); err == nil {
		t.Error("an account given nothing in the zone added a record to it")
	}
	suite.Call(t, "access_set", on(map[string]any{"zone": firstZone, "users": []map[string]any{{"name": user, "view": true, "modify": true}}}))
	t.Cleanup(func() {
		_, _ = suite.Invoke("access_set", on(map[string]any{"zone": firstZone, "remove_users": []string{user}}))
	})
	if _, err := as.AddRecord(t.Context(), technitium.NewRecord{Zone: firstZone, Name: "acc-access." + firstZone, Type: "TXT", Data: technitium.RData{"text": "yes"}}); err != nil {
		t.Errorf("an account that may modify the zone could not add a record to it: %v", err)
	}
	suite.Call(t, "record_delete", on(map[string]any{"name": "acc-access." + firstZone, "type": "TXT"}))
	removed := suite.Call(t, "access_set", on(map[string]any{"zone": firstZone, "remove_users": []string{user}}))
	if entry(acctest.Rows(t, acctest.Object(t, removed["after"], "after")["users"], "users"), user) != nil || len(acctest.Strs(t, removed["changes"], "changes")) != 1 {
		t.Errorf("taken off the zone = %v", removed)
	}

	// what cannot be: a section and a zone at once, a name the server does not know, and the administrators locked out
	for msg, args := range map[string]map[string]any{
		"one of the two":                     {"section": "Settings", "zone": firstZone, "users": []map[string]any{{"name": user}}},
		"has no account named acc-nobody":    {"section": "Settings", "users": []map[string]any{{"name": "acc-nobody", "view": true}}},
		"has no group named acc-nogroup":     {"section": "Settings", "groups": []map[string]any{{"name": "acc-nogroup", "view": true}}},
		"keeps everything in Administration": {"section": "Administration", "groups": []map[string]any{{"name": "Administrators", "view": true}}},
		"nothing was given to change":        {"section": "Settings"},
	} {
		if got := suite.CallErr(t, "access_set", on(args)); !strings.Contains(got, msg) {
			t.Errorf("access_set %v = %q, want %q in it", args, got, msg)
		}
	}
}

// Single sign-on read, and what of it can be set with no provider to sign in
// through set and put back.
//
// It does not run beside the other tests: a change to single sign-on can
// have a server restart its console.
//
//nolint:paralleltest // it changes single sign-on, which can restart the console every other test is asking
func TestSSO(t *testing.T) {
	names(t)
	first := world.First
	before := rowFor(t, acctest.Rows(t, suite.Call(t, "sso_get", on(map[string]any{}))["servers"], "servers"), "server", first)
	if acctest.BoolOf(before["enabled"]) || len(acctest.Object(t, before["group_map"], "group_map")) != 0 {
		t.Fatalf("sso_get = %v", before)
	}

	dry := suite.Call(t, "sso_set", on(map[string]any{"group_map": map[string]string{"acc-remote": "DNS Administrators"}, "allow_signup": true, "dry_run": true}))
	if len(acctest.Strs(t, dry["changes"], "changes")) != 2 || dry["after"] != nil {
		t.Errorf("a dry run of setting single sign-on = %v", dry)
	}
	set := suite.Call(t, "sso_set", on(map[string]any{"group_map": map[string]string{"acc-remote": "DNS Administrators"}, "allow_signup": true}))
	if after := acctest.Object(t, set["after"], "after"); acctest.Object(t, after["group_map"], "group_map")["acc-remote"] != "DNS Administrators" || !acctest.BoolOf(after["allow_signup"]) || acctest.BoolOf(after["enabled"]) {
		t.Errorf("set = %v", set)
	}
	if again := suite.Call(t, "sso_set", on(map[string]any{"allow_signup": true})); acctest.BoolOf(again["changed"]) {
		t.Errorf("set to what it is = %v", again)
	}
	if msg := suite.CallErr(t, "sso_set", on(map[string]any{"group_map": map[string]string{"acc-remote": "acc-nogroup"}})); !strings.Contains(msg, "has no group named acc-nogroup") {
		t.Errorf("mapped to a group that is not there = %q", msg)
	}
	if msg := suite.CallErr(t, "sso_set", on(map[string]any{"enabled": true})); !strings.Contains(msg, "give authority, client_id and client_secret") {
		t.Errorf("switched on with no provider = %q", msg)
	}
	back := suite.Call(t, "sso_set", on(map[string]any{"group_map": map[string]string{}, "allow_signup": false}))
	if after := acctest.Object(t, back["after"], "after"); len(acctest.Object(t, after["group_map"], "group_map")) != 0 || after["allow_signup"] != nil {
		t.Errorf("put back = %v", back)
	}
}
