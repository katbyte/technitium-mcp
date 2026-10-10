package tools

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// account is one account as a canned server gives it whole.
func account(name, more string) string {
	return fmt.Sprintf(`{"username":%q,"displayName":%q,"disabled":false,"totpEnabled":false,"sessionTimeoutSeconds":1800,"recentSessionLoggedOn":"2026-10-01T00:00:00Z","recentSessionRemoteAddress":"10.0.0.9","memberOfGroups":[],"sessions":[]%s}`, name, name, more)
}

// accountsPair is the pair with dock's accounts, groups, sessions and
// permissions, and every call that changes them answered. The tool's own
// token is the administrator's.
func accountsPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.AnswerWhole("user/session/get", adminSession)
	p.rpi.AnswerWhole("user/session/get", adminSession)
	p.dock.Answer("admin/users/list", `{"users":[`+account("admin", "")+`,`+account("kt", "")+`]}`)
	p.rpi.Answer("admin/users/list", `{"users":[`+account("admin", "")+`]}`)
	kt := strings.Replace(account("kt", ""), `"memberOfGroups":[],"sessions":[]`, `"memberOfGroups":["DNS Administrators"],"sessions":[{"username":"kt","isCurrentSession":false,"partialToken":"bbbb2222","type":"ApiToken","tokenName":"scripts","lastSeen":"2026-10-08T10:00:00Z","lastSeenRemoteAddress":"10.0.0.7","lastSeenUserAgent":"curl"},{"username":"kt","isCurrentSession":false,"partialToken":"cccc3333","type":"Standard","tokenName":null,"lastSeen":"2026-10-09T09:00:00Z","lastSeenRemoteAddress":"10.0.0.7","lastSeenUserAgent":"Mozilla"}]`, 1)
	p.both("admin/users/get", strings.Replace(account("admin", ""), `"memberOfGroups":[],"sessions":[]`, `"memberOfGroups":["Administrators"],"sessions":[{"username":"admin","isCurrentSession":true,"partialToken":"aaaa1111","type":"ApiToken","tokenName":"mcp","lastSeen":"2026-10-09T10:00:00Z","lastSeenRemoteAddress":"10.0.0.9","lastSeenUserAgent":"technitium-mcp"}]`, 1))
	p.dock.AnswerWhen("admin/users/get", "user", "kt", kt)
	p.both("admin/users/create", account("new", ""))
	p.both("admin/users/set", kt)
	p.both("admin/users/delete", `{}`)
	p.both("admin/groups/list", `{"groups":[{"name":"Administrators","description":"Super administrators"},{"name":"DNS Administrators","description":"DNS service administrators"}]}`)
	p.both("admin/groups/get", `{"name":"Administrators","description":"Super administrators","members":["admin"]}`)
	p.dock.AnswerWhen("admin/groups/get", "group", "DNS Administrators", `{"name":"DNS Administrators","description":"DNS service administrators","members":["kt"]}`)
	p.both("admin/groups/create", `{"name":"made","description":""}`)
	p.both("admin/groups/set", `{"name":"DNS Administrators","description":"","members":[]}`)
	p.both("admin/groups/delete", `{}`)
	p.dock.Answer("admin/sessions/list", `{"sessions":[{"username":"admin","isCurrentSession":true,"partialToken":"aaaa1111","type":"ApiToken","tokenName":"mcp","lastSeen":"2026-10-09T10:00:00Z","lastSeenRemoteAddress":"10.0.0.9","lastSeenUserAgent":"technitium-mcp"},{"username":"kt","isCurrentSession":false,"partialToken":"bbbb2222","type":"ApiToken","tokenName":"scripts","lastSeen":"2026-10-08T10:00:00Z","lastSeenRemoteAddress":"10.0.0.7","lastSeenUserAgent":"curl"},{"username":"kt","isCurrentSession":false,"partialToken":"cccc3333","type":"Standard","tokenName":null}]}`)
	p.rpi.Fail("admin/sessions/list", "error", "Access was denied.")
	p.both("admin/sessions/delete", `{}`)
	p.both("admin/sessions/createToken", `{"username":"kt","tokenName":"backups","token":"dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444"}`)

	return p
}

// accountWrites are how many calls that change an account, a group or a
// session a server got.
func accountWrites(server *technitiumtest.Server) int {
	n := 0
	for _, call := range []string{"users/create", "users/set", "users/delete", "groups/create", "groups/set", "groups/delete", "sessions/delete", "sessions/createToken", "permissions/set", "sso/set"} {
		n += len(server.Requests("admin/" + call))
	}

	return n
}

func TestUserListAndGet(t *testing.T) {
	t.Parallel()

	p := accountsPair(t)
	suite := p.session(t, Options{})

	users := acctest.Rows(t, suite.Call(t, "user_list", nil)["users"], "users")
	if len(users) != 2 || users[0]["username"] != "admin" || users[0]["missing_on"] != nil || !slices.Equal(acctest.Strs(t, users[1]["on"], "on"), []string{"dock"}) || !slices.Equal(acctest.Strs(t, users[1]["missing_on"], "missing_on"), []string{"rpi"}) || users[1]["last_signed_in"] != "2026-10-01T00:00:00Z" {
		t.Errorf("user_list = %v", users)
	}
	got := acctest.Rows(t, suite.Call(t, "user_get", map[string]any{"username": "KT"})["servers"], "servers")
	if len(got) != 2 || !acctest.BoolOf(got[1]["missing"]) {
		t.Fatalf("user_get = %v", got)
	}
	sessions := acctest.Rows(t, got[0]["sessions"], "sessions")
	if got[0]["username"] != "kt" || !slices.Equal(acctest.Strs(t, got[0]["groups"], "groups"), []string{"DNS Administrators"}) || acctest.Num(t, got[0]["session_timeout_seconds"], "session_timeout_seconds") != 1800 || len(sessions) != 2 || sessions[0]["id"] != "bbbb2222" || sessions[0]["token_name"] != "scripts" || sessions[0]["type"] != "ApiToken" || sessions[0]["last_from"] != "10.0.0.7" || sessions[1]["token_name"] != nil {
		t.Errorf("the account = %v", got[0])
	}
	if msg := suite.CallErr(t, "user_get", map[string]any{"username": "nobody"}); !strings.Contains(msg, "no server asked has an account named nobody") {
		t.Errorf("an account nobody has = %q", msg)
	}
}

func TestUserSetAndDelete(t *testing.T) {
	t.Parallel()

	p := accountsPair(t)
	suite := p.session(t, everything)

	// made: not without a password, not by a dry run, and then with what was asked
	if msg := suite.CallErr(t, "user_set", map[string]any{"server": "dock", "username": "new"}); !strings.Contains(msg, "give new_password") {
		t.Errorf("made with no password = %q", msg)
	}
	dry := suite.Call(t, "user_set", map[string]any{"server": "dock", "username": "new", "new_password": "5ecre7", "groups": []string{"DNS Administrators"}, "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have made the account new on dock", "would have set the groups of new to DNS Administrators (it was in none)"}) || accountWrites(p.dock) != 0 {
		t.Errorf("a dry run of making an account = %v", dry)
	}
	p.dock.Then("admin/users/create", func(technitiumtest.Request) {
		p.dock.Answer("admin/users/list", `{"users":[`+account("admin", "")+`,`+account("kt", "")+`,`+account("new", "")+`]}`)
		p.dock.AnswerWhen("admin/users/get", "user", "new", account("new", ""))
	})
	made := suite.Call(t, "user_set", map[string]any{"server": "dock", "username": "new", "new_password": "5ecre7", "display_name": "New"})
	if asked := p.dock.Last("admin/users/create"); !acctest.BoolOf(made["created"]) || asked.Params.Get("user") != "new" || asked.Params.Get("pass") != "5ecre7" || asked.Params.Get("displayName") != "New" || len(p.dock.Requests("admin/users/set")) != 0 || strings.Contains(fmt.Sprint(made), "5ecre7") {
		t.Errorf("made = %v, with %v", made["changes"], asked.Params)
	}

	// changed: only what differs is said and sent
	changed := suite.Call(t, "user_set", map[string]any{"server": "dock", "username": "kt", "display_name": "kt", "groups": []string{"DNS Administrators"}, "session_timeout_seconds": 1800, "disabled": false})
	if acctest.BoolOf(changed["changed"]) || len(p.dock.Requests("admin/users/set")) != 0 {
		t.Errorf("set to what it is = %v", changed)
	}
	p.dock.Then("admin/users/set", func(technitiumtest.Request) {
		p.dock.Answer("admin/users/list", `{"users":[`+account("admin", "")+`,`+account("kate", "")+`]}`)
		p.dock.AnswerWhen("admin/users/get", "user", "kate", account("kate", ""))
	})
	changed = suite.Call(t, "user_set", map[string]any{"server": "dock", "username": "KT", "new_password": "5ecre7-two", "groups": []string{}, "disabled": true, "new_username": "kate", "disable_two_factor": true})
	asked := p.dock.Last("admin/users/set")
	if got := acctest.Strs(t, changed["changes"], "changes"); !slices.Equal(got, []string{"reset the password of kt", "set the groups of kt to none (it was in DNS Administrators)", "switched the account kt off", "renamed the account kt to kate"}) || asked.Params.Get("newPass") != "5ecre7-two" || !asked.Params.Has("memberOfGroups") || asked.Params.Get("disabled") != "true" || asked.Params.Get("newUser") != "kate" || asked.Params.Has("totpEnabled") {
		t.Errorf("changed = %v, with %v", got, asked.Params)
	}

	// the tool's own account is not switched off, taken out of the administrators, or deleted
	sent := accountWrites(p.dock)
	for msg, call := range map[string]struct {
		tool string
		args map[string]any
	}{
		"admin is the account this tool works under on dock: switched off":         {"user_set", map[string]any{"server": "dock", "username": "admin", "disabled": true}},
		"admin is the account this tool works under on dock: switched off, or out": {"user_set", map[string]any{"server": "dock", "username": "Admin", "groups": []string{"DNS Administrators"}}},
		"admin is the account this tool works under on dock: deleted":              {"user_delete", map[string]any{"server": "dock", "username": "admin"}},
	} {
		if got := suite.CallErr(t, call.tool, call.args); !strings.Contains(got, msg) {
			t.Errorf("%s %v = %q, want %q in it", call.tool, call.args, got, msg)
		}
	}
	if now := accountWrites(p.dock); now != sent {
		t.Errorf("%d refused changes reached the server", now-sent)
	}

	// deleted: said with the sessions and tokens that go with it, and not asked of a server that has no such account
	p.dock.Answer("admin/users/list", `{"users":[`+account("admin", "")+`,`+account("kt", "")+`]}`)
	dry = suite.Call(t, "user_delete", map[string]any{"server": "dock", "username": "kt", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have deleted the account kt on dock with its 2 sessions and tokens"}) || len(p.dock.Requests("admin/users/delete")) != 0 {
		t.Errorf("a dry run of deleting = %v", dry)
	}
	if gone := suite.Call(t, "user_delete", map[string]any{"server": "dock", "username": "kt"}); acctest.Num(t, gone["sessions"], "sessions") != 2 || p.dock.Last("admin/users/delete").Params.Get("user") != "kt" {
		t.Errorf("deleted = %v", gone)
	}
	if nothing := suite.Call(t, "user_delete", map[string]any{"server": "rpi", "username": "kt"}); acctest.BoolOf(nothing["changed"]) || len(p.rpi.Requests("admin/users/delete")) != 0 {
		t.Errorf("an account the server does not have, deleted = %v", nothing)
	}
}

func TestGroups(t *testing.T) {
	t.Parallel()

	p := accountsPair(t)
	suite := p.session(t, everything)

	rows := acctest.Rows(t, suite.Call(t, "group_list", nil)["servers"], "servers")
	groups := acctest.Rows(t, rows[0]["groups"], "groups")
	if len(rows) != 2 || len(groups) != 2 || groups[1]["name"] != "DNS Administrators" || !slices.Equal(acctest.Strs(t, groups[1]["members"], "members"), []string{"kt"}) {
		t.Errorf("group_list = %v", rows)
	}

	// made with what it is for; changed only where it differs; the tool's own account is not taken out of the administrators
	made := suite.Call(t, "group_set", map[string]any{"server": "dock", "group": "made", "description": "by a test"})
	if asked := p.dock.Last("admin/groups/create"); !acctest.BoolOf(made["created"]) || asked.Params.Get("group") != "made" || asked.Params.Get("description") != "by a test" || len(p.dock.Requests("admin/groups/set")) != 0 {
		t.Errorf("made = %v, with %v", made, asked.Params)
	}
	if same := suite.Call(t, "group_set", map[string]any{"server": "dock", "group": "dns administrators", "description": "DNS service administrators", "members": []string{"kt"}}); acctest.BoolOf(same["changed"]) || len(p.dock.Requests("admin/groups/set")) != 0 {
		t.Errorf("set to what it is = %v", same)
	}
	changed := suite.Call(t, "group_set", map[string]any{"server": "dock", "group": "DNS Administrators", "description": "", "members": []string{}, "new_name": "DNS"})
	if asked := p.dock.Last("admin/groups/set"); len(acctest.Strs(t, changed["changes"], "changes")) != 3 || asked.Params.Get("group") != "DNS Administrators" || !asked.Params.Has("description") || !asked.Params.Has("members") || asked.Params.Get("newGroup") != "DNS" {
		t.Errorf("changed = %v, with %v", changed["changes"], asked.Params)
	}
	if msg := suite.CallErr(t, "group_set", map[string]any{"server": "dock", "group": "Administrators", "members": []string{"kt"}}); !strings.Contains(msg, "admin is the account this tool works under on dock") || len(p.dock.Requests("admin/groups/set")) != 1 {
		t.Errorf("the tool's own account taken out of the administrators = %q", msg)
	}

	dry := suite.Call(t, "group_delete", map[string]any{"server": "dock", "group": "DNS Administrators", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have deleted the group DNS Administrators on dock, which had 1 members"}) || !slices.Equal(acctest.Strs(t, dry["members"], "members"), []string{"kt"}) || len(p.dock.Requests("admin/groups/delete")) != 0 {
		t.Errorf("a dry run of deleting a group = %v", dry)
	}
	if nothing := suite.Call(t, "group_delete", map[string]any{"server": "dock", "group": "nothing"}); acctest.BoolOf(nothing["changed"]) || len(p.dock.Requests("admin/groups/delete")) != 0 {
		t.Errorf("a group the server does not have, deleted = %v", nothing)
	}
}

func TestSessionsAndTokens(t *testing.T) {
	t.Parallel()

	p := accountsPair(t)
	suite := p.session(t, everything)

	rows := acctest.Rows(t, suite.Call(t, "session_list", nil)["servers"], "servers")
	sessions := acctest.Rows(t, rows[0]["sessions"], "sessions")
	if len(sessions) != 3 || !acctest.BoolOf(sessions[0]["current"]) || sessions[1]["id"] != "bbbb2222" || sessions[1]["agent"] != "curl" || !strings.Contains(acctest.Str(rows[1]["error"]), "Access was denied") {
		t.Errorf("session_list = %v", rows)
	}

	// a token is deleted by its id, the tool's own never, and one that is not there is said not to be
	if msg := suite.CallErr(t, "session_delete", map[string]any{"server": "dock", "id": "aaaa1111"}); !strings.Contains(msg, "aaaa1111 is the token this tool works under on dock") {
		t.Errorf("the tool's own token, deleted = %q", msg)
	}
	dry := suite.Call(t, "session_delete", map[string]any{"server": "dock", "id": "bbbb2222", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{`would have deleted the API token "scripts" of kt on dock`}) || len(p.dock.Requests("admin/sessions/delete")) != 0 {
		t.Errorf("a dry run of deleting a token = %v", dry)
	}
	ended := suite.Call(t, "session_delete", map[string]any{"server": "dock", "id": "cccc3333"})
	if !slices.Equal(acctest.Strs(t, ended["changes"], "changes"), []string{"ended the session of kt on dock"}) || p.dock.Last("admin/sessions/delete").Params.Get("partialToken") != "cccc3333" {
		t.Errorf("a session ended = %v", ended)
	}
	if nothing := suite.Call(t, "session_delete", map[string]any{"server": "dock", "id": "eeee5555"}); acctest.BoolOf(nothing["changed"]) || len(p.dock.Requests("admin/sessions/delete")) != 1 {
		t.Errorf("a session that is not there, ended = %v", nothing)
	}

	// a token is made for an account that is there, under a name it does not already use, and shown once
	made := suite.Call(t, "token_create", map[string]any{"server": "dock", "username": "KT", "token_name": "backups"})
	if asked := p.dock.Last("admin/sessions/createToken"); !strings.HasPrefix(acctest.Str(made["token"]), "dddd4444") || made["username"] != "kt" || asked.Params.Get("user") != "kt" || asked.Params.Get("tokenName") != "backups" || !strings.Contains(acctest.Str(made["note"]), "the only time the token is shown") {
		t.Errorf("token_create = %v, with %v", made["note"], asked.Params)
	}
	for msg, args := range map[string]map[string]any{
		`kt already has a token named "scripts" on dock`: {"server": "dock", "username": "kt", "token_name": "scripts"},
		"dock has no account named nobody":               {"server": "dock", "username": "nobody", "token_name": "x"},
		"give username and token_name":                   {"server": "dock", "username": "kt", "token_name": " "},
	} {
		if got := suite.CallErr(t, "token_create", args); !strings.Contains(got, msg) {
			t.Errorf("token_create %v = %q, want %q in it", args, got, msg)
		}
	}
	if len(p.dock.Requests("admin/sessions/createToken")) != 1 {
		t.Errorf("%d tokens were asked for, want the one", len(p.dock.Requests("admin/sessions/createToken")))
	}
}

// Who may do what is changed by naming who changes: everyone else is sent
// back as they were, since the server takes each list whole.
func TestAccess(t *testing.T) {
	t.Parallel()

	const logs = `{"section":"Logs","userPermissions":[{"username":"kt","canView":true,"canModify":false,"canDelete":false}],"groupPermissions":[{"name":"Administrators","canView":true,"canModify":true,"canDelete":true},{"name":"Everyone","canView":true,"canModify":false,"canDelete":false}],"users":["admin","kt","new"],"groups":["Administrators","DNS Administrators","Everyone"]}`
	p := accountsPair(t)
	p.both("admin/permissions/list", `{"permissions":[`+logs+`,{"section":"Zones","userPermissions":[],"groupPermissions":[{"name":"Administrators","canView":true,"canModify":true,"canDelete":true}]}]}`)
	p.both("admin/permissions/get", logs)
	p.both("admin/permissions/set", logs)
	p.both("zones/permissions/get", strings.Replace(logs, `"section":"Logs"`, `"section":"Zones","subItem":"example.com"`, 1))
	p.both("zones/permissions/set", strings.Replace(logs, `"section":"Logs"`, `"section":"Zones","subItem":"example.com"`, 1))
	suite := p.session(t, everything)

	all := acctest.Rows(t, acctest.Rows(t, suite.Call(t, "access_get", map[string]any{"server": "dock"})["servers"], "servers")[0]["permissions"], "permissions")
	if len(all) != 2 || all[0]["section"] != "Logs" || len(acctest.Rows(t, all[0]["groups"], "groups")) != 2 || acctest.Rows(t, all[0]["users"], "users")[0]["name"] != "kt" || len(p.dock.Requests("admin/permissions/list")) != 1 {
		t.Errorf("access_get = %v", all)
	}
	zone := acctest.Rows(t, acctest.Rows(t, suite.Call(t, "access_get", map[string]any{"server": "dock", "zone": "Example.com."})["servers"], "servers")[0]["permissions"], "permissions")
	if len(zone) != 1 || zone[0]["zone"] != "example.com" || p.dock.Last("zones/permissions/get").Params.Get("zone") != "example.com" {
		t.Errorf("a zone's = %v", zone)
	}
	if msg := suite.CallErr(t, "access_get", map[string]any{"section": "Logs", "zone": "example.com"}); !strings.Contains(msg, "not both") {
		t.Errorf("a section and a zone at once = %q", msg)
	}

	// one account given more, one group added, one taken off: both lists go back whole, the rest as they were
	set := suite.Call(t, "access_set", map[string]any{"server": "dock", "section": "Logs", "users": []map[string]any{{"name": "KT", "view": true, "modify": true}, {"name": "new", "view": true}}, "groups": []map[string]any{{"name": "DNS Administrators", "view": true, "delete": true}}, "remove_groups": []string{"everyone"}})
	asked := p.dock.Last("admin/permissions/set")
	if asked.Params.Get("section") != "Logs" || asked.Params.Get("userPermissions") != "kt|true|true|false|new|true|false|false" || asked.Params.Get("groupPermissions") != "Administrators|true|true|true|DNS Administrators|true|false|true" {
		t.Errorf("the permissions were set with %v", asked.Params)
	}
	if got := acctest.Strs(t, set["changes"], "changes"); !slices.Equal(got, []string{"changed what the account kt may do from view to view, modify, in the Logs section on dock", "allowed the account new to view, in the Logs section on dock", "allowed the group DNS Administrators to view, delete, in the Logs section on dock", "removed what the group Everyone was given by name, which was to view, in the Logs section on dock"}) {
		t.Errorf("changes = %v", got)
	}
	// given what it has, nothing is sent; a dry run says what would be and gives the lists as they would stand
	if same := suite.Call(t, "access_set", map[string]any{"server": "dock", "section": "Logs", "users": []map[string]any{{"name": "kt", "view": true}}}); acctest.BoolOf(same["changed"]) || len(p.dock.Requests("admin/permissions/set")) != 1 {
		t.Errorf("given what it has = %v", same)
	}
	dry := suite.Call(t, "access_set", map[string]any{"server": "dock", "zone": "example.com", "remove_users": []string{"kt"}, "dry_run": true})
	if after := acctest.Object(t, dry["after"], "after"); !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have removed what the account kt was given by name, which was to view, in the zone example.com on dock"}) || len(acctest.Rows(t, after["users"], "users")) != 0 || len(p.dock.Requests("zones/permissions/set")) != 0 {
		t.Errorf("a dry run on a zone = %v", dry)
	}
	suite.Call(t, "access_set", map[string]any{"server": "dock", "zone": "example.com", "remove_users": []string{"kt"}})
	if asked = p.dock.Last("zones/permissions/set"); asked.Params.Get("zone") != "example.com" || !asked.Params.Has("userPermissions") || asked.Params.Get("userPermissions") != "" {
		t.Errorf("a zone's permissions were set with %v", asked.Params)
	}

	sent := accountWrites(p.dock) + len(p.dock.Requests("zones/permissions/set"))
	for msg, args := range map[string]map[string]any{
		"one of the two":                                     {"server": "dock", "users": []map[string]any{{"name": "kt"}}},
		"nothing was given to change":                        {"server": "dock", "section": "Logs"},
		"dock has no account named nobody":                   {"server": "dock", "section": "Logs", "users": []map[string]any{{"name": "nobody", "view": true}}},
		"dock has no group named Nobodies":                   {"server": "dock", "section": "Logs", "groups": []map[string]any{{"name": "Nobodies", "view": true}}},
		"the Administrators group keeps everything":          {"server": "dock", "section": "administration", "groups": []map[string]any{{"name": "Administrators", "view": true, "modify": true}}},
		"the Administrators group keeps everything in Admin": {"server": "dock", "section": "Administration", "remove_groups": []string{"Administrators"}},
		"every entry names an account or a group":            {"server": "dock", "section": "Logs", "users": []map[string]any{{"name": "a|b", "view": true}}},
	} {
		if got := suite.CallErr(t, "access_set", args); !strings.Contains(got, msg) {
			t.Errorf("access_set %v = %q, want %q in it", args, got, msg)
		}
	}
	if now := accountWrites(p.dock) + len(p.dock.Requests("zones/permissions/set")); now != sent {
		t.Errorf("%d refused changes reached the server", now-sent)
	}
}

func TestSSOTools(t *testing.T) {
	t.Parallel()

	const sso = `{"ssoEnabled":false,"ssoAuthority":null,"ssoClientId":null,"ssoClientSecret":"************","ssoMetadataAddress":null,"ssoAllowSignup":false,"ssoAllowSignupOnlyForMappedUsers":true,"ssoGroupMap":[{"remoteGroup":"ops","localGroup":"Administrators"}],"localGroups":["Administrators","DNS Administrators"]}` //nolint:gosec // G101: the stars the server gives in place of a secret, in a canned answer
	p := accountsPair(t)
	p.both("admin/sso/get", sso)
	p.both("admin/sso/set", sso)
	p.both("admin/cluster/state", inNoCluster)
	suite := p.session(t, everything)

	row := acctest.Rows(t, suite.Call(t, "sso_get", nil)["servers"], "servers")[0]
	if acctest.BoolOf(row["enabled"]) || acctest.Object(t, row["group_map"], "group_map")["ops"] != "Administrators" || !acctest.BoolOf(row["allow_signup_only_for_mapped_users"]) || strings.Contains(fmt.Sprint(row), "*") {
		t.Errorf("sso_get = %v", row)
	}

	set := suite.Call(t, "sso_set", map[string]any{"server": "dock", "enabled": true, "authority": "https://id.example.com ", "client_id": "technitium", "client_secret": "5ecre7", "allow_signup": true, "group_map": map[string]string{"ops": "Administrators", "dns": "DNS Administrators"}})
	asked := p.dock.Last("admin/sso/set")
	for param, want := range map[string]string{"ssoEnabled": "true", "ssoAuthority": "https://id.example.com", "ssoClientId": "technitium", "ssoClientSecret": "5ecre7", "ssoAllowSignup": "true", "ssoGroupMap": "dns|DNS Administrators|ops|Administrators"} {
		if asked.Params.Get(param) != want {
			t.Errorf("single sign-on was set with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if asked.Params.Has("ssoAllowSignupOnlyForMappedUsers") || len(acctest.Strs(t, set["changes"], "changes")) != 6 || strings.Contains(fmt.Sprint(set), "5ecre7") {
		t.Errorf("set = %v, with %v", set["changes"], asked.Params)
	}
	if same := suite.Call(t, "sso_set", map[string]any{"server": "dock", "allow_signup": false, "group_map": map[string]string{"ops": "Administrators"}}); acctest.BoolOf(same["changed"]) || len(p.dock.Requests("admin/sso/set")) != 1 {
		t.Errorf("set to what it is = %v", same)
	}
	for msg, args := range map[string]map[string]any{
		"give authority, client_id and client_secret": {"server": "dock", "enabled": true},
		"dock has no group named Nobodies":            {"server": "dock", "group_map": map[string]string{"ops": "Nobodies"}},
	} {
		if got := suite.CallErr(t, "sso_set", args); !strings.Contains(got, msg) {
			t.Errorf("sso_set %v = %q, want %q in it", args, got, msg)
		}
	}
	if len(p.dock.Requests("admin/sso/set")) != 1 {
		t.Errorf("%d changes to single sign-on reached the server, want the one", len(p.dock.Requests("admin/sso/set")))
	}
}

// An account changed as itself: the tool signs in, makes the changes under
// the session, and signs out again whatever happened.
func TestAccountGetAndEdit(t *testing.T) {
	t.Parallel()

	session := strings.Repeat("5e55", 16)
	p := accountsPair(t)
	p.dock.Accept(session)
	profile := strings.Replace(account("kt", `,"isSsoUser":false`), `"memberOfGroups":[]`, `"memberOfGroups":["DNS Administrators"]`, 1)
	p.both("user/profile/get", profile)
	p.dock.Answer("user/profile/set", profile)
	p.dock.AnswerWhole("user/login", `{"username":"kt","displayName":"kt","totpEnabled":false,"token":"`+session+`","status":"ok"}`)
	for _, call := range []string{"user/logout", "user/changePassword", "user/2fa/enable", "user/2fa/disable"} {
		p.dock.AnswerWhole(call, `{"status":"ok"}`)
	}
	p.dock.Answer("user/2fa/init", `{"totpEnabled":false,"qrCodePngImage":"cGljdHVyZQ==","secret":"RZ56CYOXKAXI5D23"}`)
	p.dock.Answer("user/session/delete", `{}`)
	p.dock.AnswerWhole("user/createToken", `{"username":"kt","tokenName":"own","token":"`+strings.Repeat("7ok3", 16)+`","status":"ok"}`)
	p.dock.Answer("user/createSingleUseToken", `{"username":"kt","token":"`+strings.Repeat("0nce", 16)+`"}`)
	suite := p.session(t, everything)

	own := acctest.Rows(t, suite.Call(t, "account_get", nil)["servers"], "servers")
	if len(own) != 2 || own[0]["username"] != "kt" || !slices.Equal(acctest.Strs(t, own[0]["groups"], "groups"), []string{"DNS Administrators"}) {
		t.Errorf("account_get = %v", own)
	}

	begun := suite.Call(t, "account_edit", map[string]any{"server": "dock", "username": "kt", "password": "5ecre7", "display_name": "Kate", "two_factor": "begin", "create_token": "own", "end_session": "cccc3333", "new_password": "5ecre7-new"})
	if login := p.dock.Last("user/login"); login.Token != "" || login.Params.Get("user") != "kt" || login.Params.Get("pass") != "5ecre7" {
		t.Errorf("signed in with %v under %q", login.Params, login.Token)
	}
	for _, call := range []string{"user/profile/set", "user/2fa/init", "user/createToken", "user/session/delete", "user/changePassword", "user/logout"} {
		if p.dock.Last(call).Token != session {
			t.Errorf("%s was asked under %q, want the session signed in", call, p.dock.Last(call).Token)
		}
	}
	if begun["two_factor_secret"] != "RZ56CYOXKAXI5D23" || !strings.Contains(acctest.Str(begun["two_factor_uri"]), "otpauth://totp/kt?secret=RZ56CYOXKAXI5D23") || !strings.HasPrefix(acctest.Str(begun["token"]), "7ok3") || len(acctest.Strs(t, begun["changes"], "changes")) != 5 || strings.Contains(strings.Join(acctest.Strs(t, begun["changes"], "changes"), " "), "5ecre7") {
		t.Errorf("begun = %v", begun["changes"])
	}
	if asked := p.dock.Last("user/changePassword"); asked.Params.Get("pass") != "5ecre7" || asked.Params.Get("newPass") != "5ecre7-new" {
		t.Errorf("the password was changed with the names %v", slices.Sorted(maps.Keys(asked.Params)))
	}

	enabled := suite.Call(t, "account_edit", map[string]any{"server": "dock", "username": "kt", "password": "5ecre7", "totp": "111111", "two_factor": "ENABLE", "two_factor_code": " 123456 ", "single_use_token": true})
	if p.dock.Last("user/2fa/enable").Params.Get("totp") != "123456" || p.dock.Last("user/login").Params.Get("totp") != "111111" || !strings.HasPrefix(acctest.Str(enabled["token"]), "0nce") {
		t.Errorf("enabled = %v", enabled["changes"])
	}
	suite.Call(t, "account_edit", map[string]any{"server": "dock", "username": "kt", "password": "5ecre7", "two_factor": "disable"})
	if len(p.dock.Requests("user/2fa/disable")) != 1 || len(p.dock.Requests("user/logout")) != 3 {
		t.Errorf("%d sign-outs for 3 sign-ins", len(p.dock.Requests("user/logout")))
	}

	// what cannot be is refused before anyone is signed in, and a sign-in that fails changes nothing
	logins := len(p.dock.Requests("user/login"))
	for msg, args := range map[string]map[string]any{
		"give its username and password":      {"server": "dock", "username": "kt", "password": "", "display_name": "x"},
		`two_factor "maybe"`:                  {"server": "dock", "username": "kt", "password": "5ecre7", "two_factor": "maybe"},
		"is switched on with two_factor_code": {"server": "dock", "username": "kt", "password": "5ecre7", "two_factor": "enable"},
		"nothing was given to change":         {"server": "dock", "username": "kt", "password": "5ecre7"},
	} {
		if got := suite.CallErr(t, "account_edit", args); !strings.Contains(got, msg) {
			t.Errorf("account_edit %v = %q, want %q in it", args, got, msg)
		}
	}
	if len(p.dock.Requests("user/login")) != logins {
		t.Error("a call that was refused signed in first")
	}
	p.dock.Fail("user/login", "error", "Invalid username or password for user: kt")
	if msg := suite.CallErr(t, "account_edit", map[string]any{"server": "dock", "username": "kt", "password": "wrong-5ecre7", "display_name": "x"}); !strings.Contains(msg, "signing in to dock as kt") || strings.Contains(msg, "wrong-5ecre7") || len(p.dock.Requests("user/profile/set")) != 1 {
		t.Errorf("a sign-in that failed = %q", msg)
	}
}
