package technitium_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// userDetails is one account as the server gives it whole.
const userDetails = `{"displayName":"User","username":"user1","isSsoUser":false,"totpEnabled":true,"disabled":false,"previousSessionLoggedOn":"0001-01-01T00:00:00","previousSessionRemoteAddress":"0.0.0.0","recentSessionLoggedOn":"2022-09-18T09:55:26.9800695Z","recentSessionRemoteAddress":"127.0.0.1","sessionTimeoutSeconds":1800,"memberOfGroups":["DNS Administrators"],"sessions":[{"username":"user1","isCurrentSession":false,"partialToken":"ddfaecb8e9325e77","type":"ApiToken","tokenName":"MyToken1","lastSeen":"2022-09-17T13:22:45.671Z","lastSeenRemoteAddress":"127.0.0.1","lastSeenUserAgent":"curl"}],"groups":["Administrators","DHCP Administrators","DNS Administrators"]}`

func TestUsersAndSessions(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("admin/sessions/createToken", `{"username":"user1","tokenName":"MyToken1","token":"ddfaecb8e9325e77865ee7e100f89596a65d3eae0e6dddcb33172355b95a64af"}`)
	fake.Answer("admin/sessions/delete", `{}`)
	fake.Answer("admin/users/list", `{"users":[{"displayName":"Administrator","username":"admin","isSsoUser":false,"disabled":false,"previousSessionLoggedOn":"2022-09-17T13:20:32.7933783Z","previousSessionRemoteAddress":"127.0.0.1","recentSessionLoggedOn":"2022-09-17T13:22:45.671081Z","recentSessionRemoteAddress":"127.0.0.1"},{"displayName":"User","username":"user1","isSsoUser":false,"disabled":true,"previousSessionLoggedOn":"0001-01-01T00:00:00Z","previousSessionRemoteAddress":"0.0.0.0","recentSessionLoggedOn":"0001-01-01T00:00:00Z","recentSessionRemoteAddress":"0.0.0.0"}]}`)
	fake.Answer("admin/users/get", userDetails)
	fake.Answer("admin/users/create", `{"displayName":"User","username":"user1","isSsoUser":false,"disabled":false,"previousSessionLoggedOn":"0001-01-01T00:00:00","previousSessionRemoteAddress":"0.0.0.0","recentSessionLoggedOn":"0001-01-01T00:00:00","recentSessionRemoteAddress":"0.0.0.0"}`)
	fake.Answer("admin/users/set", userDetails)
	fake.Answer("admin/users/delete", `{}`)
	c := client(t, fake)

	token, err := c.CreateTokenAs(t.Context(), "user1", "MyToken1")
	if asked := fake.Last("admin/sessions/createToken"); err != nil || !strings.HasPrefix(token, "ddfaecb8") || asked.Method != http.MethodPost || len(asked.Params) != 2 || asked.Params.Get("user") != "user1" || asked.Params.Get("tokenName") != "MyToken1" {
		t.Errorf("CreateTokenAs = %v, sent %v", err, asked.Params)
	}
	fake.Answer("admin/sessions/createToken", `{"username":"user1","tokenName":"MyToken1"}`)
	if _, err := c.CreateTokenAs(t.Context(), "user1", "MyToken1"); err == nil || !strings.Contains(err.Error(), "gave no token") {
		t.Errorf("a token that was not given = %v", err)
	}
	if err := c.DeleteSession(t.Context(), "ddfaecb8e9325e77"); err != nil || fake.Last("admin/sessions/delete").Params.Get("partialToken") != "ddfaecb8e9325e77" || fake.Last("admin/sessions/delete").Method != http.MethodPost {
		t.Errorf("DeleteSession = %v, sent %v", err, fake.Last("admin/sessions/delete").Params)
	}

	users, err := c.Users(t.Context())
	if err != nil || len(users) != 2 || users[0].Username != "admin" || users[0].DisplayName != "Administrator" || users[0].Disabled || !users[1].Disabled || users[1].RecentSessionRemoteAddress != "0.0.0.0" {
		t.Errorf("Users = %+v, %v", users, err)
	}
	one, err := c.User(t.Context(), "user1", true)
	if err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("admin/users/get"); len(asked.Params) != 2 || asked.Params.Get("user") != "user1" || asked.Params.Get("includeGroups") != "true" {
		t.Errorf("the account was asked for with %v", asked.Params)
	}
	if one.Username != "user1" || !one.TOTPEnabled || one.SessionTimeoutSeconds != 1800 || len(one.MemberOfGroups) != 1 || len(one.Groups) != 3 || len(one.Sessions) != 1 || one.Sessions[0].PartialToken != "ddfaecb8e9325e77" || one.Sessions[0].Type != technitium.SessionAPIToken {
		t.Errorf("User = %+v", one)
	}
	if _, err := c.User(t.Context(), "user1", false); err != nil || fake.Last("admin/users/get").Params.Has("includeGroups") {
		t.Errorf("the account alone was asked for with %v, %v", fake.Last("admin/users/get").Params, err)
	}

	made, err := c.CreateUser(t.Context(), technitium.NewUser{Username: "user1", Password: "a password", DisplayName: "User"})
	if asked := fake.Last("admin/users/create"); err != nil || made.Username != "user1" || asked.Method != http.MethodPost || len(asked.Params) != 3 || asked.Params.Get("user") != "user1" || asked.Params.Get("pass") != "a password" || asked.Params.Get("displayName") != "User" {
		t.Errorf("CreateUser = %+v, %v, sent %v", made, err, asked.Params)
	}

	// only what is given is sent; a second factor can only be taken off, and no group is a list with nothing in it
	changed, err := c.SetUser(t.Context(), "user1", technitium.UserChange{DisplayName: "A User", NewUsername: "user2", DisableTwoFactor: true, Disabled: new(true), SessionTimeoutSeconds: 600, NewPassword: "another", Iterations: 150000, MemberOfGroups: []string{"DNS Administrators", "DHCP Administrators"}})
	if err != nil || changed.Username != "user1" {
		t.Fatalf("SetUser = %+v, %v", changed, err)
	}
	asked := fake.Last("admin/users/set")
	for param, want := range map[string]string{"user": "user1", "displayName": "A User", "newUser": "user2", "totpEnabled": "false", "disabled": "true", "sessionTimeoutSeconds": "600", "newPass": "another", "iterations": "150000", "memberOfGroups": "DNS Administrators,DHCP Administrators"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the account was set with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if asked.Method != http.MethodPost || len(asked.Params) != 9 {
		t.Errorf("the account was set with %s %v", asked.Method, asked.Params)
	}
	if _, err := c.SetUser(t.Context(), "user1", technitium.UserChange{Disabled: new(false), MemberOfGroups: []string{}}); err != nil {
		t.Fatal(err)
	}
	if asked = fake.Last("admin/users/set"); len(asked.Params) != 3 || asked.Params.Get("disabled") != "false" || !asked.Params.Has("memberOfGroups") || asked.Params.Get("memberOfGroups") != "" || asked.Params.Has("totpEnabled") {
		t.Errorf("the account was switched on and taken out of its groups with %v", asked.Params)
	}
	if err := c.DeleteUser(t.Context(), "user1"); err != nil || fake.Last("admin/users/delete").Params.Get("user") != "user1" || fake.Last("admin/users/delete").Method != http.MethodPost {
		t.Errorf("DeleteUser = %v, sent %v", err, fake.Last("admin/users/delete").Params)
	}

	// what names nobody, or sets nothing, is not sent
	sent := len(fake.Requests("admin/users/set")) + len(fake.Requests("admin/users/create")) + len(fake.Requests("admin/users/get")) + len(fake.Requests("admin/users/delete")) + len(fake.Requests("admin/sessions/delete")) + len(fake.Requests("admin/sessions/createToken"))
	refused := map[string]error{}
	_, refused["a token for nobody"] = c.CreateTokenAs(t.Context(), "", "MyToken1")
	_, refused["a token with no name"] = c.CreateTokenAs(t.Context(), "user1", "")
	refused["no session"] = c.DeleteSession(t.Context(), "")
	_, refused["nobody read"] = c.User(t.Context(), "", false)
	_, refused["an account with no password"] = c.CreateUser(t.Context(), technitium.NewUser{Username: "user1"})
	_, refused["an account with no name"] = c.CreateUser(t.Context(), technitium.NewUser{Password: "a password"})
	_, refused["nobody set"] = c.SetUser(t.Context(), "", technitium.UserChange{DisplayName: "x"})
	_, refused["nothing set"] = c.SetUser(t.Context(), "user1", technitium.UserChange{})
	_, refused["rounds with no password"] = c.SetUser(t.Context(), "user1", technitium.UserChange{Iterations: 150000})
	_, refused["too few rounds"] = c.SetUser(t.Context(), "user1", technitium.UserChange{NewPassword: "another", Iterations: 9})
	refused["nobody deleted"] = c.DeleteUser(t.Context(), "")
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	if now := len(fake.Requests("admin/users/set")) + len(fake.Requests("admin/users/create")) + len(fake.Requests("admin/users/get")) + len(fake.Requests("admin/users/delete")) + len(fake.Requests("admin/sessions/delete")) + len(fake.Requests("admin/sessions/createToken")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}

func TestGroups(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("admin/groups/list", `{"groups":[{"name":"Administrators","description":"Super administrators"},{"name":"DNS Administrators","description":"DNS service administrators"}]}`)
	fake.Answer("admin/groups/get", `{"name":"Administrators","description":"Super administrators","members":["admin"],"users":["admin","shreyas"]}`)
	fake.Answer("admin/groups/create", `{"name":"Group1","description":"My description"}`)
	fake.Answer("admin/groups/set", `{"name":"Group2","description":"","members":["admin"]}`)
	fake.Answer("admin/groups/delete", `{}`)
	c := client(t, fake)

	groups, err := c.Groups(t.Context())
	if err != nil || len(groups) != 2 || groups[0].Name != "Administrators" || groups[1].Description != "DNS service administrators" {
		t.Errorf("Groups = %+v, %v", groups, err)
	}
	one, err := c.Group(t.Context(), "Administrators", true)
	if asked := fake.Last("admin/groups/get"); err != nil || one.Name != "Administrators" || len(one.Members) != 1 || len(one.Users) != 2 || len(asked.Params) != 2 || asked.Params.Get("group") != "Administrators" || asked.Params.Get("includeUsers") != "true" {
		t.Errorf("Group = %+v, %v, asked with %v", one, err, asked.Params)
	}
	if _, err := c.Group(t.Context(), "Administrators", false); err != nil || fake.Last("admin/groups/get").Params.Has("includeUsers") {
		t.Errorf("the group alone was asked for with %v, %v", fake.Last("admin/groups/get").Params, err)
	}
	made, err := c.CreateGroup(t.Context(), "Group1", "My description")
	if asked := fake.Last("admin/groups/create"); err != nil || made.Name != "Group1" || made.Description != "My description" || asked.Method != http.MethodPost || len(asked.Params) != 2 || asked.Params.Get("group") != "Group1" || asked.Params.Get("description") != "My description" {
		t.Errorf("CreateGroup = %+v, %v, sent %v", made, err, asked.Params)
	}
	if _, err := c.CreateGroup(t.Context(), "Group1", ""); err != nil || fake.Last("admin/groups/create").Params.Has("description") {
		t.Errorf("a group with no description was made with %v, %v", fake.Last("admin/groups/create").Params, err)
	}

	// a description is cleared by "", and left alone by saying nothing; so are the members
	changed, err := c.SetGroup(t.Context(), "Group1", technitium.GroupChange{NewName: "Group2", Description: new(""), Members: []string{"admin"}})
	if asked := fake.Last("admin/groups/set"); err != nil || changed.Name != "Group2" || len(changed.Members) != 1 || asked.Method != http.MethodPost || len(asked.Params) != 4 || asked.Params.Get("group") != "Group1" || asked.Params.Get("newGroup") != "Group2" || !asked.Params.Has("description") || asked.Params.Get("description") != "" || asked.Params.Get("members") != "admin" {
		t.Errorf("SetGroup = %+v, %v, sent %v", changed, err, asked.Params)
	}
	if _, err := c.SetGroup(t.Context(), "Group1", technitium.GroupChange{Members: []string{}}); err != nil || len(fake.Last("admin/groups/set").Params) != 2 || !fake.Last("admin/groups/set").Params.Has("members") || fake.Last("admin/groups/set").Params.Has("description") {
		t.Errorf("the group was emptied with %v, %v", fake.Last("admin/groups/set").Params, err)
	}
	if err := c.DeleteGroup(t.Context(), "Group1"); err != nil || fake.Last("admin/groups/delete").Params.Get("group") != "Group1" || fake.Last("admin/groups/delete").Method != http.MethodPost {
		t.Errorf("DeleteGroup = %v, sent %v", err, fake.Last("admin/groups/delete").Params)
	}

	sent := len(fake.Requests("admin/groups/get")) + len(fake.Requests("admin/groups/create")) + len(fake.Requests("admin/groups/set")) + len(fake.Requests("admin/groups/delete"))
	refused := map[string]error{}
	_, refused["no group read"] = c.Group(t.Context(), "", false)
	_, refused["a group with no name"] = c.CreateGroup(t.Context(), "", "x")
	_, refused["no group set"] = c.SetGroup(t.Context(), "", technitium.GroupChange{NewName: "x"})
	_, refused["nothing set"] = c.SetGroup(t.Context(), "Group1", technitium.GroupChange{})
	refused["no group deleted"] = c.DeleteGroup(t.Context(), "")
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	if now := len(fake.Requests("admin/groups/get")) + len(fake.Requests("admin/groups/create")) + len(fake.Requests("admin/groups/set")) + len(fake.Requests("admin/groups/delete")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}

// Who may do what, for a section and for one zone: read as lists, and set as
// the table the API takes written out in one line.
func TestPermissions(t *testing.T) {
	t.Parallel()

	const section = `{"section":"Dashboard","userPermissions":[{"username":"shreyas","canView":true,"canModify":false,"canDelete":false}],"groupPermissions":[{"name":"Administrators","canView":true,"canModify":true,"canDelete":true},{"name":"Everyone","canView":true,"canModify":false,"canDelete":false}],"users":["admin","shreyas"],"groups":["Administrators","Everyone"]}`
	const zone = `{"section":"Zones","subItem":"example.com","userPermissions":[{"username":"admin","canView":true,"canModify":true,"canDelete":true}],"groupPermissions":[{"name":"DNS Administrators","canView":true,"canModify":true,"canDelete":true}]}`
	fake := technitiumtest.New(t)
	fake.Answer("admin/permissions/list", `{"permissions":[`+section+`,{"section":"Zones","userPermissions":[],"groupPermissions":[{"name":"Administrators","canView":true,"canModify":true,"canDelete":true}]}]}`)
	fake.Answer("admin/permissions/get", section)
	fake.Answer("admin/permissions/set", section)
	fake.Answer("zones/permissions/get", zone)
	fake.Answer("zones/permissions/set", zone)
	c := client(t, fake)

	all, err := c.Permissions(t.Context())
	if err != nil || len(all) != 2 || all[0].Section != "Dashboard" || len(all[0].Users) != 1 || len(all[0].Groups) != 2 || all[1].Section != "Zones" || len(all[1].Users) != 0 {
		t.Errorf("Permissions = %+v, %v", all, err)
	}
	one, err := c.SectionPermissions(t.Context(), "Dashboard", true)
	if err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("admin/permissions/get"); len(asked.Params) != 2 || asked.Params.Get("section") != "Dashboard" || asked.Params.Get("includeUsersAndGroups") != "true" {
		t.Errorf("the section was asked for with %v", asked.Params)
	}
	if u := one.Users[0]; u.Username != "shreyas" || !u.CanView || u.CanModify || u.CanDelete {
		t.Errorf("an account's permissions = %+v", u)
	}
	if g := one.Groups[0]; g.Name != "Administrators" || !g.CanView || !g.CanModify || !g.CanDelete || len(one.AllUsers) != 2 || len(one.AllGroups) != 2 {
		t.Errorf("a group's permissions = %+v, among %v and %v", g, one.AllUsers, one.AllGroups)
	}
	if _, err := c.SectionPermissions(t.Context(), "Dashboard", false); err != nil || fake.Last("admin/permissions/get").Params.Has("includeUsersAndGroups") {
		t.Errorf("the section alone was asked for with %v, %v", fake.Last("admin/permissions/get").Params, err)
	}

	change := technitium.AccessChange{Users: []technitium.UserAccess{{Username: "shreyas", CanView: true}}, Groups: []technitium.GroupAccess{{Name: "Administrators", CanView: true, CanModify: true, CanDelete: true}, {Name: "Everyone", CanView: true}}}
	if _, err := c.SetSectionPermissions(t.Context(), "Dashboard", change); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("admin/permissions/set"); asked.Method != http.MethodPost || len(asked.Params) != 3 || asked.Params.Get("section") != "Dashboard" || asked.Params.Get("userPermissions") != "shreyas|true|false|false" || asked.Params.Get("groupPermissions") != "Administrators|true|true|true|Everyone|true|false|false" {
		t.Errorf("the section was set with %v", asked.Params)
	}
	// a list given with nothing in it is nobody; one not given is left alone
	if _, err := c.SetSectionPermissions(t.Context(), "Dashboard", technitium.AccessChange{Users: []technitium.UserAccess{}}); err != nil || len(fake.Last("admin/permissions/set").Params) != 2 || !fake.Last("admin/permissions/set").Params.Has("userPermissions") || fake.Last("admin/permissions/set").Params.Get("userPermissions") != "" {
		t.Errorf("the accounts were cleared with %v, %v", fake.Last("admin/permissions/set").Params, err)
	}

	forZone, err := c.ZonePermissions(t.Context(), "example.com", true)
	if asked := fake.Last("zones/permissions/get"); err != nil || forZone.Section != "Zones" || forZone.SubItem != "example.com" || len(forZone.Users) != 1 || len(asked.Params) != 2 || asked.Params.Get("zone") != "example.com" || asked.Params.Get("includeUsersAndGroups") != "true" {
		t.Errorf("ZonePermissions = %+v, %v, asked with %v", forZone, err, asked.Params)
	}
	if _, err := c.SetZonePermissions(t.Context(), "example.com", change); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/permissions/set"); asked.Method != http.MethodPost || len(asked.Params) != 3 || asked.Params.Get("zone") != "example.com" || asked.Params.Get("userPermissions") != "shreyas|true|false|false" || !strings.HasPrefix(asked.Params.Get("groupPermissions"), "Administrators|true|true|true|") {
		t.Errorf("the zone was set with %v", asked.Params)
	}

	sent := len(fake.Requests("admin/permissions/get")) + len(fake.Requests("admin/permissions/set")) + len(fake.Requests("zones/permissions/get")) + len(fake.Requests("zones/permissions/set"))
	refused := map[string]error{}
	_, refused["no section read"] = c.SectionPermissions(t.Context(), "", false)
	_, refused["no section set"] = c.SetSectionPermissions(t.Context(), "", change)
	_, refused["nobody's permissions"] = c.SetSectionPermissions(t.Context(), "Dashboard", technitium.AccessChange{})
	_, refused["a name with a bar in it"] = c.SetSectionPermissions(t.Context(), "Dashboard", technitium.AccessChange{Groups: []technitium.GroupAccess{{Name: "a|b"}}})
	_, refused["an account with no name"] = c.SetSectionPermissions(t.Context(), "Dashboard", technitium.AccessChange{Users: []technitium.UserAccess{{}}})
	_, refused["no zone read"] = c.ZonePermissions(t.Context(), "", false)
	_, refused["no zone set"] = c.SetZonePermissions(t.Context(), "", change)
	_, refused["nobody's permissions on a zone"] = c.SetZonePermissions(t.Context(), "example.com", technitium.AccessChange{})
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	if now := len(fake.Requests("admin/permissions/get")) + len(fake.Requests("admin/permissions/set")) + len(fake.Requests("zones/permissions/get")) + len(fake.Requests("zones/permissions/set")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}

func TestSSO(t *testing.T) {
	t.Parallel()

	const sso = `{"ssoEnabled":true,"ssoAuthority":"https://id.example.com","ssoClientId":"technitium","ssoClientSecret":"************","ssoMetadataAddress":null,"ssoAllowSignup":false,"ssoAllowSignupOnlyForMappedUsers":true,"ssoGroupMap":[{"remoteGroup":"dns-admins","localGroup":"DNS Administrators"}],"localGroups":["Administrators","DNS Administrators"]}` //nolint:gosec // G101: an answer as the server gives it, with its secret starred out
	const ssoUser = `{"displayName":"User","username":"user1","isSsoUser":true,"disabled":false,"previousSessionLoggedOn":"0001-01-01T00:00:00","previousSessionRemoteAddress":"0.0.0.0","recentSessionLoggedOn":"0001-01-01T00:00:00","recentSessionRemoteAddress":"0.0.0.0"}`
	fake := technitiumtest.New(t)
	fake.Answer("admin/sso/get", sso)
	fake.Answer("admin/sso/set", sso)
	fake.Answer("admin/sso/users/create", ssoUser)
	fake.Answer("admin/sso/users/set", ssoUser)
	c := client(t, fake)

	got, err := c.SSO(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Authority != "https://id.example.com" || got.ClientID != "technitium" || got.MetadataAddress != "" || got.AllowSignup || !got.AllowSignupOnlyForMappedUsers || len(got.GroupMap) != 1 || got.GroupMap[0].RemoteGroup != "dns-admins" || got.GroupMap[0].LocalGroup != "DNS Administrators" || len(got.LocalGroups) != 2 || fake.Last("admin/sso/get").Params.Get("includeGroups") != "true" {
		t.Errorf("SSO = %+v, asked with %v", got, fake.Last("admin/sso/get").Params)
	}
	if _, err := c.SSO(t.Context(), false); err != nil || len(fake.Last("admin/sso/get").Params) != 0 {
		t.Errorf("single sign-on alone was asked for with %v, %v", fake.Last("admin/sso/get").Params, err)
	}

	change := technitium.SSOChange{Enabled: new(true), Authority: new("https://id.example.com"), ClientID: new("technitium"), MetadataAddress: new(""), ClientSecret: "5ecre7", AllowSignup: new(false), AllowSignupOnlyForMappedUsers: new(true), GroupMap: []technitium.GroupMapping{{RemoteGroup: "dns-admins", LocalGroup: "DNS Administrators"}, {RemoteGroup: "ops", LocalGroup: "Administrators"}}}
	if _, err := c.SetSSO(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	asked := fake.Last("admin/sso/set")
	for param, want := range map[string]string{"ssoEnabled": "true", "ssoAuthority": "https://id.example.com", "ssoClientId": "technitium", "ssoMetadataAddress": "", "ssoClientSecret": "5ecre7", "ssoAllowSignup": "false", "ssoAllowSignupOnlyForMappedUsers": "true", "ssoGroupMap": "dns-admins|DNS Administrators|ops|Administrators"} {
		if !asked.Params.Has(param) || asked.Params.Get(param) != want {
			t.Errorf("single sign-on was set with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if asked.Method != http.MethodPost || len(asked.Params) != 8 {
		t.Errorf("single sign-on was set with %s %v", asked.Method, asked.Params)
	}
	if _, err := c.SetSSO(t.Context(), technitium.SSOChange{Enabled: new(false)}); err != nil || len(fake.Last("admin/sso/set").Params) != 1 || fake.Last("admin/sso/set").Params.Get("ssoEnabled") != "false" {
		t.Errorf("single sign-on was switched off with %v, %v", fake.Last("admin/sso/set").Params, err)
	}

	made, err := c.CreateSSOUser(t.Context(), technitium.NewSSOUser{Username: "user1", DisplayName: "User", Identifier: "sub-1234", MemberOfGroups: []string{"DNS Administrators"}})
	if asked = fake.Last("admin/sso/users/create"); err != nil || !made.IsSSOUser || asked.Method != http.MethodPost || len(asked.Params) != 4 || asked.Params.Get("user") != "user1" || asked.Params.Get("ssoIdentifier") != "sub-1234" || asked.Params.Get("displayName") != "User" || asked.Params.Get("memberOfGroups") != "DNS Administrators" {
		t.Errorf("CreateSSOUser = %+v, %v, sent %v", made, err, asked.Params)
	}
	changed, err := c.SetSSOUser(t.Context(), "user1", technitium.SSOUserChange{NewUsername: "user2", DisplayName: "A User", MemberOfGroups: []string{}})
	if asked = fake.Last("admin/sso/users/set"); err != nil || changed.Username != "user1" || asked.Method != http.MethodPost || len(asked.Params) != 4 || asked.Params.Get("user") != "user1" || asked.Params.Get("newUser") != "user2" || asked.Params.Get("displayName") != "A User" || !asked.Params.Has("memberOfGroups") {
		t.Errorf("SetSSOUser = %+v, %v, sent %v", changed, err, asked.Params)
	}

	sent := len(fake.Requests("admin/sso/set")) + len(fake.Requests("admin/sso/users/create")) + len(fake.Requests("admin/sso/users/set"))
	refused := map[string]error{}
	_, refused["nothing set"] = c.SetSSO(t.Context(), technitium.SSOChange{})
	_, refused["a mapping to nothing"] = c.SetSSO(t.Context(), technitium.SSOChange{GroupMap: []technitium.GroupMapping{{RemoteGroup: "ops"}}})
	_, refused["a mapping with a bar in it"] = c.SetSSO(t.Context(), technitium.SSOChange{GroupMap: []technitium.GroupMapping{{RemoteGroup: "a|b", LocalGroup: "Administrators"}}})
	_, refused["an account the provider does not know"] = c.CreateSSOUser(t.Context(), technitium.NewSSOUser{Username: "user1"})
	_, refused["an account with no name"] = c.CreateSSOUser(t.Context(), technitium.NewSSOUser{Identifier: "sub-1234"})
	_, refused["nobody set"] = c.SetSSOUser(t.Context(), "", technitium.SSOUserChange{DisplayName: "x"})
	_, refused["nothing of the account set"] = c.SetSSOUser(t.Context(), "user1", technitium.SSOUserChange{})
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	if now := len(fake.Requests("admin/sso/set")) + len(fake.Requests("admin/sso/users/create")) + len(fake.Requests("admin/sso/users/set")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}
