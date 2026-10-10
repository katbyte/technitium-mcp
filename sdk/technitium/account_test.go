package technitium_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// sessionToken is the token the canned server answers a sign-in with.
var sessionToken = strings.Repeat("932b2a34", 8)

// Signing in is the one thing done with no token: the name and password go
// in the body of a POST, and the client that comes back works under the
// session's own token.
func TestLoginAndTokens(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Accept(sessionToken)
	fake.AnswerWhole("user/login", `{"displayName":"Administrator","username":"admin","isSsoUser":false,"totpEnabled":true,"token":"`+sessionToken+`","info":{"version":"15.6","dnsServerDomain":"ns1.example","defaultRecordTtl":3600,"permissions":{"Zones":{"canView":true,"canModify":true,"canDelete":false}}},"status":"ok"}`)
	fake.AnswerWhole("user/createToken", `{"username":"admin","tokenName":"automation","token":"aaaa2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b6aaaa","status":"ok"}`)
	fake.AnswerWhole("user/createSingleUseToken", `{"username":"admin","token":"bbbb2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b6bbbb","status":"ok"}`)
	fake.AnswerWhole("user/logout", `{"status":"ok"}`)
	c := client(t, fake)

	session, who, err := c.Login(t.Context(), "admin", "hunter2", "123456")
	if err != nil {
		t.Fatal(err)
	}
	asked := fake.Last("user/login")
	if asked.Method != http.MethodPost || asked.Token != "" || asked.Params.Get("user") != "admin" || asked.Params.Get("pass") != "hunter2" || asked.Params.Get("totp") != "123456" || asked.Params.Get("includeInfo") != "true" {
		t.Errorf("signed in with %s %v under the token %q", asked.Method, asked.Params, asked.Token)
	}
	if who.Username != "admin" || who.DisplayName != "Administrator" || !who.TOTPEnabled || who.IsSSOUser || who.Info.Version != "15.6" || who.Info.Domain != "ns1.example" || !who.Info.Permissions["Zones"].CanModify || who.Info.Permissions["Zones"].CanDelete {
		t.Errorf("signed in as %+v", who)
	}
	if session.BaseURL() != c.BaseURL() {
		t.Errorf("the session is on %s, the client on %s", session.BaseURL(), c.BaseURL())
	}

	// what the session asks, it asks under its own token; the client it came from keeps its own
	token, err := session.CreateToken(t.Context(), "automation")
	if asked = fake.Last("user/createToken"); err != nil || !strings.HasPrefix(token, "aaaa") || asked.Token != sessionToken || asked.Method != http.MethodPost || len(asked.Params) != 1 || asked.Params.Get("tokenName") != "automation" {
		t.Errorf("CreateToken = %v, sent %v under %q", err, asked.Params, asked.Token)
	}
	token, err = c.CreateTokenFor(t.Context(), "admin", "hunter2", "", "automation")
	if asked = fake.Last("user/createToken"); err != nil || !strings.HasPrefix(token, "aaaa") || asked.Token != "" || asked.Params.Get("user") != "admin" || asked.Params.Get("pass") != "hunter2" || asked.Params.Has("totp") || asked.Params.Get("tokenName") != "automation" {
		t.Errorf("CreateTokenFor = %v, sent %v under %q", err, asked.Params, asked.Token)
	}
	once, err := session.SingleUseToken(t.Context())
	if asked = fake.Last("user/createSingleUseToken"); err != nil || !strings.HasPrefix(once, "bbbb") || asked.Token != sessionToken || len(asked.Params) != 0 {
		t.Errorf("SingleUseToken = %v, sent %v under %q", err, asked.Params, asked.Token)
	}
	if err := session.Logout(t.Context()); err != nil || fake.Last("user/logout").Token != sessionToken || fake.Last("user/logout").Method != http.MethodPost {
		t.Errorf("Logout = %v, under %q", err, fake.Last("user/logout").Token)
	}

	// an answer with no token in it is no session, and what names nobody is not sent
	fake.AnswerWhole("user/login", `{"username":"admin","status":"ok"}`)
	if _, _, err := c.Login(t.Context(), "admin", "hunter2", ""); err == nil || !strings.Contains(err.Error(), "gave no session") {
		t.Errorf("a sign-in that answered with no token = %v", err)
	}
	fake.AnswerWhole("user/createToken", `{"username":"admin","status":"ok"}`)
	if _, err := session.CreateToken(t.Context(), "automation"); err == nil || !strings.Contains(err.Error(), "gave no token") {
		t.Errorf("a token that was not given = %v", err)
	}
	fake.AnswerWhole("user/createSingleUseToken", `{"status":"ok"}`)
	if _, err := session.SingleUseToken(t.Context()); err == nil || !strings.Contains(err.Error(), "gave no token") {
		t.Errorf("a single use token that was not given = %v", err)
	}
	fake.Fail("user/login", "error", "Invalid username or password for user: admin")
	if _, _, err := c.Login(t.Context(), "admin", "wrong", ""); err == nil || !strings.Contains(err.Error(), "Invalid username or password") || strings.Contains(err.Error(), "wrong") {
		t.Errorf("a wrong password = %v", err)
	}
	sent := len(fake.Requests("user/login")) + len(fake.Requests("user/createToken"))
	if _, _, err := c.Login(t.Context(), "", "hunter2", ""); err == nil {
		t.Error("nobody signed in")
	}
	if _, _, err := c.Login(t.Context(), "admin", "", ""); err == nil {
		t.Error("an account signed in with no password")
	}
	if _, err := session.CreateToken(t.Context(), ""); err == nil {
		t.Error("a token was made under no name")
	}
	if _, err := c.CreateTokenFor(t.Context(), "admin", "", "", "automation"); err == nil {
		t.Error("a token was made for an account with no password")
	}
	if now := len(fake.Requests("user/login")) + len(fake.Requests("user/createToken")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}

// An account's own: its profile, its sessions, its password and its second
// factor.
func TestProfileAndPassword(t *testing.T) {
	t.Parallel()

	const profile = `{"displayName":"Administrator","username":"admin","isSsoUser":false,"totpEnabled":false,"disabled":false,"previousSessionLoggedOn":"2022-09-15T12:59:05.944Z","previousSessionRemoteAddress":"127.0.0.1","recentSessionLoggedOn":"2022-09-15T13:57:50.1843973Z","recentSessionRemoteAddress":"127.0.0.1","sessionTimeoutSeconds":1800,"memberOfGroups":["Administrators"],"sessions":[{"username":"admin","isCurrentSession":true,"partialToken":"620c3bfcd09d0a07","type":"Standard","tokenName":null,"lastSeen":"2022-09-15T13:58:02.4728Z","lastSeenRemoteAddress":"127.0.0.1","lastSeenUserAgent":"Mozilla/5.0"}]}`
	fake := technitiumtest.New(t)
	fake.Answer("user/profile/get", profile)
	fake.Answer("user/profile/set", profile)
	fake.Answer("user/session/delete", `{}`)
	fake.AnswerWhole("user/changePassword", `{"status":"ok"}`)
	fake.Answer("user/2fa/init", `{"totpEnabled":false,"qrCodePngImage":"iVBORw0KGgoAAAANSUhEU","secret":"RZ56CYOXKAXI5D23"}`)
	fake.AnswerWhole("user/2fa/enable", `{"status":"ok"}`)
	fake.AnswerWhole("user/2fa/disable", `{"status":"ok"}`)
	c := client(t, fake)

	got, err := c.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "admin" || got.DisplayName != "Administrator" || got.TOTPEnabled || got.Disabled || got.SessionTimeoutSeconds != 1800 || len(got.MemberOfGroups) != 1 || got.RecentSessionRemoteAddress != "127.0.0.1" || got.PreviousSessionLoggedOn == "" || len(got.Sessions) != 1 {
		t.Errorf("Profile = %+v", got)
	}
	if s := got.Sessions[0]; s.PartialToken != "620c3bfcd09d0a07" || !s.IsCurrentSession || s.Type != "Standard" || s.TokenName != "" {
		t.Errorf("its session = %+v", s)
	}

	if got, err = c.SetProfile(t.Context(), technitium.ProfileChange{DisplayName: "Admin", SessionTimeoutSeconds: 900}); err != nil || got.Username != "admin" {
		t.Errorf("SetProfile = %+v, %v", got, err)
	}
	if asked := fake.Last("user/profile/set"); asked.Method != http.MethodPost || len(asked.Params) != 2 || asked.Params.Get("displayName") != "Admin" || asked.Params.Get("sessionTimeoutSeconds") != "900" {
		t.Errorf("the profile was set with %v", asked.Params)
	}
	if _, err = c.SetProfile(t.Context(), technitium.ProfileChange{SessionTimeoutSeconds: 600}); err != nil || fake.Last("user/profile/set").Params.Has("displayName") {
		t.Errorf("the timeout alone was set with %v, %v", fake.Last("user/profile/set").Params, err)
	}
	if _, err = c.SetProfile(t.Context(), technitium.ProfileChange{}); err == nil || len(fake.Requests("user/profile/set")) != 2 {
		t.Errorf("nothing was set = %v", err)
	}

	if err := c.EndSession(t.Context(), "620c3bfcd09d0a07"); err != nil || fake.Last("user/session/delete").Params.Get("partialToken") != "620c3bfcd09d0a07" || fake.Last("user/session/delete").Method != http.MethodPost {
		t.Errorf("EndSession = %v, sent %v", err, fake.Last("user/session/delete").Params)
	}
	if err := c.EndSession(t.Context(), ""); err == nil || len(fake.Requests("user/session/delete")) != 1 {
		t.Errorf("no session was ended = %v", err)
	}

	// a password goes in the body of a POST, the rounds only when asked for
	if err := c.ChangePassword(t.Context(), "old", "new-one", "", 0); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("user/changePassword"); asked.Method != http.MethodPost || len(asked.Params) != 2 || asked.Params.Get("pass") != "old" || asked.Params.Get("newPass") != "new-one" {
		t.Errorf("the password was changed with %v", asked.Params)
	}
	if err := c.ChangePassword(t.Context(), "old", "new-one", "123456", 200000); err != nil || fake.Last("user/changePassword").Params.Get("totp") != "123456" || fake.Last("user/changePassword").Params.Get("iterations") != "200000" {
		t.Errorf("the password was changed with %v, %v", fake.Last("user/changePassword").Params, err)
	}
	for name, change := range map[string]struct {
		current, replacement string
		rounds               int
	}{"no current": {"", "new", 0}, "no new": {"old", "", 0}, "too few rounds": {"old", "new", 5}, "too many rounds": {"old", "new", technitium.MaxPasswordIterations + 1}} {
		if err := c.ChangePassword(t.Context(), change.current, change.replacement, "", change.rounds); err == nil {
			t.Errorf("%s: the password was changed", name)
		}
	}
	if len(fake.Requests("user/changePassword")) != 2 {
		t.Errorf("%d password changes reached the server, want 2", len(fake.Requests("user/changePassword")))
	}

	setup, err := c.InitTwoFactor(t.Context())
	if err != nil || setup.Enabled || setup.Secret != "RZ56CYOXKAXI5D23" || setup.QRCodePNG == "" || fake.Last("user/2fa/init").Method != http.MethodPost {
		t.Errorf("InitTwoFactor = %+v, %v", setup, err)
	}
	if err := c.EnableTwoFactor(t.Context(), "123456"); err != nil || fake.Last("user/2fa/enable").Params.Get("totp") != "123456" || fake.Last("user/2fa/enable").Method != http.MethodPost {
		t.Errorf("EnableTwoFactor = %v, sent %v", err, fake.Last("user/2fa/enable").Params)
	}
	if err := c.EnableTwoFactor(t.Context(), ""); err == nil || len(fake.Requests("user/2fa/enable")) != 1 {
		t.Errorf("a second factor was switched on with no code = %v", err)
	}
	if err := c.DisableTwoFactor(t.Context()); err != nil || fake.Last("user/2fa/disable").Method != http.MethodPost {
		t.Errorf("DisableTwoFactor = %v", err)
	}
}
