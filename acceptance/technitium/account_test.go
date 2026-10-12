//go:build acceptance

package technitium_test

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

	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// code is the one-time code an authenticator app shows for a secret at a
// time (RFC 6238: six digits, a new one every thirty seconds).
func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("the secret is not base32: %v", err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30)) //nolint:gosec // G115: the time is after 1970
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	at4 := sum[len(sum)-1] & 0x0f

	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[at4:at4+4])&0x7fffffff)%1000000)
}

// An account from its making to its deletion: signed in as, given tokens,
// its password changed, a second factor put on and taken off, its sessions
// ended one by one.
func TestAccountLife(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	const name, pass, newPass = "it-account", "a first passw0rd", "a second passw0rd"
	_ = c.DeleteUser(ctx, name)
	_ = c.DeleteUser(ctx, name+"-renamed")

	made, err := c.CreateUser(ctx, technitium.NewUser{Username: name, Password: pass, DisplayName: "An Account"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.DeleteUser(noCancel(t), name) })
	if made.Username != name || made.DisplayName != "An Account" || made.Disabled || made.IsSSOUser {
		t.Errorf("CreateUser = %+v", made)
	}
	if _, err := c.CreateUser(ctx, technitium.NewUser{Username: name, Password: pass}); err == nil {
		t.Error("the account was made twice")
	}
	users, err := c.Users(ctx)
	if err != nil || !slices.ContainsFunc(users, func(u technitium.User) bool { return u.Username == name }) || !slices.ContainsFunc(users, func(u technitium.User) bool { return u.Username == "admin" }) {
		t.Errorf("Users = %+v, %v", users, err)
	}
	one, err := c.User(ctx, name, true)
	if err != nil || one.Username != name || one.TOTPEnabled || one.SessionTimeoutSeconds == 0 || !slices.Contains(one.Groups, "Administrators") || len(one.Sessions) != 0 {
		t.Errorf("User = %+v, %v", one, err)
	}
	if _, err := c.User(ctx, "it-nobody", false); err == nil {
		t.Error("an account that is not there was read")
	}

	// signed in, the account works under a session of its own
	session, who, err := c.Login(ctx, name, pass, "")
	if err != nil {
		t.Fatal(err)
	}
	if who.Username != name || who.DisplayName != "An Account" || who.TOTPEnabled || who.Info.Version == "" || len(who.Info.Permissions) == 0 {
		t.Errorf("signed in as %+v", who)
	}
	if _, _, err := c.Login(ctx, name, "not its password", ""); err == nil {
		t.Error("the account signed in with a wrong password")
	}
	profile, err := session.Profile(ctx)
	if err != nil || profile.Username != name || len(profile.Sessions) != 1 || !profile.Sessions[0].IsCurrentSession || profile.Sessions[0].Type != "Standard" || profile.Sessions[0].PartialToken == "" || profile.RecentSessionLoggedOn == "" {
		t.Errorf("Profile = %+v, %v", profile, err)
	}
	if profile, err = session.SetProfile(ctx, technitium.ProfileChange{DisplayName: "Its Own Name", SessionTimeoutSeconds: 900}); err != nil || profile.DisplayName != "Its Own Name" || profile.SessionTimeoutSeconds != 900 {
		t.Errorf("SetProfile = %+v, %v", profile, err)
	}
	// an API token is refused what is the account's own to change
	if _, err := c.SetProfile(ctx, technitium.ProfileChange{DisplayName: "By A Token"}); err == nil {
		t.Error("an API token changed its account's profile")
	}

	// tokens: one made under the session, one with the password, one by the administrator, and one that works once
	token, err := session.CreateToken(ctx, "it-session-made")
	if err != nil || len(token) < 32 {
		t.Fatalf("CreateToken = %d characters, %v", len(token), err)
	}
	byToken, err := technitium.New(c.BaseURL(), token)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := byToken.Session(ctx); err != nil || s.Username != name || s.TokenName != "it-session-made" {
		t.Errorf("the token's session = %+v, %v", s, err)
	}
	if _, err := c.CreateTokenFor(ctx, name, pass, "", "it-password-made"); err != nil {
		t.Errorf("CreateTokenFor = %v", err)
	}
	if _, err := c.CreateTokenAs(ctx, name, "it-admin-made"); err != nil {
		t.Errorf("CreateTokenAs = %v", err)
	}
	once, err := session.SingleUseToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	single, err := technitium.New(c.BaseURL(), once)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := single.Session(ctx); err != nil || s.Username != name {
		t.Errorf("the single use token's first call = %+v, %v", s, err)
	}
	if _, err := single.Session(ctx); !technitium.IsInvalidToken(err) {
		t.Errorf("the single use token's second call = %v, want it refused", err)
	}

	// its sessions: the one signed in and the three tokens; one ended by the account itself, one by the administrator
	one, err = c.User(ctx, name, false)
	if err != nil {
		t.Fatal(err)
	}
	partial := func(tokenName string) string {
		t.Helper()
		for _, s := range one.Sessions {
			if s.TokenName == tokenName {
				return s.PartialToken
			}
		}
		t.Fatalf("the account has no token named %s among %+v", tokenName, one.Sessions)

		return ""
	}
	if len(one.Sessions) != 4 {
		t.Errorf("the account's sessions = %+v, want the one signed in and three tokens", one.Sessions)
	}
	if err := session.EndSession(ctx, partial("it-password-made")); err != nil {
		t.Errorf("EndSession = %v", err)
	}
	if err := c.DeleteSession(ctx, partial("it-admin-made")); err != nil {
		t.Errorf("DeleteSession = %v", err)
	}
	if after, err := c.User(ctx, name, false); err != nil || len(after.Sessions) != 2 {
		t.Errorf("after two were ended the account's sessions = %+v, %v", after.Sessions, err)
	}
	all, err := c.Sessions(ctx)
	if err != nil || !slices.ContainsFunc(all, func(s technitium.OpenSession) bool {
		return s.TokenName == "it-session-made" && s.PartialToken != "" && strings.HasPrefix(token, s.PartialToken)
	}) {
		t.Errorf("Sessions = %+v, %v", all, err)
	}

	// its password, changed by itself under its session
	if err := session.ChangePassword(ctx, "not its password", newPass, "", 0); err == nil {
		t.Error("the password was changed without the one it had")
	}
	if err := session.ChangePassword(ctx, pass, newPass, "", technitium.MinPasswordIterations); err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}
	if _, _, err := c.Login(ctx, name, pass, ""); err == nil {
		t.Error("the old password still signs in")
	}

	// a second factor: begun, switched on with a code made from its secret, asked for at signing in, and taken off
	setup, err := session.InitTwoFactor(ctx)
	if err != nil || setup.Secret == "" || setup.QRCodePNG == "" || setup.Enabled {
		t.Fatalf("InitTwoFactor = %v with a secret of %d characters", err, len(setup.Secret))
	}
	if err := session.EnableTwoFactor(ctx, "000000"); err == nil {
		t.Error("a second factor was switched on with a made-up code")
	}
	if err := session.EnableTwoFactor(ctx, code(t, setup.Secret, time.Now())); err != nil {
		t.Fatalf("EnableTwoFactor = %v", err)
	}
	if _, _, err := c.Login(ctx, name, newPass, ""); err == nil {
		t.Error("the account signed in without its second factor")
	}
	again, who, err := c.Login(ctx, name, newPass, code(t, setup.Secret, time.Now()))
	if err != nil || !who.TOTPEnabled {
		t.Fatalf("signing in with a code = %+v, %v", who, err)
	}
	if err := again.DisableTwoFactor(ctx); err != nil {
		t.Errorf("DisableTwoFactor = %v", err)
	}
	if err := again.Logout(ctx); err != nil {
		t.Errorf("Logout = %v", err)
	}
	if _, err := again.Profile(ctx); !technitium.IsInvalidToken(err) {
		t.Errorf("a session that was ended = %v, want its token refused", err)
	}

	// the administrator's changes: renamed, its password reset, switched off - which ends what it had open - and on
	changed, err := c.SetUser(ctx, name, technitium.UserChange{NewUsername: name + "-renamed", DisplayName: "Renamed", SessionTimeoutSeconds: 1200, NewPassword: pass, MemberOfGroups: []string{"DNS Administrators"}})
	if err != nil || changed.Username != name+"-renamed" || changed.DisplayName != "Renamed" || changed.SessionTimeoutSeconds != 1200 || !slices.Equal(changed.MemberOfGroups, []string{"DNS Administrators"}) {
		t.Fatalf("SetUser = %+v, %v", changed, err)
	}
	t.Cleanup(func() { _ = c.DeleteUser(noCancel(t), name+"-renamed") })
	if _, _, err := c.Login(ctx, name+"-renamed", pass, ""); err != nil {
		t.Errorf("the reset password does not sign in: %v", err)
	}
	// switched off, whoever was signed in as it is signed out; its API tokens are kept, and refused until it is back on
	if changed, err = c.SetUser(ctx, name+"-renamed", technitium.UserChange{Disabled: new(true), MemberOfGroups: []string{}}); err != nil || !changed.Disabled || len(changed.MemberOfGroups) != 0 || len(changed.Sessions) != 1 || changed.Sessions[0].Type != technitium.SessionAPIToken {
		t.Errorf("switched off = %+v, %v", changed, err)
	}
	if _, err := byToken.Session(ctx); err == nil {
		t.Error("a token of an account that was switched off still works")
	}
	if _, _, err := c.Login(ctx, name+"-renamed", pass, ""); err == nil {
		t.Error("an account that was switched off signed in")
	}
	if changed, err = c.SetUser(ctx, name+"-renamed", technitium.UserChange{Disabled: new(false)}); err != nil || changed.Disabled {
		t.Errorf("switched on = %+v, %v", changed, err)
	}
	if s, err := byToken.Session(ctx); err != nil || s.Username != name+"-renamed" {
		t.Errorf("its token once it was back on = %+v, %v", s, err)
	}

	if err := c.DeleteUser(ctx, name+"-renamed"); err != nil {
		t.Errorf("DeleteUser = %v", err)
	}
	if err := c.DeleteUser(ctx, name+"-renamed"); err == nil {
		t.Error("the account was deleted twice")
	}
}
