package tools

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	mcpregistry "github.com/katbyte/go-kt/mcp/registry"
)

// loggedSession is a session over a pair whose write line goes to a builder,
// so a test can read what the line said of a call.
func loggedSession(t *testing.T, p *pair, mu *sync.Mutex, logged *strings.Builder) *acctest.Suite {
	t.Helper()

	r := &registry{servers: p.set, opts: Options{EnableWrite: true, EnableDelete: true, Toolsets: []string{mcpregistry.All}}, writeLog: func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = fmt.Fprintf(logged, format+"\n", args...)
	}}
	queueTools(r)

	return hostRegistry(t, r)
}

// One line is written for every write, with what it was sent; and no secret a
// tool is sent reaches it: a password, a one-time code, an app's configuration
// or its record's data, a proxy's password among a record's options or among
// the settings, the transfer keys of a call that is refused - while the
// settings that are no secret are written as sent.
func TestTheWriteLineShowsNoSecret(t *testing.T) {
	t.Parallel()

	var (
		mu     sync.Mutex
		logged strings.Builder
	)
	said := func() string {
		mu.Lock()
		defer mu.Unlock()

		return logged.String()
	}

	// an account that can be signed in as, as the test of account_edit has it
	session := strings.Repeat("5e55", 16)
	signedIn := accountsPair(t)
	signedIn.dock.Accept(session)
	signedIn.both("user/profile/get", account("kt", `,"isSsoUser":false`))
	signedIn.dock.AnswerWhole("user/login", `{"username":"kt","displayName":"kt","totpEnabled":false,"token":"`+session+`","status":"ok"}`)
	for _, call := range []string{"user/logout", "user/changePassword", "user/2fa/enable"} {
		signedIn.dock.AnswerWhole(call, `{"status":"ok"}`)
	}
	accounts := loggedSession(t, signedIn, &mu, &logged)
	accounts.Call(t, "account_edit", map[string]any{"server": "dock", "username": "kt", "password": "5ecre7-pass", "totp": "111111", "two_factor": "enable", "two_factor_code": "123456", "new_password": "5ecre7-new"})
	accounts.Call(t, "user_set", map[string]any{"server": "dock", "username": "kt", "new_password": "5ecre7-reset", "display_name": "Kate"})

	settings := loggedSession(t, settingsPair(t), &mu, &logged)
	settings.Call(t, "settings_set", map[string]any{"server": "dock", "settings": map[string]string{"cacheMaximumRecordTtl": "40000", "proxyPassword": "pr0xy-5ecre7"}, "dry_run": true})
	// a call that is refused is written too: the transfer keys, which settings_set will not take, carry their secrets
	if msg := settings.CallErr(t, "settings_set", map[string]any{"server": "dock", "settings": map[string]string{"tsigKeys": "home|k3y-5ecre7|hmac-sha256"}}); !strings.Contains(msg, "tsig_key_set adds or changes one") {
		t.Errorf("the transfer keys set whole = %q", msg)
	}

	p := appsPair(t)
	p.dock.Answer("apps/config/get", `{"config":"{\"enable\": true}"}`)
	apps := loggedSession(t, p, &mu, &logged)
	apps.Call(t, "app_config_set", map[string]any{"server": "dock", "name": "Split Horizon", "config": `{"enable":false,"key":"c0nf1g-5ecre7"}`, "dry_run": true})

	records := loggedSession(t, writePair(t), &mu, &logged)
	records.Call(t, "record_set", map[string]any{"server": "dock", "name": "fwd.example.com", "type": "FWD", "value": "Udp 10.0.0.53", "options": map[string]string{"forwarderPriority": "9", "proxyPassword": "pr0xy-5ecre7"}, "dry_run": true})
	// the data an app's record carries is the app's own, as its configuration is
	records.Call(t, "record_set", map[string]any{"server": "dock", "name": "app.example.com", "type": "APP", "value": "Split Horizon SplitHorizon.SimpleAddress", "options": map[string]string{"recordData": `{"key":"r3c0rd-5ecre7"}`}, "dry_run": true})

	log := said()
	for _, tool := range []string{"write account_edit", "write user_set", "write settings_set", "write app_config_set", "write record_set"} {
		if !strings.Contains(log, tool) {
			t.Errorf("no line for %s in:\n%s", tool, log)
		}
	}
	for _, secret := range []string{"5ecre7", "111111", "123456", "c0nf1g", `"enable":false`, "k3y-", "r3c0rd"} {
		if strings.Contains(log, secret) {
			t.Errorf("the write line shows %q:\n%s", secret, log)
		}
	}
	// the settings that are no secret are written as sent, and the names of what was blanked are still there
	for _, shown := range []string{"cacheMaximumRecordTtl", "40000", "proxyPassword", "forwarderPriority", "kt", "Split Horizon"} {
		if !strings.Contains(log, shown) {
			t.Errorf("the write line leaves out %q:\n%s", shown, log)
		}
	}
}
