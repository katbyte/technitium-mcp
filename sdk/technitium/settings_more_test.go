package technitium_test

import (
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/apidoc"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// allSettings is the settings as a server answers them, with what is secret
// in them: a certificate's password, a proxy's, and a key's shared secret.
const allSettings = `{"version":"15.6","dnsServerDomain":"ns1.example","defaultRecordTtl":3600,"recursion":"AllowOnlyForPrivateNetworks","forwarders":["192.0.2.53"],"webServiceTlsCertificatePassword":"5ecre7-cert","dnsTlsCertificatePassword":"5ecre7-dns","proxy":{"type":"Socks5","address":"192.0.2.9","port":1080,"username":"u","password":"5ecre7-proxy"},"tsigKeys":[{"keyName":"home","sharedSecret":"5ecre7-tsig=","algorithmName":"hmac-sha256"}],"enableBlocking":true}`

// object is a value that must be a JSON object, and list one that must be a
// JSON array: what the settings give as any.
func object(t *testing.T, value any) map[string]any {
	t.Helper()

	out, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%v is no object", value)
	}

	return out
}

func list(t *testing.T, value any) []any {
	t.Helper()

	out, ok := value.([]any)
	if !ok {
		t.Fatalf("%v is no list", value)
	}

	return out
}

// Every setting is read and set by the API's own name for it, and nothing
// that is read back holds a password or a key.
func TestAllSettings(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("settings/get", allSettings)
	fake.Answer("settings/set", allSettings)
	fake.Answer("settings/getTsigKeyNames", `{"tsigKeyNames":["key1","key2"]}`)
	c := client(t, fake)

	got, err := c.AllSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got["dnsServerDomain"] != "ns1.example" || got["defaultRecordTtl"] != float64(3600) || got["enableBlocking"] != any(true) {
		t.Errorf("AllSettings = %v", got)
	}
	proxy, keys := object(t, got["proxy"]), list(t, got["tsigKeys"])
	if len(keys) != 1 {
		t.Fatalf("the keys = %v", keys)
	}
	key := object(t, keys[0])
	if proxy["address"] != "192.0.2.9" || proxy["username"] != "u" || key["keyName"] != "home" || key["algorithmName"] != "hmac-sha256" {
		t.Errorf("what is no secret was not read: proxy %v, keys %v", proxy, keys)
	}
	for _, secret := range []string{"webServiceTlsCertificatePassword", "dnsTlsCertificatePassword"} {
		if _, there := got[secret]; there {
			t.Errorf("%s was read", secret)
		}
	}
	if _, there := proxy["password"]; there {
		t.Error("the proxy's password was read")
	}
	if _, there := key["sharedSecret"]; there {
		t.Error("a key's shared secret was read")
	}

	after, err := c.SetSettings(t.Context(), map[string]string{"recursion": "Deny", "forwarders": "192.0.2.53,192.0.2.54", "tsigKeys": "home|c2VjcmV0|hmac-sha256", "proxyPassword": "p"})
	if err != nil {
		t.Fatal(err)
	}
	asked := fake.Last("settings/set")
	if asked.Method != http.MethodPost || len(asked.Params) != 4 || asked.Params.Get("recursion") != "Deny" || asked.Params.Get("forwarders") != "192.0.2.53,192.0.2.54" || asked.Params.Get("tsigKeys") != "home|c2VjcmV0|hmac-sha256" || asked.Params.Get("proxyPassword") != "p" {
		t.Errorf("the settings were set with %s %v", asked.Method, asked.Params)
	}
	if _, there := after["webServiceTlsCertificatePassword"]; there || after["dnsServerDomain"] != "ns1.example" {
		t.Errorf("the settings as they now stand = %v", after)
	}

	// a setting the API does not know is refused here: the server would pass it over in silence
	if _, err := c.SetSettings(t.Context(), map[string]string{"recursionn": "Deny"}); err == nil || !strings.Contains(err.Error(), `no setting named "recursionn"`) {
		t.Errorf("a setting that is not one = %v", err)
	}
	if _, err := c.SetSettings(t.Context(), nil); err == nil || len(fake.Requests("settings/set")) != 1 {
		t.Errorf("nothing was set = %v", err)
	}

	// a setting a later version brought, an older server passes over and says ok: an error here, with the settings as they stand. What it takes and never gives back is not held against it
	fake.Answer("settings/set", `{"version":"15.5","recursion":"Deny"}`)
	after, err = c.SetSettings(t.Context(), map[string]string{"recursion": "Deny", "enableCachePrefetch": "true", "proxyPassword": "p"})
	if err == nil || !strings.Contains(err.Error(), "the server (version 15.5) said ok and has no setting named enableCachePrefetch: a later version") || after["recursion"] != "Deny" {
		t.Errorf("a setting the server's version does not have = %v, %v", after, err)
	}

	names, err := c.TSIGKeyNames(t.Context())
	if err != nil || len(names) != 2 || names[0] != "key1" {
		t.Errorf("TSIGKeyNames = %v, %v", names, err)
	}
}

// The settings the client knows by name are the ones the API document gives
// the call that sets them: no more, and none missing.
func TestSettingNamesAreTheDocuments(t *testing.T) {
	t.Parallel()

	doc, err := apidoc.Vendored()
	if err != nil {
		t.Fatal(err)
	}
	call := doc.Call("settings/set")
	if call == nil {
		t.Fatal("the document has no settings/set")
	}
	seen := map[string]bool{}
	for _, name := range technitium.SettingNames {
		if seen[name] {
			t.Errorf("SettingNames has %s twice", name)
		}
		seen[name] = true
		if !call.Takes(name) {
			t.Errorf("SettingNames has %s, which the document does not give settings/set", name)
		}
	}
	// four settings of older servers are still in the document's example
	// address and nowhere in its list: recursion and blockingType replaced
	// three of them and ipv6Mode the fourth, so they are not offered
	gone := []string{"allowRecursion", "allowRecursionOnlyForPrivateNetworks", "preferIPv6", "useNxDomainForBlocking"}
	for _, param := range call.Params {
		if slices.Contains(gone, param) {
			if seen[param] {
				t.Errorf("SettingNames has %s, which the document only has in an old example", param)
			}

			continue
		}
		if param != "token" && param != "node" && !seen[param] {
			t.Errorf("the document gives settings/set the parameter %s, which SettingNames does not have", param)
		}
	}
}

// A backup is the parts asked for as one zip file, and a restore sends one
// back as a file with the parts to take from it in the address.
func TestBackupAndRestore(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.AnswerText("settings/backup", "PK\x03\x04 a backup")
	fake.Answer("settings/restore", allSettings)
	c := client(t, fake)

	zip, err := c.Backup(t.Context(), technitium.BackupItems{Zones: true, DNSSettings: true, Scopes: true})
	if err != nil || !strings.HasPrefix(string(zip), "PK") {
		t.Fatalf("Backup = %q, %v", zip, err)
	}
	if asked := fake.Last("settings/backup"); asked.Method != http.MethodGet || len(asked.Params) != 3 || asked.Params.Get("zones") != "true" || asked.Params.Get("dnsSettings") != "true" || asked.Params.Get("scopes") != "true" {
		t.Errorf("the backup was asked for with %v", asked.Params)
	}
	if _, err := c.Backup(t.Context(), technitium.Everything()); err != nil || len(fake.Last("settings/backup").Params) != 13 {
		t.Errorf("everything was asked for with %v, %v", fake.Last("settings/backup").Params, err)
	}

	got, err := c.Restore(t.Context(), technitium.BackupItems{Zones: true, AllowedZones: true}, true, zip)
	if err != nil || got.Domain != "ns1.example" {
		t.Fatalf("Restore = %+v, %v", got, err)
	}
	if asked := fake.Last("settings/restore"); asked.Method != http.MethodPost || !bytes.Equal(asked.File, zip) || len(asked.Params) != 3 || asked.Params.Get("zones") != "true" || asked.Params.Get("allowedZones") != "true" || asked.Params.Get("deleteExistingFiles") != "true" {
		t.Errorf("the backup was restored from %q with %v", asked.File, asked.Params)
	}
	if _, err := c.Restore(t.Context(), technitium.BackupItems{Zones: true}, false, zip); err != nil || fake.Last("settings/restore").Params.Has("deleteExistingFiles") {
		t.Errorf("the zones alone were restored with %v, %v", fake.Last("settings/restore").Params, err)
	}

	if _, err := c.Backup(t.Context(), technitium.BackupItems{}); err == nil {
		t.Error("a backup of nothing was asked for")
	}
	if _, err := c.Restore(t.Context(), technitium.BackupItems{}, false, zip); err == nil {
		t.Error("nothing was restored")
	}
	if _, err := c.Restore(t.Context(), technitium.BackupItems{Zones: true}, false, nil); err == nil {
		t.Error("an empty backup was restored")
	}
	if _, err := c.Restore(t.Context(), technitium.BackupItems{Zones: true}, false, []byte("not a zip file")); err == nil {
		t.Error("what is no zip file was restored")
	}
	if len(fake.Requests("settings/backup")) != 2 || len(fake.Requests("settings/restore")) != 2 {
		t.Error("a refused call reached the server")
	}
}

// A transfer key is added, changed and taken away by sending the whole list
// of keys back, the others as they were with their secrets: the settings
// take the keys as one.
func TestTSIGKeys(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("settings/get", `{"version":"15.6","tsigKeys":[{"keyName":"cluster-catalog.example","sharedSecret":"Y2x1c3Rlcg==","algorithmName":"hmac-sha256"},{"keyName":"old.example","sharedSecret":"b2xk","algorithmName":"hmac-sha512"}]}`)
	fake.Answer("settings/set", `{"version":"15.6"}`)
	c := client(t, fake)

	// a new key goes on the end of the ones there are
	if err := c.SetTSIGKey(t.Context(), "new.example", "bmV3", ""); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("settings/set"); asked.Method != http.MethodPost || len(asked.Params) != 1 || asked.Params.Get("tsigKeys") != "cluster-catalog.example|Y2x1c3Rlcg==|hmac-sha256|old.example|b2xk|hmac-sha512|new.example|bmV3|hmac-sha256" {
		t.Errorf("a key was added with %v", asked.Params)
	}
	// one that is there is changed where it stands, whatever case its name is given in
	if err := c.SetTSIGKey(t.Context(), "OLD.example", "Y2hhbmdlZA==", "hmac-sha256"); err != nil || fake.Last("settings/set").Params.Get("tsigKeys") != "cluster-catalog.example|Y2x1c3Rlcg==|hmac-sha256|old.example|Y2hhbmdlZA==|hmac-sha256" {
		t.Errorf("a key was changed with %v, %v", fake.Last("settings/set").Params, err)
	}
	if err := c.DeleteTSIGKey(t.Context(), "old.example"); err != nil || fake.Last("settings/set").Params.Get("tsigKeys") != "cluster-catalog.example|Y2x1c3Rlcg==|hmac-sha256" {
		t.Errorf("a key was taken away with %v, %v", fake.Last("settings/set").Params, err)
	}
	// a key that is not there is not taken away, and nothing is sent
	sent := len(fake.Requests("settings/set"))
	if err := c.DeleteTSIGKey(t.Context(), "nothing.example"); err != nil || len(fake.Requests("settings/set")) != sent {
		t.Errorf("a key that is not there, taken away = %v with %d calls", err, len(fake.Requests("settings/set"))-sent)
	}

	// the last key gone, the server is told there are none in its own word for it
	fake.Answer("settings/get", `{"version":"15.6","tsigKeys":[{"keyName":"only.example","sharedSecret":"b25seQ==","algorithmName":"hmac-sha256"}]}`)
	if err := c.DeleteTSIGKey(t.Context(), "only.example"); err != nil || fake.Last("settings/set").Params.Get("tsigKeys") != "false" {
		t.Errorf("the last key was taken away with %v, %v", fake.Last("settings/set").Params, err)
	}

	sent = len(fake.Requests("settings/set")) + len(fake.Requests("settings/get"))
	for what, err := range map[string]error{"a key with no name": c.SetTSIGKey(t.Context(), "", "bmV3", ""), "a key with a bar in its name": c.SetTSIGKey(t.Context(), "a|b", "bmV3", ""), "no key taken away": c.DeleteTSIGKey(t.Context(), "")} {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	if now := len(fake.Requests("settings/set")) + len(fake.Requests("settings/get")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}
