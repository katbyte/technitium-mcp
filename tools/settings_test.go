package tools

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

const (
	dockSettings = `{"version":"15.6","dnsServerDomain":"dock","dnsServerLocalEndPoints":["0.0.0.0:53"],"defaultRecordTtl":3600,"zoneTransferAllowedNetworks":["10.0.0.0/24"],"notifyAllowedNetworks":[],"dnsServerEnableCheckForUpdate":true,"dnsAppsEnableAutomaticUpdate":true,"dnssecValidation":true,
		"webServiceHttpPort":5380,"webServiceEnableTls":true,"webServiceTlsPort":53443,"webServiceHttpToTlsRedirect":true,"webServiceUseSelfSignedTlsCertificate":true,"webServiceTlsCertificatePassword":"5ecre7-cert",
		"enableDnsOverTls":true,"enableDnsOverQuic":true,"tsigKeys":[{"keyName":"home","sharedSecret":"5ecre7-tsig=","algorithmName":"hmac-sha256"}],
		"recursion":"UseSpecifiedNetworkACL","recursionNetworkACL":["10.0.0.0/8"],"qnameMinimization":true,"serveStale":true,"cacheNegativeRecordTtl":300,
		"enableBlocking":true,"blockingType":"NxDomain","blockListUrls":["https://example.com/list.txt"],"blockListUpdateIntervalHours":24,"blockListNextUpdatedOn":"2026-10-11T03:50:00.123Z",
		"proxy":{"type":"Socks5","address":"10.0.0.9","port":1080,"username":"u","password":"5ecre7-proxy"},"forwarders":["1.1.1.1","9.9.9.9"],"forwarderProtocol":"Tls",
		"loggingType":"File","logQueries":true,"logFolder":"/var/log/technitium/dns"}`
	rpiSettings = `{"version":"15.6","dnsServerDomain":"rpi","dnsServerLocalEndPoints":["0.0.0.0:53"],"defaultRecordTtl":3600,"zoneTransferAllowedNetworks":[],"dnssecValidation":false,
		"webServiceHttpPort":5380,"webServiceEnableTls":false,"recursion":"Allow","qnameMinimization":true,"serveStale":true,"cacheNegativeRecordTtl":300,
		"enableBlocking":false,"blockListUrls":["https://example.com/list.txt"],"forwarders":null,"forwarderProtocol":"Udp","loggingType":"None","logQueries":false}`
)

// server_settings sets the servers' settings side by side, names the ones
// they do not have alike, and gives no secret: a transfer key by its name,
// and no password at all.
func TestServerSettings(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("settings/get", dockSettings)
	p.rpi.Answer("settings/get", rpiSettings)
	p.dock.Answer("apps/list", `{"apps":[{"name":"Query Logs (Sqlite)","version":"8.0","dnsApps":[{"classPath":"QueryLogsSqlite.App","isQueryLogger":true}]},{"name":"Block Page","version":"1.0","dnsApps":[{"classPath":"x","isQueryLogger":false}]}]}`)
	p.rpi.Fail("apps/list", "error", "Access was denied.")
	suite := p.session(t, Options{})

	out := suite.Call(t, "server_settings", nil)
	rows := acctest.Rows(t, out["servers"], "servers")
	if len(rows) != 2 {
		t.Fatalf("servers = %v", rows)
	}
	dock, rpi := rows[0], rows[1]

	for field, want := range map[string]any{
		"recursion": "UseSpecifiedNetworkACL", "forwarder_protocol": "Tls", "proxy": "Socks5 10.0.0.9:1080", "blocking": "NxDomain", "block_lists_every": "24h", "block_lists_next": "2026-10-11T03:50:00Z",
		"console": "http on 5380, https on 53443 with a certificate it signed for itself, http sent on to https", "query_log": "File in /var/log/technitium/dns, queries logged",
		"dnssec_validation": true, "serve_stale": true, "update_check": true,
	} {
		if dock[field] != want {
			t.Errorf("dock's %s = %v, want %v", field, dock[field], want)
		}
	}
	for field, want := range map[string][]string{
		"listens": {"0.0.0.0:53"}, "also": {"DNS-over-QUIC", "DNS-over-TLS"}, "recursion_networks": {"10.0.0.0/8"}, "forwarders": {"1.1.1.1", "9.9.9.9"}, "transfer_networks": {"10.0.0.0/24"},
		"tsig_keys": {"home (hmac-sha256)"}, "block_lists": {"https://example.com/list.txt"}, "apps": {"Query Logs (Sqlite) 8.0 (keeps a searchable log of queries)", "Block Page 1.0"},
	} {
		if got := acctest.Strs(t, dock[field], field); !slices.Equal(got, want) {
			t.Errorf("dock's %s = %v, want %v", field, got, want)
		}
	}
	if acctest.Num(t, dock["default_ttl"], "default_ttl") != 3600 || acctest.Num(t, dock["cache_negative_ttl"], "cache_negative_ttl") != 300 {
		t.Errorf("dock's TTLs = %v and %v", dock["default_ttl"], dock["cache_negative_ttl"])
	}

	// what is off, or not there, is not said; blocking off hides the lists it would use
	if rpi["blocking"] != "off" || rpi["block_lists"] != nil || rpi["forwarders"] != nil || rpi["forwarder_protocol"] != nil || rpi["also"] != nil || rpi["proxy"] != nil || rpi["tsig_keys"] != nil || rpi["console"] != "http on 5380" || rpi["query_log"] != "None" || acctest.BoolOf(rpi["dnssec_validation"]) {
		t.Errorf("rpi = %v", rpi)
	}
	// its apps could not be read, which is said, and its settings are given all the same
	if !strings.Contains(acctest.Str(rpi["note"]), "the installed apps could not be read") || rpi["recursion"] != "Allow" {
		t.Errorf("rpi, whose apps the token may not read = %v", rpi)
	}

	want := []string{"also", "recursion", "forwarders", "dnssec_validation", "transfer_networks", "tsig_keys", "blocking", "block_lists", "console", "query_log", "apps"}
	if got := acctest.Strs(t, out["differ"], "differ"); !slices.Equal(got, want) {
		t.Errorf("differ = %v, want %v", got, want)
	}

	// nothing secret is anywhere in the answer
	printed, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(printed), "5ecre7") {
		t.Errorf("the answer carries a secret: %s", printed)
	}

	// one server alone differs from nobody, and a server that cannot be asked is said
	if alone := suite.Call(t, "server_settings", map[string]any{"server": "rpi"}); alone["differ"] != nil || len(acctest.Rows(t, alone["servers"], "servers")) != 1 {
		t.Errorf("one server alone = %v", alone)
	}
	p.rpi.Fail("settings/get", "error", "Access was denied.")
	failed := acctest.Rows(t, suite.Call(t, "server_settings", nil)["servers"], "servers")
	if !strings.Contains(acctest.Str(failed[1]["error"]), "Access was denied") || failed[0]["recursion"] != "UseSpecifiedNetworkACL" {
		t.Errorf("with one server refusing = %v", failed)
	}
	p.dock.Fail("settings/get", "error", "boom")
	if msg := suite.CallErr(t, "server_settings", nil); !strings.Contains(msg, "dock: settings/get: boom") {
		t.Errorf("with no server answering = %q", msg)
	}
}
