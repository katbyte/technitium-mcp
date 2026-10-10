package technitium_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// A server's settings, cut down from a 15.6 server's own, with the secrets a
// real one carries: a TSIG key's, a certificate's, a proxy's.
const settingsAnswer = `{"version":"15.6","dnsServerDomain":"ns1","dnsServerLocalEndPoints":["0.0.0.0:53","[::]:53"],"defaultRecordTtl":3600,"defaultNsRecordTtl":14400,"defaultSoaRecordTtl":900,
	"zoneTransferAllowedNetworks":["10.0.0.0/24"],"notifyAllowedNetworks":[],"dnsServerEnableCheckForUpdate":true,"dnsAppsEnableAutomaticUpdate":false,"dnssecValidation":true,
	"webServiceHttpPort":5380,"webServiceEnableTls":true,"webServiceTlsPort":53443,"webServiceHttpToTlsRedirect":false,"webServiceUseSelfSignedTlsCertificate":true,"webServiceTlsCertificatePassword":"5ecre7-cert",
	"enableDnsOverTls":true,"enableDnsOverHttps":false,"dnsTlsCertificatePassword":"5ecre7-dns",
	"tsigKeys":[{"keyName":"home","sharedSecret":"5ecre7-tsig=","algorithmName":"hmac-sha256"}],
	"recursion":"UseSpecifiedNetworkACL","recursionNetworkACL":["10.0.0.0/8","!10.9.0.0/16"],"qnameMinimization":true,
	"saveCache":true,"serveStale":true,"cacheMaximumEntries":10000,"cacheMinimumRecordTtl":10,"cacheMaximumRecordTtl":604800,"cacheNegativeRecordTtl":300,
	"enableBlocking":true,"blockingType":"NxDomain","customBlockingAddresses":[],"blockListUrls":["https://example.com/list.txt"],"blockListUpdateIntervalHours":24,"blockListNextUpdatedOn":"2026-10-11T03:50:00Z",
	"proxy":{"type":"Socks5","address":"10.0.0.9","port":1080,"username":"u","password":"5ecre7-proxy","bypass":[]},
	"forwarders":["1.1.1.1","9.9.9.9"],"forwarderProtocol":"Tls",
	"loggingType":"File","logQueries":true,"useLocalTime":false,"logFolder":"/var/log/technitium/dns","maxLogFileDays":365}`

// The settings are read without their secrets: a TSIG key is its name and
// algorithm, and no password is among what the client keeps.
func TestSettings(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("settings/get", settingsAnswer)

	got, err := client(t, fake).Settings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "15.6" || got.Domain != "ns1" || !slices.Equal(got.LocalEndPoints, []string{"0.0.0.0:53", "[::]:53"}) || got.DefaultRecordTTL != 3600 || !got.DNSSECValidation || got.AppsAutoUpdate || !got.CheckForUpdate {
		t.Errorf("Settings = %+v", got)
	}
	if got.Recursion != "UseSpecifiedNetworkACL" || len(got.RecursionNetworkACL) != 2 || !slices.Equal(got.Forwarders, []string{"1.1.1.1", "9.9.9.9"}) || got.ForwarderProtocol != "Tls" || !slices.Equal(got.ZoneTransferAllowedNetworks, []string{"10.0.0.0/24"}) {
		t.Errorf("how it resolves and transfers = %+v", got)
	}
	if !got.EnableBlocking || got.BlockingType != "NxDomain" || len(got.BlockListURLs) != 1 || got.BlockListUpdateIntervalHours != 24 || got.BlockListNextUpdatedOn == "" {
		t.Errorf("its blocking = %+v", got)
	}
	if !got.WebServiceEnableTLS || got.WebServiceTLSPort != 53443 || !got.WebServiceUseSelfSignedCert || !got.EnableDNSOverTLS || got.EnableDNSOverHTTPS || !got.LogQueries || got.LoggingType != "File" || got.CacheNegativeRecordTTL != 300 {
		t.Errorf("its console, protocols, logging and cache = %+v", got)
	}
	if len(got.TSIGKeys) != 1 || got.TSIGKeys[0].Name != "home" || got.TSIGKeys[0].Algorithm != "hmac-sha256" || got.Proxy == nil || got.Proxy.Type != "Socks5" || got.Proxy.Address != "10.0.0.9" || got.Proxy.Port != 1080 {
		t.Errorf("its keys and proxy = %+v, %+v", got.TSIGKeys, got.Proxy)
	}

	printed, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(printed), "5ecre7") {
		t.Errorf("the settings carry a secret: %s", printed)
	}
}

func TestApps(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("apps/list", `{"apps":[
		{"name":"Query Logs (Sqlite)","version":"8.0","dnsApps":[{"classPath":"QueryLogsSqlite.App","isQueryLogger":true}]},
		{"name":"Block Page","version":"1.0","dnsApps":[{"classPath":"BlockPageWebServer.App","isQueryLogger":false}]}
	]}`)

	apps, err := client(t, fake).Apps(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 || apps[0].Name != "Query Logs (Sqlite)" || apps[0].Version != "8.0" || !apps[0].LogsQueries() || apps[1].LogsQueries() {
		t.Errorf("Apps = %+v", apps)
	}
}
