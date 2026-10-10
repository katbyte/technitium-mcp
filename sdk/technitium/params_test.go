package technitium_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// sentAs holds a request against the parameters it must carry, each with
// its value, and no others.
func sentAs(t *testing.T, what string, asked technitiumtest.Request, want map[string]string) {
	t.Helper()

	for param, value := range want {
		if !asked.Params.Has(param) || asked.Params.Get(param) != value {
			t.Errorf("%s: %s = %q, want %q", what, param, asked.Params.Get(param), value)
		}
	}
	if len(asked.Params) != len(want) {
		t.Errorf("%s: sent %d parameters, want %d: %v", what, len(asked.Params), len(want), asked.Params)
	}
}

//go:fix inline

// A zone is made with everything the API takes for its type.
func TestCreateZoneWhole(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/create", `{"domain":"example.com"}`)
	fake.Answer("zones/delete", `{}`)
	fake.Answer("zones/list", `{"pageNumber":2,"totalPages":3,"totalZones":25,"zones":[{"name":"example.com","type":"Primary"}]}`)
	c := client(t, fake)

	if _, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "example.com", Type: technitium.ZonePrimary, Catalog: "catalog.example", SerialByDate: true}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "a primary", fake.Last("zones/create"), map[string]string{"zone": "example.com", "type": "Primary", "catalog": "catalog.example", "useSoaSerialDateScheme": "true"})

	if _, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "example.com", Type: technitium.ZoneSecondary, PrimaryNameServerAddresses: []string{"192.0.2.1", "192.0.2.2"}, TransferProtocol: "Tls", TSIGKeyName: "transfer.example", ValidateZone: true}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "a secondary", fake.Last("zones/create"), map[string]string{"zone": "example.com", "type": "Secondary", "primaryNameServerAddresses": "192.0.2.1,192.0.2.2", "zoneTransferProtocol": "Tls", "tsigKeyName": "transfer.example", "validateZone": "true"})

	if _, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "example.com", Type: technitium.ZoneForwarder, Forwarder: "https://dns.example/dns-query", ForwarderProtocol: "Https", DNSSECValidation: true, Proxy: &technitium.Proxy{Type: "Socks5", Address: "192.0.2.9", Port: 1080, Username: "u", Password: "pr0xy-5ecre7"}}); err != nil {
		t.Fatal(err)
	}
	made := fake.Last("zones/create")
	sentAs(t, "a forwarder", made, map[string]string{"zone": "example.com", "type": "Forwarder", "forwarder": "https://dns.example/dns-query", "protocol": "Https", "dnssecValidation": "true", "proxyType": "Socks5", "proxyAddress": "192.0.2.9", "proxyPort": "1080", "proxyUsername": "u", "proxyPassword": "pr0xy-5ecre7"})
	if made.Method != http.MethodPost {
		t.Errorf("a zone with a proxy's password was made with %s", made.Method)
	}
	if _, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "example.com", Type: technitium.ZoneForwarder, EmptyForwarder: true}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "a forwarder with nothing in it", fake.Last("zones/create"), map[string]string{"zone": "example.com", "type": "Forwarder", "initializeForwarder": "false"})

	// several deleted at once, and the list a page at a time
	if err := c.DeleteZones(t.Context(), []string{"a.example", "b.example"}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "several deleted", fake.Last("zones/delete"), map[string]string{"zones": "a.example,b.example"})
	if err := c.DeleteZones(t.Context(), []string{"a.example", ""}); err == nil || len(fake.Requests("zones/delete")) != 1 {
		t.Errorf("a zone with no name among them = %v", err)
	}
	page, err := c.ZonesPage(t.Context(), technitium.ZoneFilter{Name: "*.com"}, 2, 10)
	if err != nil || page.PageNumber != 2 || page.TotalPages != 3 || page.TotalZones != 25 || len(page.Zones) != 1 {
		t.Errorf("ZonesPage = %+v, %v", page, err)
	}
	sentAs(t, "a page of the zones", fake.Last("zones/list"), map[string]string{"pageNumber": "2", "zonesPerPage": "10", "filterName": "*.com"})
	if _, err := c.ZonesPage(t.Context(), technitium.ZoneFilter{}, 0, 10); err == nil {
		t.Error("page 0 was asked for")
	}
}

// Every option a zone has is set, and a list given empty is cleared with the
// API's word for none.
func TestSetZoneOptionsWhole(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/options/set", `{}`)
	c := client(t, fake)

	if err := c.SetZoneOptions(t.Context(), "example.com", technitium.ZoneChange{QueryAccess: "UseSpecifiedNetworkACL", QueryAccessNetworks: []string{"192.0.2.0/24", "!192.0.2.9"}, ZoneTransferTSIGKeyNames: []string{"transfer.example", "other.example"}, UpdatePolicies: []technitium.UpdatePolicy{{TSIGKeyName: "dhcp.example", Domain: "*.example.com", AllowedTypes: []string{"A", "AAAA"}}, {TSIGKeyName: "acme.example", Domain: "_acme-challenge.example.com", AllowedTypes: []string{"TXT"}}}, NotifySecondaryCatalogsNameServers: []string{"192.0.2.3"}, PrimaryNameServerAddresses: []string{"192.0.2.1"}, PrimaryZoneTransferProtocol: "Quic", PrimaryZoneTransferTSIGKeyName: new("transfer.example"), ValidateZone: new(true), OverrideCatalogQueryAccess: new(true), OverrideCatalogZoneTransfer: new(false), OverrideCatalogNotify: new(true)}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "every option", fake.Last("zones/options/set"), map[string]string{"zone": "example.com", "queryAccess": "UseSpecifiedNetworkACL", "queryAccessNetworkACL": "192.0.2.0/24,!192.0.2.9", "zoneTransferTsigKeyNames": "transfer.example,other.example", "updateSecurityPolicies": "dhcp.example|*.example.com|A,AAAA|acme.example|_acme-challenge.example.com|TXT", "notifySecondaryCatalogsNameServers": "192.0.2.3", "primaryNameServerAddresses": "192.0.2.1", "primaryZoneTransferProtocol": "Quic", "primaryZoneTransferTsigKeyName": "transfer.example", "validateZone": "true", "overrideCatalogQueryAccess": "true", "overrideCatalogZoneTransfer": "false", "overrideCatalogNotify": "true"})

	// cleared: the keys and the policies with false, the key a copy signs with and its primary's address with nothing
	if err := c.SetZoneOptions(t.Context(), "example.com", technitium.ZoneChange{ZoneTransferTSIGKeyNames: []string{}, UpdatePolicies: []technitium.UpdatePolicy{}, PrimaryNameServerAddresses: []string{}, PrimaryZoneTransferTSIGKeyName: new("")}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "cleared", fake.Last("zones/options/set"), map[string]string{"zone": "example.com", "zoneTransferTsigKeyNames": "false", "updateSecurityPolicies": "false", "primaryNameServerAddresses": "", "primaryZoneTransferTsigKeyName": ""})

	sent := len(fake.Requests("zones/options/set"))
	for name, policy := range map[string]technitium.UpdatePolicy{"no key": {Domain: "example.com", AllowedTypes: []string{"A"}}, "no types": {TSIGKeyName: "k", Domain: "example.com"}, "a bar in a name": {TSIGKeyName: "k|j", Domain: "example.com", AllowedTypes: []string{"A"}}} {
		if err := c.SetZoneOptions(t.Context(), "example.com", technitium.ZoneChange{UpdatePolicies: []technitium.UpdatePolicy{policy}}); err == nil || !strings.Contains(err.Error(), "an update policy names a key") {
			t.Errorf("%s = %v", name, err)
		}
	}
	if len(fake.Requests("zones/options/set")) != sent {
		t.Error("a policy that cannot be written as one was sent")
	}
}

// A scope is set with everything it can hand out, the tables with a bar
// between every cell, and a list given empty is cleared.
func TestSetScopeWhole(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("dhcp/scopes/set", `{}`)
	fake.Answer("dhcp/scopes/get", `{"name":"LAN","startingAddress":"192.0.2.100","endingAddress":"192.0.2.199","subnetMask":"255.255.255.0","leaseTimeDays":1,"offerDelayTime":250,"pingCheckEnabled":true,"pingCheckTimeout":1000,"pingCheckRetries":2,"domainName":"lan.example","domainSearchList":["lan.example","example.com"],"dnsUpdates":true,"dnsOverwriteForDynamicLease":true,"dnsTtl":600,"serverAddress":"192.0.2.5","serverHostName":"tftp","bootFileName":"boot.bin","routerAddress":"192.0.2.1","useThisDnsServer":true,"dnsServers":[],"winsServers":["192.0.2.6"],"ntpServers":["192.0.2.7"],"ntpServerDomainNames":["pool.ntp.org"],"staticRoutes":[{"destination":"198.51.100.0","subnetMask":"255.255.255.0","router":"192.0.2.2"}],"vendorInfo":[{"identifier":"PXEClient","information":"06:01:03"}],"capwapAcIpAddresses":["192.0.2.8"],"tftpServerAddresses":["192.0.2.5"],"genericOptions":[{"code":150,"value":"C0:00:02:05"}],"exclusions":[],"reservedLeases":[],"allowOnlyReservedLeases":false,"blockLocallyAdministeredMacAddresses":true,"ignoreClientIdentifierOption":true}`)
	c := client(t, fake)

	lan := technitium.NewScope{Name: "LAN", StartingAddress: "192.0.2.100", EndingAddress: "192.0.2.199", SubnetMask: "255.255.255.0"}
	whole := lan
	whole.NewName = "Office"
	whole.OfferDelayTime, whole.PingCheckTimeout, whole.PingCheckRetries, whole.DNSTTL = new(250), new(1000), new(2), new(600)
	whole.PingCheckEnabled, whole.DNSOverwriteForDynamicLease, whole.BlockLocallyAdministeredMACAddresses, whole.IgnoreClientIdentifierOption = new(true), new(true), new(true), new(false)
	whole.ServerAddress, whole.ServerHostName, whole.BootFileName = new("192.0.2.5"), new("tftp"), new("boot.bin")
	whole.DomainSearchList, whole.WINSServers, whole.NTPServers, whole.NTPServerDomainNames, whole.CAPWAPAddresses, whole.TFTPServerAddresses = []string{"lan.example", "example.com"}, []string{"192.0.2.6"}, []string{"192.0.2.7"}, []string{"pool.ntp.org"}, []string{"192.0.2.8"}, []string{"192.0.2.5"}
	whole.StaticRoutes = []technitium.StaticRoute{{Destination: "198.51.100.0", SubnetMask: "255.255.255.0", Router: "192.0.2.2"}}
	whole.VendorInfo = []technitium.VendorInfo{{Identifier: "PXEClient", Information: "06:01:03"}}
	whole.GenericOptions = []technitium.GenericOption{{Code: 150, Value: "C0:00:02:05"}}
	whole.ReservedLeases = []technitium.Reservation{{HostName: "nas", HardwareAddress: "AA-00-00-00-00-01", Address: "192.0.2.30", Comments: "the nas"}, {HardwareAddress: "AA-00-00-00-00-02", Address: "192.0.2.31"}}
	if err := c.SetScope(t.Context(), &whole); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "a scope whole", fake.Last("dhcp/scopes/set"), map[string]string{"name": "LAN", "startingAddress": "192.0.2.100", "endingAddress": "192.0.2.199", "subnetMask": "255.255.255.0", "newName": "Office", "offerDelayTime": "250", "pingCheckEnabled": "true", "pingCheckTimeout": "1000", "pingCheckRetries": "2", "dnsTtl": "600", "dnsOverwriteForDynamicLease": "true", "blockLocallyAdministeredMacAddresses": "true", "ignoreClientIdentifierOption": "false", "serverAddress": "192.0.2.5", "serverHostName": "tftp", "bootFileName": "boot.bin", "domainSearchList": "lan.example,example.com", "winsServers": "192.0.2.6", "ntpServers": "192.0.2.7", "ntpServerDomainNames": "pool.ntp.org", "capwapAcIpAddresses": "192.0.2.8", "tftpServerAddresses": "192.0.2.5", "staticRoutes": "198.51.100.0|255.255.255.0|192.0.2.2", "vendorInfo": "PXEClient|06:01:03", "genericOptions": "150|C0:00:02:05", "reservedLeases": "nas|AA-00-00-00-00-01|192.0.2.30|the nas||AA-00-00-00-00-02|192.0.2.31|"})

	// cleared: a list or a table given empty is sent as nothing, and one not given is not sent
	cleared := lan
	cleared.NTPServers, cleared.StaticRoutes, cleared.BootFileName = []string{}, []technitium.StaticRoute{}, new("")
	if err := c.SetScope(t.Context(), &cleared); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "cleared", fake.Last("dhcp/scopes/set"), map[string]string{"name": "LAN", "startingAddress": "192.0.2.100", "endingAddress": "192.0.2.199", "subnetMask": "255.255.255.0", "ntpServers": "", "staticRoutes": "", "bootFileName": ""})
	barred := lan
	barred.VendorInfo = []technitium.VendorInfo{{Identifier: "a|b", Information: "01"}}
	if err := c.SetScope(t.Context(), &barred); err == nil || !strings.Contains(err.Error(), "a bar between its cells") || len(fake.Requests("dhcp/scopes/set")) != 2 {
		t.Errorf("a bar in a cell = %v", err)
	}

	// and all of it is read back
	got, err := c.Scope(t.Context(), "LAN")
	if err != nil {
		t.Fatal(err)
	}
	if got.OfferDelayTime != 250 || !got.PingCheckEnabled || got.PingCheckTimeout != 1000 || got.PingCheckRetries != 2 || len(got.DomainSearchList) != 2 || !got.DNSOverwriteForDynamicLease || got.ServerAddress != "192.0.2.5" || got.ServerHostName != "tftp" || got.BootFileName != "boot.bin" || got.WINSServers[0] != "192.0.2.6" || got.NTPServers[0] != "192.0.2.7" || got.NTPServerDomainNames[0] != "pool.ntp.org" || got.StaticRoutes[0].Router != "192.0.2.2" || got.VendorInfo[0].Information != "06:01:03" || got.CAPWAPAddresses[0] != "192.0.2.8" || got.TFTPServerAddresses[0] != "192.0.2.5" || got.GenericOptions[0].Code != 150 || !got.BlockLocallyAdministeredMACAddresses || !got.IgnoreClientIdentifierOption {
		t.Errorf("the scope read back = %+v", got)
	}
}

// The smaller things a call takes beside what it is mostly asked for.
func TestTheRestOfWhatCallsTake(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	for _, path := range []string{"dhcp/leases/remove", "dhcp/leases/convertToReserved", "dhcp/leases/convertToDynamic", "zones/records/delete"} {
		fake.Answer(path, `{}`)
	}
	fake.Answer("blocked/list", `{"domain":"example.com","zones":["ads"],"records":[]}`)
	fake.Answer("admin/cluster/primary/setOptions", `{"clusterInitialized":true}`)
	fake.Answer("allowed/list", `{"domain":"example.com","zones":[],"records":[]}`)
	fake.Answer("cache/list", `{"domain":"example.com","zones":["www"],"records":[]}`)
	fake.Answer("dnsClient/resolve", chainAnswer)
	fake.Answer("dashboard/stats/get", `{"stats":{"totalQueries":1}}`)
	fake.Answer("dashboard/stats/getTop", `{"topClients":[]}`)
	fake.Answer("logs/query", `{"pageNumber":1,"totalPages":1,"totalEntries":0,"entries":[]}`)
	fake.AnswerText("logs/export", "RowNumber\n")
	fake.AnswerWhole("user/createToken", `{"username":"kt","tokenName":"t","token":"`+strings.Repeat("ab", 32)+`","status":"ok"}`)
	c := client(t, fake)

	// a lease by the identifier its machine sent
	for path, call := range map[string]func() error{
		"dhcp/leases/remove":            func() error { return c.RemoveLeaseOfClient(t.Context(), "LAN", "01-AA-00-00-00-00-01") },
		"dhcp/leases/convertToReserved": func() error { return c.ReserveLeaseOfClient(t.Context(), "LAN", "01-AA-00-00-00-00-01") },
		"dhcp/leases/convertToDynamic":  func() error { return c.UnreserveLeaseOfClient(t.Context(), "LAN", "01-AA-00-00-00-00-01") },
	} {
		if err := call(); err != nil {
			t.Fatal(err)
		}
		sentAs(t, path, fake.Last(path), map[string]string{"name": "LAN", "clientIdentifier": "01-AA-00-00-00-00-01"})
	}
	if err := c.RemoveLeaseOfClient(t.Context(), "LAN", ""); err == nil || c.ReserveLeaseOfClient(t.Context(), "", "x") == nil || c.UnreserveLeaseOfClient(t.Context(), "LAN", "") == nil {
		t.Error("a lease with nothing to name it was asked for")
	}

	// a list walked upward
	if up, err := c.BlockedAbove(t.Context(), "x.example.com"); err != nil || up.Domain != "example.com" {
		t.Errorf("BlockedAbove = %+v, %v", up, err)
	}
	sentAs(t, "blocked, upward", fake.Last("blocked/list"), map[string]string{"domain": "x.example.com", "direction": "up"})
	if _, err := c.AllowedAbove(t.Context(), "x.example.com"); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "allowed, upward", fake.Last("allowed/list"), map[string]string{"domain": "x.example.com", "direction": "up"})
	if _, err := c.AllowedUnder(t.Context(), "example.com"); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "allowed, under a name", fake.Last("allowed/list"), map[string]string{"domain": "example.com"})
	if _, err := c.CacheAbove(t.Context(), "x.example.com"); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "the cache, upward", fake.Last("cache/list"), map[string]string{"domain": "x.example.com", "direction": "up"})

	// a question asked as if from a network, and an answer taken into a zone: the second changes the server, and is a POST
	if _, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "example.com", ClientSubnet: "203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "asked as if from a network", fake.Last("dnsClient/resolve"), map[string]string{"domain": "example.com", "server": "this-server", "type": "A", "eDnsClientSubnet": "203.0.113.0/24"})
	if _, err := c.ImportResolved(t.Context(), technitium.ResolveQuery{Name: "example.com", Type: "MX", Via: "192.0.2.53", Protocol: "Tcp", DNSSEC: true}); err != nil {
		t.Fatal(err)
	}
	imported := fake.Last("dnsClient/resolve")
	sentAs(t, "an answer taken into a zone", imported, map[string]string{"domain": "example.com", "server": "192.0.2.53", "type": "MX", "protocol": "Tcp", "dnssec": "true", "import": "true"})
	if imported.Method != http.MethodPost {
		t.Errorf("an answer was taken into a zone with %s", imported.Method)
	}
	if _, err := c.ImportResolved(t.Context(), technitium.ResolveQuery{Name: "example.com"}); err != nil || fake.Last("dnsClient/resolve").Params.Get("server") != "recursive-resolver" {
		t.Errorf("with no server named it asks %q, %v", fake.Last("dnsClient/resolve").Params.Get("server"), err)
	}
	if _, err := c.ImportResolved(t.Context(), technitium.ResolveQuery{}); err == nil {
		t.Error("an answer to no question was imported")
	}

	// the statistics' own options, and a window of one's own for a list
	if _, err := c.Stats(t.Context(), technitium.StatsWindow{Type: "LastDay", EveryQueryType: true}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "every query type", fake.Last("dashboard/stats/get"), map[string]string{"type": "LastDay", "utc": "true", "dontTrimQueryTypeData": "true"})
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := c.TopStats(t.Context(), technitium.StatsWindow{Start: start, End: start.Add(24 * time.Hour), NoReverseLookup: true, OnlyRateLimited: true}, technitium.TopClients, 5); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "the clients held back", fake.Last("dashboard/stats/getTop"), map[string]string{"type": "Custom", "start": "2026-10-01T00:00:00Z", "end": "2026-10-02T00:00:00Z", "statsType": "TopClients", "limit": "5", "noReverseLookup": "true", "onlyRateLimitedClients": "true"})

	// a log searched by the class asked in, and exported with every filter a search takes
	q := technitium.LogQuery{App: "Query Logs (Sqlite)", ClassPath: "QueryLogsSqlite.App", Class: "CH"}
	if _, err := c.QueryLog(t.Context(), q); err != nil {
		t.Fatal(err)
	}
	if fake.Last("logs/query").Params.Get("qclass") != "CH" {
		t.Errorf("the class was sent as %q", fake.Last("logs/query").Params.Get("qclass"))
	}
	q.Name, q.Client, q.Type, q.RCode, q.ResponseType, q.Protocol, q.Start, q.End = "*.example.com", "192.0.2.7", "A", "NxDomain", "Authoritative", "Udp", start, start.Add(time.Hour)
	if _, err := c.ExportQueryLog(t.Context(), q); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "an export with every filter", fake.Last("logs/export"), map[string]string{"name": "Query Logs (Sqlite)", "classPath": "QueryLogsSqlite.App", "qclass": "CH", "qname": "*.example.com", "clientIpAddress": "192.0.2.7", "qtype": "A", "rcode": "NxDomain", "responseType": "Authoritative", "protocol": "Udp", "start": "2026-10-01T00:00:00Z", "end": "2026-10-01T01:00:00Z"})
	if _, err := c.SetClusterOptions(t.Context(), technitium.ClusterOptions{HeartbeatRefreshIntervalSeconds: 30, HeartbeatRetryIntervalSeconds: 10, ConfigRefreshIntervalSeconds: 900, ConfigRetryIntervalSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "a cluster's four times", fake.Last("admin/cluster/primary/setOptions"), map[string]string{"heartbeatRefreshIntervalSeconds": "30", "heartbeatRetryIntervalSeconds": "10", "configRefreshIntervalSeconds": "900", "configRetryIntervalSeconds": "60"})

	// a token made by name and password with a second factor's code, an address deleted with the hints that follow it, and a cluster's four times
	if _, err := c.CreateTokenFor(t.Context(), "kt", "5ecre7", "123456", "t"); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "a token with a code", fake.Last("user/createToken"), map[string]string{"user": "kt", "pass": "5ecre7", "totp": "123456", "tokenName": "t"})
	address := &technitium.Record{Name: "x.example.com", Type: "A", Data: technitium.RData{"ipAddress": "192.0.2.4"}}
	if err := c.DeleteAddress(t.Context(), "example.com", address); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "an address deleted with its hints", fake.Last("zones/records/delete"), map[string]string{"zone": "example.com", "domain": "x.example.com", "type": "A", "ipAddress": "192.0.2.4", "updateSvcbHints": "true"})
	if err := c.DeleteAddress(t.Context(), "example.com", &technitium.Record{Name: "x.example.com", Type: "TXT", Data: technitium.RData{"text": "x"}}); err == nil || len(fake.Requests("zones/records/delete")) != 1 {
		t.Errorf("a TXT record deleted as an address = %v", err)
	}
	// a TXT record known only by its text is named by it, with how it was split
	if err := c.DeleteRecord(t.Context(), "", &technitium.Record{Name: "x.example.com", Type: "TXT", Data: technitium.RData{"text": "one\ntwo", "splitText": true}}); err != nil {
		t.Fatal(err)
	}
	sentAs(t, "a TXT record by its text", fake.Last("zones/records/delete"), map[string]string{"domain": "x.example.com", "type": "TXT", "text": "one\ntwo", "splitText": "true"})
}

// Every setting the server has can be set by its name, and every part of a
// server restored from a backup.
func TestEverySettingAndEveryPart(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("settings/restore", `{"version":"15.6"}`)
	c := client(t, fake)

	all := map[string]string{}
	for _, name := range technitium.SettingNames {
		all[name] = "x"
	}

	// the server answers with every setting it has: one sent that it does not answer with is one it does not have
	answer, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	fake.Answer("settings/set", string(answer))

	if _, err := c.SetSettings(t.Context(), all); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("settings/set"); len(asked.Params) != len(technitium.SettingNames) || asked.Method != http.MethodPost {
		t.Errorf("%d settings were sent with %s, want all %d", len(asked.Params), asked.Method, len(technitium.SettingNames))
	}
	if _, err := c.Restore(t.Context(), technitium.Everything(), true, []byte("PK\x03\x04 a backup")); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("settings/restore"); len(asked.Params) != 14 || asked.Params.Get("authConfig") != "true" || asked.Params.Get("deleteExistingFiles") != "true" {
		t.Errorf("everything was restored with %v", asked.Params)
	}
}
