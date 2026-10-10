package tools

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

// rec is a record as a canned server gives one.
func rec(name, recordType, data string, more ...string) string {
	return `{"name":"` + name + `","type":"` + recordType + `","ttl":3600,"rData":` + data + strings.Join(append([]string{""}, more...), ",") + `}`
}

func addr(name, address string, more ...string) string {
	return rec(name, "A", `{"ipAddress":"`+address+`"}`, more...)
}

func cname(name, target string) string {
	return rec(name, "CNAME", `{"cname":"`+target+`"}`)
}

func ptr(name, target string) string {
	return rec(name, "PTR", `{"ptrName":"`+target+`"}`)
}

// zoneOf makes a server answer with these records for a zone read whole.
func zoneOf(p *pair, onRPI bool, zone string, records ...string) {
	server := p.dock
	if onRPI {
		server = p.rpi
	}
	server.AnswerWhen("zones/records/get", "domain", zone, `{"zone":{"name":"`+zone+`"},"records":[`+strings.Join(records, ",")+`]}`)
}

// auditPair is two servers holding one of everything an audit looks for.
func auditPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[
		{"name":"example.com","type":"Primary","soaSerial":7},
		{"name":"van.example.com","type":"Primary","soaSerial":3,"dnssecStatus":"SignedWithNSEC"},
		{"name":"apex.example","type":"Primary","soaSerial":1},
		{"name":"0.0.10.in-addr.arpa","type":"Primary","soaSerial":2},
		{"name":"off.example","type":"Primary","soaSerial":1,"disabled":true},
		{"name":"lan.example","type":"Primary","soaSerial":4},
		{"name":"copy.example","type":"Secondary","soaSerial":5,"syncFailed":true,"isExpired":true},
		{"name":"cluster-catalog.example","type":"Catalog","soaSerial":1}
	]}`)
	p.rpi.Answer("zones/list", `{"zones":[
		{"name":"example.com","type":"Primary","soaSerial":9},
		{"name":"copy.example","type":"Primary","soaSerial":6,"notifyFailed":true,"notifyFailedFor":["10.0.0.2"]},
		{"name":"cluster-catalog.example","type":"SecondaryCatalog","soaSerial":1}
	]}`)

	zoneOf(p, false, "example.com",
		rec("example.com", "SOA", `{"primaryNameServer":"dock","responsiblePerson":"hostadmin@example.com","serial":7}`),
		rec("example.com", "NS", `{"nameServer":"dock.elsewhere.net"}`),
		rec("example.com", "MX", `{"preference":10,"exchange":"mail.example.com"}`),
		rec("_sip._tcp.example.com", "SRV", `{"priority":1,"weight":2,"port":5060,"target":"m.example.com"}`),
		cname("m.example.com", "emby.van.example.com"),
		cname("gone.example.com", "nothing.van.example.com"),
		cname("a.example.com", "b.example.com"), cname("b.example.com", "a.example.com"),
		cname("l1.example.com", "l2.example.com"), cname("l2.example.com", "l3.example.com"), cname("l3.example.com", "l4.example.com"), cname("l4.example.com", "l5.example.com"), cname("l5.example.com", "l6.example.com"), addr("l6.example.com", "10.0.0.60"),
		cname("both.example.com", "m.example.com"), addr("both.example.com", "10.0.0.9"),
		addr("emby.van.example.com", "10.0.0.99"),
		addr("*.wild.example.com", "10.0.0.8"),
		addr("two.example.com", "10.0.0.5"), addr("two.example.com", "10.0.1.5"),
		addr("bad_host.example.com", "10.0.0.6"), addr("_ok.example.com", "10.0.0.61"),
		addr("technitium.example.com", "10.0.0.10"), addr("technitum.example.com", "10.0.0.11"), addr("server1.example.com", "10.0.0.12"), addr("server2.example.com", "10.0.0.13"), addr("pimox5a.example.com", "10.0.0.19"), addr("pimox5b.example.com", "10.0.0.20"),
		strings.Replace(addr("fast.example.com", "10.0.0.14"), `"ttl":3600`, `"ttl":30`, 1), strings.Replace(addr("slow.example.com", "10.0.0.15"), `"ttl":3600`, `"ttl":1209600`, 1),
		addr("spacey.example.com", "10.0.0.16", `"comments":"two  spaces "`),
		addr("old.example.com", "10.0.0.17", `"disabled":true`), addr("temp.example.com", "10.0.0.18", `"expiryTtl":172800`),
		rec("txt.example.com", "TXT", `{"text":"free  text  is  its  own"}`),
	)
	// van.example.com names a node of the cluster that is not configured here as its name server, and holds a signature the server has let expire
	zoneOf(p, false, "van.example.com", rec("van.example.com", "NS", `{"nameServer":"ns3.cluster.example"}`), rec("van.example.com", "RRSIG", `{"typeCovered":"NS","algorithm":"ECDSAP256SHA256","keyTag":22,"signatureExpiration":"2020-01-01T00:00:00Z","signatureInception":"2019-12-01T00:00:00Z","signersName":"van.example.com"}`), addr("emby.van.example.com", "10.0.0.4"), addr("dock.van.example.com", "10.0.0.2"))
	zoneOf(p, false, "apex.example", rec("apex.example", "SOA", `{"primaryNameServer":"dock"}`), cname("apex.example", "elsewhere.example.net"))
	zoneOf(p, false, "0.0.10.in-addr.arpa",
		ptr("4.0.0.10.in-addr.arpa", "emby.van.example.com"),
		ptr("7.0.0.10.in-addr.arpa", "ghost.van.example.com"),
		ptr("5.0.0.10.in-addr.arpa", "emby.van.example.com"),
		ptr("9.0.0.10.in-addr.arpa", "both.example.com"), ptr("9.0.0.10.in-addr.arpa", "other.example.net"),
	)
	zoneOf(p, false, "off.example", rec("off.example", "SOA", `{"primaryNameServer":"oldname","serial":1}`), addr("x.off.example", "192.0.2.1"))
	zoneOf(p, false, "copy.example", addr("a.copy.example", "192.0.2.2"))

	// rpi holds the zone as its own too, with one record of its own and one
	// it cannot follow: it has no zone for where the CNAME points
	zoneOf(p, true, "example.com",
		rec("example.com", "SOA", `{"primaryNameServer":"rpi","responsiblePerson":"hostadmin@example.com","serial":9}`),
		rec("example.com", "NS", `{"nameServer":"dock.elsewhere.net"}`),
		cname("m.example.com", "emby.van.example.com"),
		addr("only-rpi.example.com", "192.0.2.3"),
	)
	zoneOf(p, true, "copy.example", addr("a.copy.example", "192.0.2.2"))
	auditDHCPOf(p)
	auditBlockingOf(p)
	auditSetupOf(p)
	auditMoreOf(p)

	return p
}

// A node of a cluster, an account and an app as a canned server gives each.
func nodeJSON(id int, name, kind, state, version string) string {
	return fmt.Sprintf(`{"id":%d,"name":"%s.cluster.example","url":"https://%s.cluster.example:53443/","ipAddresses":["10.0.0.%d"],"type":%q,"state":%q,"version":%q,"lastSeen":"2020-01-01T00:00:00Z"}`, id, name, name, id, kind, state, version)
}

func userJSON(name, more string) string {
	return fmt.Sprintf(`{"username":%q,"displayName":%q,"recentSessionLoggedOn":"2026-10-01T00:00:00Z","memberOfGroups":[],"sessions":[]%s}`, name, name, more)
}

func appJSON(name, version string, logs bool) string {
	return fmt.Sprintf(`{"name":%q,"version":%q,"dnsApps":[{"classPath":"App.%s","isQueryLogger":%v,"isQueryLogs":%v}]}`, name, version, strings.ReplaceAll(name, " ", ""), logs, logs)
}

// auditMoreOf gives the pair what each says of its cluster, its accounts,
// its signed zone, its queries and its apps. They are a cluster that is not
// whole: dock, its primary, cannot reach rpi and lists a third node nobody
// configured; rpi, a version behind, has not fetched the configuration in
// years and does not list the third. dock has an administrator with no
// second factor, an account nobody used, one switched off with a token left,
// and a section everyone may change; a signed zone with a key waiting for
// its DS, one never published, one never replaced and one of an old
// algorithm; a day in which a tenth of its queries failed, most from one
// client, and a name asked for that does not exist; and an app behind the
// store that rpi does not run. rpi cannot resolve, keeps no log, and will
// not list its accounts.
func auditMoreOf(p *pair) {
	p.dock.Answer("admin/cluster/state", `{"clusterInitialized":true,"dnsServerDomain":"dock.cluster.example","version":"15.6","clusterDomain":"cluster.example","configRefreshIntervalSeconds":900,"serverIpAddresses":["10.20.0.2","10.20.5.2"],"clusterNodes":[`+nodeJSON(2, "dock", "Primary", "Self", "15.6")+`,`+nodeJSON(3, "rpi", "Secondary", "Unreachable", "15.5")+`,`+nodeJSON(9, "ns3", "Secondary", "Connected", "15.6")+`]}`)
	p.rpi.Answer("admin/cluster/state", `{"clusterInitialized":true,"dnsServerDomain":"rpi.cluster.example","version":"15.5","clusterDomain":"cluster.example","configRefreshIntervalSeconds":900,"configLastSynced":"2020-01-01T00:00:00Z","serverIpAddresses":["10.20.0.3"],"clusterNodes":[`+nodeJSON(2, "dock", "Primary", "Connected", "15.6")+`,`+nodeJSON(3, "rpi", "Secondary", "Self", "15.5")+`]}`)

	p.dock.Answer("admin/users/list", `{"users":[`+userJSON("admin", "")+`,`+userJSON("never", "")+`,`+userJSON("off", "")+`,`+userJSON("careful", "")+`]}`)
	p.dock.AnswerWhen("admin/users/get", "user", "admin", strings.Replace(userJSON("admin", ""), `"memberOfGroups":[],"sessions":[]`, `"memberOfGroups":["Administrators"],"sessions":[{"type":"ApiToken","tokenName":"mcp"}]`, 1))
	p.dock.AnswerWhen("admin/users/get", "user", "never", strings.Replace(userJSON("never", ""), "2026-10-01T00:00:00Z", "0001-01-01T00:00:00", 1))
	p.dock.AnswerWhen("admin/users/get", "user", "off", strings.Replace(userJSON("off", `,"disabled":true`), `"sessions":[]`, `"sessions":[{"type":"ApiToken","tokenName":"left"}]`, 1))
	p.dock.AnswerWhen("admin/users/get", "user", "careful", strings.Replace(userJSON("careful", `,"totpEnabled":true`), `"memberOfGroups":[]`, `"memberOfGroups":["Administrators"]`, 1))
	p.dock.Answer("admin/permissions/list", `{"permissions":[{"section":"Cache","userPermissions":[],"groupPermissions":[{"name":"Administrators","canView":true,"canModify":true,"canDelete":true},{"name":"Everyone","canView":true,"canModify":true,"canDelete":false}]},{"section":"Zones","userPermissions":[],"groupPermissions":[{"name":"Everyone","canView":true,"canModify":false,"canDelete":false}]}]}`)
	p.rpi.Fail("admin/users/list", "error", "Access was denied.")

	p.dock.Answer("zones/dnssec/properties/get", `{"name":"van.example.com","type":"Primary","dnssecStatus":"SignedWithNSEC","dnsKeyTtl":3600,"dnssecPrivateKeys":[{"keyTag":11,"keyType":"KeySigningKey","algorithm":"ECDSAP256SHA256","state":"Ready","stateChangedOn":"2026-10-01T00:00:00Z","rolloverDays":0},{"keyTag":22,"keyType":"ZoneSigningKey","algorithm":"ECDSAP256SHA256","state":"Active","rolloverDays":0},{"keyTag":33,"keyType":"ZoneSigningKey","algorithm":"ECDSAP256SHA256","state":"Generated","stateChangedOn":"2026-09-01T00:00:00Z","rolloverDays":30},{"keyTag":44,"keyType":"ZoneSigningKey","algorithm":"RSASHA1","state":"Active","isRetiring":true,"rolloverDays":30}]}`)
	p.dock.Answer("zones/dnssec/viewDS", `{"name":"van.example.com","type":"Primary","dnssecStatus":"SignedWithNSEC","dsRecords":[{"keyTag":11,"dnsKeyState":"Ready","algorithm":"ECDSAP256SHA256","publicKey":"cHVibGlj","digests":[{"digestType":"SHA256","digest":"AB12"}]}]}`)

	p.dock.AnswerWhole("dnsClient/healthCheck", `{"server":"dock","status":"ok"}`)
	p.rpi.Fail("dnsClient/healthCheck", "error", "DNS Server failed to resolve the request.")
	p.dock.AnswerWhen("dashboard/stats/get", "type", "LastDay", `{"stats":{"totalQueries":2000,"totalServerFailure":200,"blockListZones":0},"topClients":[{"name":"10.0.0.50","domain":"busy.van.example.com","hits":1500},{"name":"10.0.0.51","hits":1000},{"name":"10.0.0.52","hits":200}],"topDomains":[{"name":"emby.van.example.com","hits":1200},{"name":"dock.van.example.com","hits":500},{"name":"www.example.org","hits":5000}]}`)
	p.dock.Answer("apps/list", `{"apps":[`+appJSON("Query Logs (Sqlite)", "8", true)+`,`+appJSON("Split Horizon", "1.0", false)+`]}`)
	p.rpi.Answer("apps/list", `{"apps":[]}`)
	p.dock.Answer("apps/config/get", `{"config":"{\"enableLogging\":true,\"maxLogDays\":7}"}`)
	p.dock.Answer("apps/listStoreApps", `{"storeApps":[{"name":"Split Horizon","version":"1.1","url":"https://download.example.org/SplitHorizonApp.zip","size":"11 KB","installed":true,"installedVersion":"1.0","updateAvailable":true},{"name":"Query Logs (Sqlite)","version":"8","url":"https://download.example.org/QueryLogsSqliteApp.zip","size":"1 MB","installed":true,"installedVersion":"8","updateAvailable":false}]}`)
	p.rpi.Fail("apps/listStoreApps", "error", "Could not reach the app store.")
	var asked []string
	for name, times := range map[string]int{"nothing.van.example.com": 6, "rare.example.com": 2, "elsewhere.example.net": 7} {
		for range times {
			asked = append(asked, fmt.Sprintf(`{"rowNumber":1,"timestamp":"2026-10-09T10:00:00Z","clientIpAddress":"10.0.0.50","protocol":"Udp","responseType":"Authoritative","rcode":"NxDomain","qname":%q,"qtype":"A","qclass":"IN","answer":null}`, name))
		}
	}
	p.dock.Answer("logs/query", `{"pageNumber":1,"totalPages":1,"totalEntries":`+strconv.Itoa(len(asked))+`,"entries":[`+strings.Join(asked, ",")+`]}`)
}

// auditSetupOf gives the pair what each says of itself and of its zones'
// options: dock a zone anyone may transfer and change, another changed by
// address alone, a token nobody uses and a version behind; rpi the password
// it shipped with, a zone it will not give its copy, and sessions it will
// not list.
func auditSetupOf(p *pair) {
	p.dock.AnswerWhole("status", `{"hasDefaultCredentials":false,"ssoEnabled":false,"server":"dock","status":"ok"}`)
	p.rpi.AnswerWhole("status", `{"hasDefaultCredentials":true,"ssoEnabled":false,"server":"rpi","status":"ok"}`)
	p.both("zones/options/get", `{"type":"Primary","queryAccess":"Allow","zoneTransfer":"AllowOnlyZoneNameServers","notify":"ZoneNameServers","update":"Deny"}`)
	p.dock.AnswerWhen("zones/options/get", "zone", "example.com", `{"type":"Primary","zoneTransfer":"Allow","notify":"ZoneNameServers","update":"Allow"}`)
	p.dock.AnswerWhen("zones/options/get", "zone", "van.example.com", `{"type":"Primary","zoneTransfer":"Deny","notify":"None","update":"UseSpecifiedNetworkACL","updateNetworkACL":["10.0.0.0/24"],"updateSecurityPolicies":[]}`)
	p.dock.AnswerWhen("zones/options/get", "zone", "lan.example", `{"type":"Primary","zoneTransfer":"Deny","notify":"None","update":"UseSpecifiedNetworkACL","updateNetworkACL":["10.0.0.0/24"],"updateSecurityPolicies":[{"tsigKeyName":"home","domain":"*.lan.example","allowedTypes":["A"]}]}`)
	p.dock.AnswerWhen("zones/options/get", "zone", "copy.example", `{"type":"Secondary","zoneTransfer":"Deny","notify":"None","update":"Deny","primaryNameServerAddresses":["10.0.0.3"]}`)
	p.rpi.AnswerWhen("zones/options/get", "zone", "copy.example", `{"type":"Primary","zoneTransfer":"Deny","notify":"None","update":"Deny"}`)
	p.dock.Answer("admin/sessions/list", `{"sessions":[{"username":"admin","isCurrentSession":true,"type":"ApiToken","tokenName":"mcp","lastSeen":"2020-01-01T00:00:00Z"},{"username":"kt","isCurrentSession":false,"type":"ApiToken","tokenName":"old-script","lastSeen":"2025-01-01T00:00:00Z"},{"username":"kt","isCurrentSession":false,"type":"Standard","tokenName":null,"lastSeen":"2025-01-01T00:00:00Z"}]}`)
	p.rpi.Fail("admin/sessions/list", "error", "Access was denied.")
	p.dock.Answer("user/checkForUpdate", `{"dnsServerEnableCheckForUpdate":true,"updateAvailable":true,"updateVersion":"15.7","currentVersion":"15.6","changeLogLink":"https://technitium.com/dns/changelog"}`)
	p.rpi.Fail("user/checkForUpdate", "error", "Could not reach the update server.")
}

// auditBlockingOf gives the pair their blocking: dock blocks, by lists it
// has not fetched and that hold nothing and by entries of its own, most of
// which do nothing; rpi has blocking off and one name on its list.
func auditBlockingOf(p *pair) {
	p.dock.Answer("settings/get", `{"recursion":"AllowOnlyForPrivateNetworks","webServiceEnableTls":true,"enableBlocking":true,"blockingType":"NxDomain","blockListUrls":["https://lists.example.org/ads.txt","!https://lists.example.org/fine.txt"],"blockListUpdateIntervalHours":24,"blockListNextUpdatedOn":"2020-01-01T00:00:00Z"}`)
	p.rpi.Answer("settings/get", `{"recursion":"Allow","webServiceEnableTls":false,"enableBlocking":false,"blockingType":"NxDomain","blockListUrls":["https://lists.example.org/ads.txt"],"blockListUpdateIntervalHours":24,"blockListNextUpdatedOn":"2020-01-01T00:00:00Z"}`)
	p.both("dashboard/stats/get", `{"stats":{"totalQueries":0,"blockListZones":0}}`)
	// a name dock's own zone answers for, one under .test, one beside the entry above it, and one the allowed list wins over
	p.dock.AnswerText("blocked/export", "emby.van.example.com\nads.blocked.test\nads.example.net\nx.ads.example.net\ngood.example.org\n")
	p.dock.AnswerText("allowed/export", "example.org\nwww.example.org\n")
	p.rpi.AnswerText("blocked/export", "ads.example.net\n")
	p.rpi.AnswerText("allowed/export", "")
}

// A lease, a reservation and a scope as a canned server gives each.
func leaseJSON(scope, kind, mac, address, host string) string {
	name := "null"
	if host != "" {
		name = `"` + host + `"`
	}

	return `{"scope":"` + scope + `","type":"` + kind + `","hardwareAddress":"` + mac + `","clientIdentifier":"1-` + strings.ReplaceAll(mac, "-", "") + `","address":"` + address + `","hostName":` + name + `,"leaseObtained":"2026-10-09T17:52:51.4918249Z","leaseExpires":"2026-10-10T17:52:51.5033207Z"}`
}

func reservedJSON(mac, address, host, comments string) string {
	quoted := func(text string) string {
		if text == "" {
			return "null"
		}

		return `"` + text + `"`
	}

	return `{"hostName":` + quoted(host) + `,"hardwareAddress":"` + mac + `","address":"` + address + `","comments":` + quoted(comments) + `}`
}

func scopeJSON(name, first, last, more string, reserved ...string) string {
	return `{"name":"` + name + `","startingAddress":"` + first + `","endingAddress":"` + last + `","subnetMask":"255.255.255.0","leaseTimeDays":1,"leaseTimeHours":0,"leaseTimeMinutes":0,` + more + `,"reservedLeases":[` + strings.Join(reserved, ",") + `],"allowOnlyReservedLeases":false}`
}

const (
	defaultScopeListed = `{"name":"Default","enabled":false,"startingAddress":"192.168.1.1","endingAddress":"192.168.1.254","subnetMask":"255.255.255.0","networkAddress":"192.168.1.0","broadcastAddress":"192.168.1.255"}`
	lanScopeListed     = `{"name":"LAN","enabled":true,"startingAddress":"10.20.0.100","endingAddress":"10.20.0.119","subnetMask":"255.255.255.0","networkAddress":"10.20.0.0","broadcastAddress":"10.20.0.255","interfaceAddress":"10.20.0.2"}`
	labScopeListed     = `{"name":"Lab","enabled":true,"startingAddress":"10.20.5.10","endingAddress":"10.20.5.19","subnetMask":"255.255.255.0","networkAddress":"10.20.5.0","broadcastAddress":"10.20.5.255","interfaceAddress":"10.20.5.2"}`
	lanScopeOptions    = `"domainName":"lan.example","dnsUpdates":true,"dnsTtl":900,"routerAddress":"10.20.0.1","useThisDnsServer":false,"dnsServers":["10.20.0.2","9.9.9.9"],"exclusions":[{"startingAddress":"10.20.0.118","endingAddress":"10.20.0.119"}]`
	byLAN              = `"comments":"Via 'LAN' DHCP scope"`
)

// auditDHCPOf gives the pair their DHCP: dock leases on two networks and
// holds the zone its scope records names in, with one of everything the DHCP
// audit looks for; rpi has the scope a server ships with, switched off.
func auditDHCPOf(p *pair) {
	p.dock.Answer("admin/cluster/state", `{"clusterInitialized":false,"dnsServerDomain":"dock","version":"15.6","serverIpAddresses":["10.20.0.2","10.20.5.2"]}`)
	p.rpi.Answer("admin/cluster/state", `{"clusterInitialized":false,"dnsServerDomain":"rpi","version":"15.6","serverIpAddresses":["10.20.0.3"]}`)

	p.dock.Answer("dhcp/scopes/list", `{"scopes":[`+defaultScopeListed+`,`+lanScopeListed+`,`+labScopeListed+`]}`)
	p.rpi.Answer("dhcp/scopes/list", `{"scopes":[`+defaultScopeListed+`]}`)
	p.both("dhcp/scopes/get", scopeJSON("Default", "192.168.1.1", "192.168.1.254", `"useThisDnsServer":true`))
	p.dock.AnswerWhen("dhcp/scopes/get", "name", "LAN", scopeJSON("LAN", "10.20.0.100", "10.20.0.119", lanScopeOptions,
		reservedJSON("AA-00-00-00-00-01", "10.20.0.4", "emby", "the emby vm"),
		reservedJSON("AA-00-00-00-00-02", "10.20.0.30", "nas", ""),
		reservedJSON("AA-00-00-00-00-03", "10.20.0.22", "dock", ""),
		reservedJSON("AA-00-00-00-00-04", "10.9.9.9", "", ""),
		reservedJSON("AA-00-00-00-00-05", "10.20.0.40", "twin", ""),
		reservedJSON("AA-00-00-00-00-06", "10.20.0.40", "", ""),
		reservedJSON("AA-00-00-00-00-07", "10.20.0.50", "printer", ""),
		reservedJSON("00-00-00-00-00-00", "10.20.0.60", "", ""),
	))
	// Lab names its own server twice over, and a node of the cluster that is not configured here
	p.dock.AnswerWhen("dhcp/scopes/get", "name", "Lab", scopeJSON("Lab", "10.20.5.10", "10.20.5.19", `"domainName":"lab.example","dnsUpdates":false,"useThisDnsServer":true,"dnsServers":["10.20.5.2","10.0.0.9"]`))

	leases := make([]string, 0, 14)
	leases = append(leases,
		leaseJSON("LAN", "Reserved", "AA-00-00-00-00-01", "10.20.0.4", "emby.lan.example"),
		leaseJSON("LAN", "Dynamic", "AA-00-00-00-00-10", "10.20.0.100", "laptop.lan.example"),
		leaseJSON("LAN", "Dynamic", "AA-00-00-00-00-11", "10.20.0.101", "phone.lan.example"),
		leaseJSON("LAN", "Dynamic", "AA-00-00-00-00-12", "10.20.0.102", ""),
		leaseJSON("LAN", "Dynamic", "AA-00-00-00-00-99", "10.20.0.50", "guest.lan.example"),
	)
	for i := range 9 {
		leases = append(leases, leaseJSON("Lab", "Dynamic", "AA-00-00-00-01-0"+string(rune('0'+i)), "10.20.5.1"+string(rune('0'+i)), ""))
	}
	p.dock.Answer("dhcp/leases/list", `{"leases":[`+strings.Join(leases, ",")+`]}`)
	p.rpi.Answer("dhcp/leases/list", `{"leases":[]}`)

	zoneOf(p, false, "lan.example",
		rec("lan.example", "SOA", `{"primaryNameServer":"dock","serial":4}`),
		addr("dock.lan.example", "10.20.0.2"),
		addr("emby.lan.example", "10.20.0.4", byLAN), addr("printer.lan.example", "10.20.0.50", byLAN), addr("laptop.lan.example", "10.20.0.100", byLAN),
		// made by hand: a name a lease has, an address a lease has, an address in the range, and one in the part of it left out
		addr("phone.lan.example", "10.20.0.77"), addr("static.lan.example", "10.20.0.102"), addr("fixed.lan.example", "10.20.0.110"), addr("excl.lan.example", "10.20.0.118"),
		// the server's own, for a lease that is gone and for a scope that is
		addr("gone.lan.example", "10.20.0.105", byLAN), addr("old.lan.example", "10.20.0.200", `"comments":"Via 'Old' DHCP scope"`),
	)
}

// found is the findings of an audit, each as its problem, its name or zone,
// and the servers it is on.
func auditFindings(t *testing.T, suite *acctest.Suite, tool string, args map[string]any) []map[string]any {
	t.Helper()

	return acctest.Rows(t, suite.Call(t, tool, args)["findings"], "findings")
}

// want fails the test unless the findings hold one of a kind at a name whose
// detail says what it should, on the servers it should.
func want(t *testing.T, findings []map[string]any, problem, at, says string, servers ...string) {
	t.Helper()

	for _, f := range findings {
		if f["problem"] != problem || (f["name"] != at && (f["name"] != nil || f["zone"] != at)) {
			continue
		}
		if !strings.Contains(acctest.Str(f["detail"]), says) {
			t.Errorf("%s at %s says %q, want it to say %q", problem, at, f["detail"], says)
		}
		if got := acctest.Texts(f["servers"]); !slices.Equal(got, servers) {
			t.Errorf("%s at %s is on %v, want %v", problem, at, got, servers)
		}
		if acctest.Str(f["fix"]) == "" {
			t.Errorf("%s at %s has no fix", problem, at)
		}

		return
	}
	t.Errorf("no %s at %s among %d findings", problem, at, len(findings))
}

// none fails the test when the findings hold one of a kind at a name.
func none(t *testing.T, findings []map[string]any, problem, at string) {
	t.Helper()

	for _, f := range findings {
		if f["problem"] == problem && (f["name"] == at || (f["name"] == nil && f["zone"] == at)) {
			t.Errorf("a %s at %s was found, and nothing is wrong there: %v", problem, at, f["detail"])
		}
	}
}

func TestAuditServers(t *testing.T) {
	t.Parallel()

	suite := auditPair(t).session(t, Options{})
	out := suite.Call(t, "audit_servers", nil)
	found := acctest.Rows(t, out["findings"], "findings")

	want(t, found, "zone_missing", "van.example.com", "van.example.com is on dock and not on rpi", "dock")
	want(t, found, "two_primaries", "example.com", "dock and rpi each hold example.com as a primary zone of their own", "dock", "rpi")
	// the SOA is each server's own to differ in; the records that differ are said, the first few by name
	want(t, found, "records_differ", "example.com", "32 records of example.com are not the same on dock and rpi: example.com MX 10 mail.example.com (ttl 3600) on dock alone;")
	want(t, found, "records_differ", "example.com", "; and 27 more")
	want(t, found, "copy_behind", "copy.example", "dock holds copy.example at serial 5 and its primary rpi is at 6", "dock")
	want(t, found, "sync_failed", "copy.example", "its last transfer from the primary failed", "dock")
	want(t, found, "copy_expired", "copy.example", "has expired", "dock")
	want(t, found, "notify_failed", "copy.example", "rpi could not tell 10.0.0.2 that copy.example had changed", "rpi")
	// a copy and its primary hold the same records: nothing differs there
	none(t, found, "records_differ", "copy.example")
	none(t, found, "two_primaries", "copy.example")

	// the server that lacks the zone follows a catalog the holder has: that is the way to give it the zone
	for _, f := range found {
		if f["problem"] == "zone_missing" && f["zone"] == "van.example.com" && !strings.Contains(acctest.Str(f["fix"]), "dock holds the catalog cluster-catalog.example, which rpi follows, and this zone is not a member of it") {
			t.Errorf("the fix for a zone the catalog does not carry = %q", f["fix"])
		}
	}

	counts := acctest.Object(t, out["counts"], "counts")
	if acctest.NumOr0(counts["zone_missing"]) != 5 || acctest.NumOr0(counts["two_primaries"]) != 1 || acctest.Num(t, out["zones"], "zones") != 7 || !slices.Equal(acctest.Strs(t, out["asked"], "asked"), []string{"dock", "rpi"}) {
		t.Errorf("counts = %v over %v zones", counts, out["zones"])
	}
	// one server alone has nothing to differ from
	if alone := suite.Call(t, "audit_servers", map[string]any{"server": "rpi"}); acctest.NumOr0(acctest.Object(t, alone["counts"], "counts")["zone_missing"]) != 0 || acctest.NumOr0(acctest.Object(t, alone["counts"], "counts")["notify_failed"]) != 1 {
		t.Errorf("rpi alone = %v", alone["counts"])
	}
}

func TestAuditTargets(t *testing.T) {
	t.Parallel()

	suite := auditPair(t).session(t, Options{})
	found := auditFindings(t, suite, "audit_targets", nil)

	want(t, found, "dangling", "gone.example.com", "gone.example.com is a CNAME that leads through nothing.van.example.com, and nothing.van.example.com has no record in van.example.com", "dock")
	// rpi holds the CNAME and no zone for where it points, so there the target's name is in the zone above with nothing at it
	want(t, found, "dangling", "m.example.com", "emby.van.example.com has no record in example.com", "rpi")
	want(t, found, "loop", "a.example.com", "the chain loops back to a.example.com", "dock")
	want(t, found, "loop", "b.example.com", "loops back", "dock")
	want(t, found, "long_chain", "l1.example.com", "l1.example.com takes 5 CNAMEs to reach an address", "dock")
	none(t, found, "long_chain", "l2.example.com")
	want(t, found, "cname_at_apex", "apex.example", "apex.example is its zone's own name and has a CNAME to elsewhere.example.net", "dock")
	want(t, found, "cname_with_others", "both.example.com", "both.example.com has a CNAME to m.example.com and beside it A 10.0.0.9", "dock")
	want(t, found, "target_missing", "example.com", "the MX at example.com names mail.example.com, which has no record in example.com", "dock")
	want(t, found, "target_is_cname", "_sip._tcp.example.com", "the SRV at _sip._tcp.example.com names m.example.com, which is a CNAME", "dock")
	// a name server in no zone here is not theirs to judge, and a zone's own SOA and NS are no company for its CNAME to be told of twice
	none(t, found, "target_missing", "van.example.com")
	none(t, found, "cname_with_others", "apex.example")

	// one kind, in one zone
	only := suite.Call(t, "audit_targets", map[string]any{"problems": []string{"loop"}, "zone": "example.com"})
	if got := acctest.Rows(t, only["findings"], "findings"); len(got) != 2 || acctest.Num(t, only["total"], "total") != 2 || len(acctest.Object(t, only["counts"], "counts")) != 1 {
		t.Errorf("the loops alone = %v", only)
	}
	if msg := suite.CallErr(t, "audit_targets", map[string]any{"problems": []string{"no_ptr"}}); !strings.Contains(msg, `audit_targets finds no "no_ptr": it finds dangling, loop`) {
		t.Errorf("a kind it does not find = %q", msg)
	}
}

func TestAuditReverse(t *testing.T) {
	t.Parallel()

	suite := auditPair(t).session(t, Options{})
	found := auditFindings(t, suite, "audit_reverse", map[string]any{"server": "dock"})

	want(t, found, "no_ptr", "2.0.0.10.in-addr.arpa", "10.0.0.2 is held by dock.van.example.com and has no PTR record")
	want(t, found, "ptr_stale", "7.0.0.10.in-addr.arpa", "the PTR for 10.0.0.7 names ghost.van.example.com, which has no address record")
	want(t, found, "ptr_stale", "5.0.0.10.in-addr.arpa", "the PTR for 10.0.0.5 names emby.van.example.com, which holds 10.0.0.4")
	want(t, found, "ptr_elsewhere", "5.0.0.10.in-addr.arpa", "10.0.0.5 is held by two.example.com and its PTR names emby.van.example.com")
	want(t, found, "several_ptrs", "9.0.0.10.in-addr.arpa", "10.0.0.9 has 2 PTR records, naming both.example.com, other.example.net")
	want(t, found, "no_reverse_zone", "1.0.10.in-addr.arpa", "1 addresses in 10.0.1.0/24 are held by records and no reverse zone here holds their PTRs: 10.0.1.5")
	// an address with its PTR, one of several names for an address the PTR names, a wildcard, and an address that is someone else's
	none(t, found, "no_ptr", "4.0.0.10.in-addr.arpa")
	none(t, found, "ptr_elsewhere", "9.0.0.10.in-addr.arpa")
	none(t, found, "no_ptr", "8.0.0.10.in-addr.arpa")
	none(t, found, "no_reverse_zone", "2.0.192.in-addr.arpa")
	// the fix for a missing PTR is the call that adds it
	for _, f := range found {
		if f["problem"] == "no_ptr" && f["name"] == "2.0.0.10.in-addr.arpa" && f["fix"] != "record_set name=2.0.0.10.in-addr.arpa type=PTR value=dock.van.example.com" {
			t.Errorf("the fix for a missing PTR = %q", f["fix"])
		}
	}
}

func TestAuditOverlapsNamingAndState(t *testing.T) {
	t.Parallel()

	suite := auditPair(t).session(t, Options{})

	overlaps := auditFindings(t, suite, "audit_overlaps", map[string]any{"server": "dock"})
	want(t, overlaps, "shadowed", "emby.van.example.com", "emby.van.example.com has records in example.com (A 10.0.0.99), and the server also holds the zone van.example.com, which answers for that name instead")
	want(t, overlaps, "wildcard", "*.wild.example.com", "every name under wild.example.com with no record of its own is answered with A 10.0.0.8")
	want(t, overlaps, "addresses_apart", "two.example.com", "two.example.com has addresses in 10.0.0.0/24 and 10.0.1.0/24")
	if len(overlaps) != 3 {
		t.Errorf("overlaps = %v, want the three", overlaps)
	}

	naming := auditFindings(t, suite, "audit_naming", map[string]any{"server": "dock"})
	want(t, naming, "underscore", "bad_host.example.com", "has an underscore in its name")
	want(t, naming, "near_duplicate", "technitium.example.com", "technitium.example.com and technitum.example.com differ by a slip of the keyboard")
	want(t, naming, "ttl_short", "fast.example.com", "has a TTL of 30 seconds")
	want(t, naming, "ttl_long", "slow.example.com", "has a TTL of 14.0 days")
	want(t, naming, "space", "spacey.example.com", "the comment of the A record at spacey.example.com has double space, edge space")
	// a label that begins with an underscore names a service; numbered hosts are two hosts; a TXT's spaces are its own
	none(t, naming, "underscore", "_ok.example.com")
	none(t, naming, "underscore", "_sip._tcp.example.com")
	none(t, naming, "near_duplicate", "server1.example.com")
	none(t, naming, "near_duplicate", "pimox5a.example.com")
	none(t, naming, "space", "txt.example.com")
	for _, f := range naming {
		if f["problem"] == "space" && f["fix"] != `it should read "two spaces"` {
			t.Errorf("the fix for the spaces = %q", f["fix"])
		}
	}

	state := auditFindings(t, suite, "audit_state", nil)
	want(t, state, "zone_disabled", "off.example", "off.example is disabled", "dock")
	want(t, state, "record_disabled", "old.example.com", "the A 10.0.0.17 at old.example.com is disabled", "dock")
	want(t, state, "record_expires", "temp.example.com", "deletes itself 2.0 days after its last change", "dock")
	if len(state) != 3 {
		t.Errorf("state = %v, want the three", state)
	}
}

// audit_all runs every audit in one reading and says how much each found;
// what each found is the audit's own to give.
func TestAuditAll(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	suite := p.session(t, Options{})

	out := suite.Call(t, "audit_all", nil)
	rows := acctest.Rows(t, out["audits"], "audits")
	if len(rows) != len(audits) {
		t.Fatalf("audits = %v, want every one", rows)
	}
	total := 0
	for i, row := range rows {
		if row["audit"] != audits[i].name {
			t.Errorf("audit %d = %v, want %s", i, row["audit"], audits[i].name)
		}
		// each audit, called itself, finds what audit_all counted
		own := suite.Call(t, audits[i].name, map[string]any{"limit": 1000})
		if acctest.Num(t, row["total"], "total") != acctest.Num(t, own["total"], "total") || acctest.Num(t, row["total"], "total") == 0 {
			t.Errorf("%s: audit_all counts %v and the audit finds %v, and the fixture has something for every audit", audits[i].name, row["total"], own["total"])
		}
		total += acctest.Num(t, row["total"], "total")
	}
	if acctest.Num(t, out["total"], "total") != total || acctest.Num(t, out["zones"], "zones") != 7 {
		t.Errorf("total = %v over %v zones, want %d over 7", out["total"], out["zones"], total)
	}
	// the zones are read once for all of them
	if n := len(p.dock.Requests("zones/list")); n != 1+len(audits) {
		t.Errorf("dock's zones were listed %d times, want once for audit_all and once for each audit called after", n)
	}

	// one zone's
	narrowed := suite.Call(t, "audit_all", map[string]any{"zone": "copy.example"})
	// what the servers do not hold alike of it, and what its own records and options have wrong
	rows = acctest.Rows(t, narrowed["audits"], "audits")
	if zones := slices.IndexFunc(rows, func(row map[string]any) bool { return row["audit"] == "audit_zones" }); acctest.Num(t, rows[0]["total"], "total") != 4 || acctest.Num(t, rows[zones]["total"], "total") != 4 || acctest.Num(t, narrowed["total"], "total") != 8 {
		t.Errorf("one zone's = %v", narrowed)
	}

	// a limit, and reading on
	paged := suite.Call(t, "audit_reverse", map[string]any{"limit": 2, "offset": 1, "server": "dock"})
	if len(acctest.Rows(t, paged["findings"], "findings")) != 2 || !strings.Contains(acctest.Str(paged["note"]), "starting at the 2nd: read on with offset 3") {
		t.Errorf("paged = %v", paged)
	}

	// a server that cannot be asked is said, and the rest audited
	p.rpi.Fail("zones/list", "error", "boom")
	if failed := acctest.Rows(t, suite.Call(t, "audit_all", nil)["failed"], "failed"); len(failed) != 1 || failed[0]["server"] != "rpi" {
		t.Errorf("failed = %v", failed)
	}
}

// audit_dhcp reads every scope, reservation and lease beside the zones, and
// finds where they do not agree.
func TestAuditDHCP(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	suite := p.session(t, Options{})
	out := suite.Call(t, "audit_dhcp", nil)
	found := acctest.Rows(t, out["findings"], "findings")

	// the scopes
	want(t, found, "pool_low", "Lab", "scope Lab on dock has 1 of its 10 addresses free: 9 leases are held and 0 addresses reserved", "dock")
	none(t, found, "pool_low", "LAN")
	want(t, found, "scope_domain_unknown", "Lab", "scope Lab on dock tells machines they are in lab.example, and no server asked holds a zone for it", "dock")
	none(t, found, "scope_domain_unknown", "LAN")
	want(t, found, "scope_dns_unknown", "LAN", "scope LAN on dock tells machines to resolve through 9.9.9.9, which is no address of a server asked", "dock")
	want(t, found, "scope_dns_missing", "LAN", "scope LAN on dock tells machines to resolve through 10.20.0.2, 9.9.9.9 and not through rpi (10.20.0.3)", "dock")
	want(t, found, "scope_dns_missing", "Lab", "resolve through 10.20.5.2, 10.20.5.2, 10.0.0.9 and not through rpi (10.20.0.3)", "dock")
	// the same server as this server and by its address; a node of the cluster that was not read is a server all the same
	want(t, found, "scope_dns_same", "Lab", "scope Lab on dock tells machines to resolve through 10.20.5.2 twice, as this server and by its address", "dock")
	none(t, found, "scope_dns_unknown", "Lab")

	// the reservations
	want(t, found, "reservation_outside", "10.9.9.9", "scope LAN on dock keeps 10.9.9.9 for AA-00-00-00-00-04, which is outside its network 10.20.0.0/24", "dock")
	want(t, found, "reservation_no_mac", "10.20.0.60", "scope LAN on dock keeps 10.20.0.60 for 00-00-00-00-00-00, whose hardware address is all zeros", "dock")
	want(t, found, "reservation_shared", "10.20.0.40", "10.20.0.40 is kept for 2 machines on dock: AA-00-00-00-00-05 (twin), AA-00-00-00-00-06", "dock")
	want(t, found, "reservation_leased_away", "10.20.0.50", "scope LAN on dock keeps 10.20.0.50 for AA-00-00-00-00-07 (printer), and AA-00-00-00-00-99 (guest.lan.example) holds a lease on it until 2026-10-10T17:52:51Z", "dock")
	want(t, found, "reservation_no_record", "nas.lan.example", "scope LAN on dock keeps 10.20.0.30 for AA-00-00-00-00-02 (nas), and nas.lan.example has no address record on dock", "dock")
	want(t, found, "reservation_no_record", "10.20.0.40", "no record on dock names that address", "dock")
	want(t, found, "reservation_record_elsewhere", "dock.lan.example", "scope LAN on dock keeps 10.20.0.22 for AA-00-00-00-00-03 (dock), and dock.lan.example holds 10.20.0.2", "dock")
	none(t, found, "reservation_no_record", "emby.lan.example")
	none(t, found, "reservation_no_record", "printer.lan.example")

	// records made by hand against what the scope gives out
	want(t, found, "static_in_pool", "fixed.lan.example", "fixed.lan.example holds 10.20.0.110 by a record made by hand, and scope LAN on dock leases from 10.20.0.100-10.20.0.119", "dock")
	want(t, found, "address_leased_elsewhere", "static.lan.example", "static.lan.example holds 10.20.0.102 by a record made by hand, and scope LAN on dock has leased that address to AA-00-00-00-00-12 until 2026-10-10T17:52:51Z", "dock")
	want(t, found, "lease_name_taken", "phone.lan.example", "AA-00-00-00-00-11 on dock is leased 10.20.0.101 under the name phone.lan.example, which a record made by hand holds for 10.20.0.77", "dock")
	// an address in the part of the range left out, the server's own record of a lease, and an address outside the range
	none(t, found, "static_in_pool", "excl.lan.example")
	none(t, found, "static_in_pool", "laptop.lan.example")
	none(t, found, "static_in_pool", "phone.lan.example")
	none(t, found, "static_in_pool", "static.lan.example")

	// the server's own records, outliving what they were written for
	want(t, found, "record_left_behind", "gone.lan.example", "A 10.20.0.105 at gone.lan.example was written by the DHCP scope LAN on dock, which has no lease and no reservation for 10.20.0.105 now", "dock")
	want(t, found, "record_left_behind", "old.lan.example", "A 10.20.0.200 at old.lan.example was written by the DHCP scope Old on dock, which is gone", "dock")
	none(t, found, "record_left_behind", "laptop.lan.example")
	none(t, found, "record_left_behind", "emby.lan.example")

	// one server alone leases
	alone := slices.IndexFunc(found, func(f map[string]any) bool { return f["problem"] == "dhcp_one_server" })
	if alone < 0 || !strings.Contains(acctest.Str(found[alone]["detail"]), "dock alone leases addresses, and rpi has no scope switched on") || !slices.Equal(acctest.Texts(found[alone]["servers"]), []string{"dock"}) || acctest.Str(found[alone]["fix"]) == "" {
		t.Errorf("one server leasing alone = %v", found)
	}
	counts := acctest.Object(t, out["counts"], "counts")
	for problem, n := range map[string]int{"dhcp_one_server": 1, "ranges_overlap": 0, "pool_low": 1, "scope_domain_unknown": 1, "scope_dns_unknown": 1, "scope_dns_same": 1, "scope_dns_missing": 2, "reservation_outside": 1, "reservation_no_mac": 1, "reservation_shared": 1, "reservation_leased_away": 1, "reservation_record_elsewhere": 1, "static_in_pool": 1, "address_leased_elsewhere": 1, "lease_name_taken": 1, "record_left_behind": 2} {
		if acctest.NumOr0(counts[problem]) != n {
			t.Errorf("%d %s, want %d: %v", acctest.NumOr0(counts[problem]), problem, n, found)
		}
	}
	if out["note"] != nil {
		t.Errorf("note = %v", out["note"])
	}

	// one zone's, and one server's: asked alone, a server is not said to lease alone
	if in := suite.Call(t, "audit_dhcp", map[string]any{"zone": "lan.example", "problems": []string{"static_in_pool", "pool_low"}}); acctest.Num(t, in["total"], "total") != 1 {
		t.Errorf("one zone's = %v", in)
	}
	if one := auditFindings(t, suite, "audit_dhcp", map[string]any{"server": "dock", "problems": []string{"dhcp_one_server", "scope_dns_missing", "pool_low"}}); len(one) != 1 || one[0]["problem"] != "pool_low" || one[0]["servers"] != nil {
		t.Errorf("dock alone = %v", one)
	}

	// a scope on every interface says this server with no address: one of the server's own beside it is the same server twice
	p.dock.Answer("dhcp/scopes/list", `{"scopes":[`+defaultScopeListed+`,`+lanScopeListed+`,`+strings.Replace(labScopeListed, `"interfaceAddress":"10.20.5.2"`, `"interfaceAddress":"0.0.0.0"`, 1)+`]}`)
	p.dock.AnswerWhen("dhcp/scopes/get", "name", "Lab", scopeJSON("Lab", "10.20.5.10", "10.20.5.19", `"domainName":"lab.example","dnsUpdates":false,"useThisDnsServer":true,"dnsServers":["10.20.0.2"]`))
	if same := auditFindings(t, suite, "audit_dhcp", map[string]any{"server": "dock", "problems": []string{"scope_dns_same"}}); len(same) != 1 || !strings.Contains(acctest.Str(same[0]["detail"]), "scope Lab on dock tells machines to resolve through 10.20.0.2 twice") {
		t.Errorf("this server on every interface beside its own address = %v", same)
	}

	// both leasing, over addresses they share
	p.rpi.Answer("dhcp/scopes/list", `{"scopes":[`+strings.ReplaceAll(strings.ReplaceAll(lanScopeListed, "10.20.0.100", "10.20.0.110"), "10.20.0.119", "10.20.0.130")+`]}`)
	p.rpi.Answer("dhcp/scopes/get", scopeJSON("LAN", "10.20.0.110", "10.20.0.130", `"useThisDnsServer":true`))
	both := auditFindings(t, suite, "audit_dhcp", map[string]any{"problems": []string{"dhcp_one_server", "ranges_overlap"}})
	want(t, both, "ranges_overlap", "LAN", "dock (scope LAN) and rpi (scope LAN) both lease 10.20.0.110-10.20.0.117, and neither knows what the other has given", "dock", "rpi")
	if len(both) != 1 {
		t.Errorf("both leasing = %v, want the one overlap", both)
	}

	// a server whose DHCP will not be read is said, and the other's audited
	p.rpi.Fail("dhcp/scopes/list", "error", "Access was denied.")
	denied := suite.Call(t, "audit_dhcp", nil)
	if said := acctest.Str(denied["note"]); !strings.Contains(said, "the DHCP of rpi could not be read, so none of it was audited: dhcp/scopes/list: Access was denied.") || acctest.NumOr0(acctest.Object(t, denied["counts"], "counts")["pool_low"]) != 1 || acctest.NumOr0(acctest.Object(t, denied["counts"], "counts")["dhcp_one_server"]) != 0 {
		t.Errorf("with rpi's DHCP unread = %v", denied)
	}
	if said := acctest.Str(suite.Call(t, "audit_all", nil)["note"]); !strings.Contains(said, "the DHCP of rpi could not be read") {
		t.Errorf("audit_all with rpi's DHCP unread says %q", said)
	}
}

// audit_blocking reads each server's blocking and its own two lists, and
// finds what blocks nothing and where the servers do not block alike.
func TestAuditBlocking(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	suite := p.session(t, Options{})
	out := suite.Call(t, "audit_blocking", nil)
	found := acctest.Rows(t, out["findings"], "findings")

	// the lists dock fetches: overdue, and holding nothing
	lists := func(problem, says string, servers ...string) {
		t.Helper()
		i := slices.IndexFunc(found, func(f map[string]any) bool {
			return f["problem"] == problem && strings.Contains(acctest.Str(f["detail"]), says)
		})
		if i < 0 || !slices.Equal(acctest.Texts(found[i]["servers"]), servers) || acctest.Str(found[i]["fix"]) == "" {
			t.Errorf("no %s saying %q on %v among %v", problem, says, servers, found)
		}
	}
	lists("lists_not_fetched", "the block lists were due to be fetched at 2020-01-01T00:00:00Z and have not been", "dock")
	lists("lists_empty", "the 1 block lists fetched hold no names between them: none has loaded, so nothing of theirs is blocked. The lists: https://lists.example.org/ads.txt", "dock")
	// rpi has blocking off, with a list and a name it would block
	lists("blocking_off", "blocking is switched off, with 1 lists to fetch and 1 names on the blocked list: none of it is blocked", "rpi")

	// the entries that do nothing
	want(t, found, "entry_never_applies", "emby.van.example.com", "emby.van.example.com is on the blocked list, and the zone van.example.com, held here, answers for the name before any list is looked at", "dock")
	want(t, found, "entry_never_applies", "ads.blocked.test", "the server answers for every name under .test itself", "dock")
	want(t, found, "entry_overridden", "good.example.org", "good.example.org is on the blocked list and example.org on the allowed list, which wins", "dock")
	want(t, found, "entry_redundant", "x.ads.example.net", "x.ads.example.net is on the blocked list with ads.example.net above it", "dock")
	want(t, found, "entry_redundant", "www.example.org", "www.example.org is on the allowed list with example.org above it", "dock")
	none(t, found, "entry_redundant", "ads.example.net")
	none(t, found, "entry_never_applies", "ads.example.net")

	// the two against each other
	lists("blocking_differs", "dock has blocking on and rpi has it off: a name one refuses the other resolves", "dock", "rpi")
	lists("blocking_differs", "dock fetches 2 block lists and rpi 1, and they are not the same lists", "dock", "rpi")
	lists("blocking_differs", "4 names are on the blocked list of one of dock and rpi and not the other: emby.van.example.com (dock alone)", "dock", "rpi")
	lists("blocking_differs", "2 names are on the allowed list of one of dock and rpi and not the other", "dock", "rpi")

	counts := acctest.Object(t, out["counts"], "counts")
	for problem, n := range map[string]int{"blocking_off": 1, "blocking_paused": 0, "lists_not_fetched": 1, "lists_empty": 1, "entry_never_applies": 2, "entry_overridden": 1, "entry_redundant": 2, "blocking_differs": 4} {
		if acctest.NumOr0(counts[problem]) != n {
			t.Errorf("%d %s, want %d: %v", acctest.NumOr0(counts[problem]), problem, n, found)
		}
	}
	if out["note"] != nil {
		t.Errorf("note = %v", out["note"])
	}

	// one server alone has nothing to differ from; and a pause is said as one, with when it ends
	p.rpi.Answer("settings/get", `{"enableBlocking":false,"blockListUrls":[],"temporaryDisableBlockingTill":"2099-01-01T00:00:00Z"}`)
	alone := auditFindings(t, suite, "audit_blocking", map[string]any{"server": "rpi"})
	if len(alone) != 1 || alone[0]["problem"] != "blocking_paused" || alone[0]["detail"] != "blocking is paused until 2099-01-01T00:00:00Z: nothing is blocked till then" || alone[0]["servers"] != nil {
		t.Errorf("rpi alone, paused = %v", alone)
	}

	// a dashboard that may not be read leaves what the lists hold unsaid, not said to be nothing
	p.dock.Fail("dashboard/stats/get", "error", "Access was denied.")
	if got := auditFindings(t, suite, "audit_blocking", map[string]any{"server": "dock", "problems": []string{"lists_empty", "lists_not_fetched"}}); len(got) != 1 || got[0]["problem"] != "lists_not_fetched" {
		t.Errorf("with the dashboard refused = %v", got)
	}
	// lists not fetched since they were set are due at the server's never and a day, which is no time
	p.dock.Answer("settings/get", `{"enableBlocking":true,"blockListUrls":["https://lists.example.org/ads.txt"],"blockListUpdateIntervalHours":24,"blockListNextUpdatedOn":"0001-01-02T00:00:00"}`)
	if got := auditFindings(t, suite, "audit_blocking", map[string]any{"server": "dock", "problems": []string{"lists_not_fetched"}}); len(got) != 1 || !strings.Contains(acctest.Str(got[0]["detail"]), "the block lists have not been fetched since they were set") {
		t.Errorf("lists never fetched = %v", got)
	}
	// a server whose blocking will not be read is said, and the other's audited
	p.rpi.Fail("blocked/export", "error", "Access was denied.")
	denied := suite.Call(t, "audit_blocking", nil)
	if said := acctest.Str(denied["note"]); !strings.Contains(said, "the blocking of rpi could not be read, so none of it was audited: blocked/export: Access was denied.") || acctest.NumOr0(acctest.Object(t, denied["counts"], "counts")["blocking_differs"]) != 0 || acctest.NumOr0(acctest.Object(t, denied["counts"], "counts")["entry_overridden"]) != 1 {
		t.Errorf("with rpi's blocking unread = %v", denied)
	}
}

// audit_zones holds each zone's NS and SOA records and its options against
// the servers that hold it and what each calls itself.
func TestAuditZones(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	suite := p.session(t, Options{})
	out := suite.Call(t, "audit_zones", map[string]any{"limit": 100})
	found := acctest.Rows(t, out["findings"], "findings")
	has := func(problem, zone, says string, servers ...string) {
		t.Helper()
		i := slices.IndexFunc(found, func(f map[string]any) bool {
			return f["problem"] == problem && f["zone"] == zone && slices.Equal(acctest.Texts(f["servers"]), servers)
		})
		if i < 0 || !strings.Contains(acctest.Str(found[i]["detail"]), says) || acctest.Str(found[i]["fix"]) == "" {
			t.Errorf("no %s for %s on %v saying %q among %v", problem, zone, servers, says, found)
		}
	}

	// the zone each holds as its own names a name server that is neither, and not itself
	has("ns_unknown", "example.com", "example.com names dock.elsewhere.net as a name server of its own, which is the name of no server asked", "dock")
	has("ns_unknown", "example.com", "dock.elsewhere.net", "rpi")
	// a node of the cluster that is not configured here is a server all the same
	none(t, found, "ns_unknown", "van.example.com")
	has("ns_missing", "example.com", "dock holds example.com as its primary and calls itself dock, which none of the zone's NS records names: they name dock.elsewhere.net", "dock")
	has("ns_missing", "example.com", "rpi holds example.com as its primary and calls itself rpi", "rpi")
	// a zone made when the server had another name
	has("soa_primary", "off.example", "the SOA record of off.example names oldname as the zone's primary, and the server that holds it as its primary calls itself dock", "dock")
	// rpi's zone, which dock holds a copy of: rpi gives it to nobody and tells nobody, and names no name server at all
	has("transfer_denied", "copy.example", "rpi lets nobody transfer copy.example, and dock holds a copy of it", "rpi")
	has("notify_none", "copy.example", "rpi tells nobody when copy.example changes, and dock holds a copy of it", "rpi")
	has("ns_missing", "copy.example", "dock holds a copy of copy.example and calls itself dock, which none of the zone's NS records names: they name none", "dock")

	counts := acctest.Object(t, out["counts"], "counts")
	// a primary with no copy among the servers asked may keep its zone to itself
	if acctest.NumOr0(counts["ns_unknown"]) != 2 || acctest.NumOr0(counts["soa_primary"]) != 1 || acctest.NumOr0(counts["transfer_denied"]) != 1 || acctest.NumOr0(counts["notify_none"]) != 1 || out["note"] != nil {
		t.Errorf("counts = %v, note = %v", counts, out["note"])
	}
	// zones that name nothing wrong: lan.example's SOA names dock, and the reverse zone has none to name wrongly
	for _, f := range found {
		if f["problem"] == "soa_primary" && f["zone"] != "off.example" {
			t.Errorf("a primary nothing is wrong with is found: %v", f)
		}
	}

	// options that will not be read are said, and the records still audited
	p.rpi.Fail("zones/options/get", "error", "Access was denied.")
	p.rpi.FailWhen("zones/options/get", "zone", "copy.example", "error", "Access was denied.")
	denied := suite.Call(t, "audit_zones", map[string]any{"problems": []string{"transfer_denied", "ns_unknown"}})
	if said := acctest.Str(denied["note"]); !strings.Contains(said, "rpi would not give the options of example.com (zones/options/get: Access was denied.), the options of copy.example") || acctest.NumOr0(acctest.Object(t, denied["counts"], "counts")["transfer_denied"]) != 0 || acctest.NumOr0(acctest.Object(t, denied["counts"], "counts")["ns_unknown"]) != 2 {
		t.Errorf("with rpi's options unread = %v", denied)
	}
	// a server that will not say what it calls itself is said, and left out
	p.rpi.Fail("status", "error", "boom")
	gone := suite.Call(t, "audit_zones", nil)
	if said := acctest.Str(gone["note"]); !strings.Contains(said, "rpi would not say what it calls itself, so how it serves its zones was not audited: status: boom") || acctest.NumOr0(acctest.Object(t, gone["counts"], "counts")["transfer_denied"]) != 0 {
		t.Errorf("with rpi unread = %v", gone)
	}
}

// audit_security reads each server's settings, sessions and zone options
// for what is left open.
// Reverse zones of the wrong shape: one address each where no zone holds
// the network, and one with no PTR in it.
func TestAuditReverseZoneShapes(t *testing.T) {
	t.Parallel()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"162.16.16.172.in-addr.arpa","type":"Primary","soaSerial":1},{"name":"163.16.16.172.in-addr.arpa","type":"Primary","soaSerial":1},{"name":"170.16.16.172.in-addr.arpa","type":"Primary","soaSerial":1},{"name":"5.0.10.in-addr.arpa","type":"Primary","soaSerial":1},{"name":"9.9.10.in-addr.arpa","type":"Primary","soaSerial":1},{"name":"1.9.9.10.in-addr.arpa","type":"Primary","soaSerial":1},{"name":"2.9.9.10.in-addr.arpa","type":"Primary","soaSerial":1}]}`)
	p.rpi.Answer("zones/list", `{"zones":[]}`)
	p.both("status", `{"hasDefaultCredentials":false,"ssoEnabled":false,"server":"dock","status":"ok"}`)
	p.both("admin/cluster/state", `{"clusterInitialized":false,"dnsServerDomain":"dock","version":"15.6"}`)
	p.both("zones/options/get", `{"type":"Primary","queryAccess":"Allow","zoneTransfer":"Deny","notify":"None","update":"Deny"}`)
	zoneOf(p, false, "162.16.16.172.in-addr.arpa", ptr("162.16.16.172.in-addr.arpa", "mac.guest.example"))
	zoneOf(p, false, "163.16.16.172.in-addr.arpa", ptr("163.16.16.172.in-addr.arpa", "phone.guest.example"))
	zoneOf(p, false, "170.16.16.172.in-addr.arpa", rec("170.16.16.172.in-addr.arpa", "SOA", `{"primaryNameServer":"dock","serial":1}`))
	zoneOf(p, false, "5.0.10.in-addr.arpa", ptr("1.5.0.10.in-addr.arpa", "iot.example"))
	// a /24 held beside zones of one address under it is what the server writes into: those are not the finding
	zoneOf(p, false, "9.9.10.in-addr.arpa", ptr("3.9.9.10.in-addr.arpa", "a.example"))
	zoneOf(p, false, "1.9.9.10.in-addr.arpa", ptr("1.9.9.10.in-addr.arpa", "b.example"))
	zoneOf(p, false, "2.9.9.10.in-addr.arpa", ptr("2.9.9.10.in-addr.arpa", "c.example"))
	suite := p.session(t, Options{})
	found := auditFindings(t, suite, "audit_zones", map[string]any{"server": "dock", "problems": []string{"reverse_zone_per_address", "reverse_zone_empty"}})

	want(t, found, "reverse_zone_per_address", "16.16.172.in-addr.arpa", "3 reverse zones each hold one address of 172.16.16.0/24 (162, 163, 170) and no zone holds the network")
	want(t, found, "reverse_zone_empty", "170.16.16.172.in-addr.arpa", "the reverse zone 170.16.16.172.in-addr.arpa holds no PTR record")
	none(t, found, "reverse_zone_empty", "5.0.10.in-addr.arpa")
	none(t, found, "reverse_zone_per_address", "9.9.10.in-addr.arpa")
	if len(found) != 2 {
		t.Errorf("%d findings, want the two: %v", len(found), found)
	}
	if fix := found[slices.IndexFunc(found, func(f map[string]any) bool { return f["problem"] == "reverse_zone_per_address" })]["fix"]; !strings.HasPrefix(acctest.Str(fix), "make the zone 16.16.172.in-addr.arpa (zone_create)") {
		t.Errorf("the fix = %q", fix)
	}
}

func TestAuditSecurity(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	suite := p.session(t, Options{})
	out := suite.Call(t, "audit_security", nil)
	found := acctest.Rows(t, out["findings"], "findings")
	has := func(problem, at, says string, servers ...string) {
		t.Helper()
		i := slices.IndexFunc(found, func(f map[string]any) bool {
			return f["problem"] == problem && (at == "" || f["name"] == at) && slices.Equal(acctest.Texts(f["servers"]), servers)
		})
		if i < 0 || !strings.Contains(acctest.Str(found[i]["detail"]), says) || acctest.Str(found[i]["fix"]) == "" {
			t.Errorf("no %s at %q on %v saying %q among %v", problem, at, servers, says, found)
		}
	}

	has("default_password", "", "the admin account still has the password the server ships with", "rpi")
	has("recursion_open", "", "the server resolves any name for anyone who can reach it", "rpi")
	has("console_plain", "", "answer over plain HTTP alone", "rpi")
	has("update_available", "", "version 15.7 is out and the server runs 15.6", "dock")
	has("token_unused", "old-script", `the API token "old-script" of kt was last used on 2025-01-01`, "dock")
	has("transfer_open", "example.com", "anyone who can reach the server may transfer example.com whole", "dock")
	has("update_open", "example.com", "anyone who can reach the server may change the records of example.com by a DNS update, with no key asked for", "dock")
	has("update_open", "van.example.com", "from an address that is allowed (UseSpecifiedNetworkACL), with no key asked for", "dock")

	counts := acctest.Object(t, out["counts"], "counts")
	// the token that asked is in use, a console session is no token, a zone changed only with a key is closed, and a copy's options are its primary's to set
	for problem, n := range map[string]int{"default_password": 1, "recursion_open": 1, "console_plain": 1, "update_available": 1, "token_unused": 1, "transfer_open": 1, "update_open": 2} {
		if acctest.NumOr0(counts[problem]) != n {
			t.Errorf("%d %s, want %d: %v", acctest.NumOr0(counts[problem]), problem, n, found)
		}
	}
	// what a server would not give is said: nothing was found there because nothing was looked at
	if said := acctest.Str(out["note"]); !strings.Contains(said, "rpi would not give its sessions and tokens (admin/sessions/list: Access was denied.)") || strings.Contains(said, "checkForUpdate") {
		t.Errorf("note = %q", said)
	}

	// what both have is said once, of both
	p.dock.Answer("settings/get", `{"recursion":"Allow","webServiceEnableTls":false}`)
	both := auditFindings(t, suite, "audit_security", map[string]any{"problems": []string{"recursion_open", "console_plain"}})
	if len(both) != 2 || both[0]["servers"] != nil || both[1]["servers"] != nil {
		t.Errorf("what both leave open = %v", both)
	}
}

func TestAuditCluster(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	suite := p.session(t, Options{})
	found := auditFindings(t, suite, "audit_cluster", nil)

	want(t, found, "node_unreachable", "rpi.cluster.example", "dock cannot reach the node rpi.cluster.example of the cluster cluster.example, which it last heard from at 2020-01-01T00:00:00Z", "dock")
	want(t, found, "node_not_configured", "ns3.cluster.example", "is not among the servers configured here")
	want(t, found, "versions_differ", "cluster.example", "run different versions of the server: 15.5, 15.6")
	want(t, found, "config_stale", "rpi.cluster.example", "rpi last fetched the primary's configuration at 2020-01-01T00:00:00Z, and is set to every 900 seconds", "rpi")
	want(t, found, "nodes_disagree", "cluster.example", "dock list dock.cluster.example, ns3.cluster.example, rpi.cluster.example; rpi list dock.cluster.example, rpi.cluster.example")
	none(t, found, "single_node", "cluster.example")
	none(t, found, "outside_cluster", "cluster.example")
	if len(found) != 5 {
		t.Errorf("%d findings, want the five: %v", len(found), found)
	}

	// a cluster of one, and a server outside it
	p.rpi.Answer("admin/cluster/state", `{"clusterInitialized":false,"dnsServerDomain":"rpi","version":"15.6"}`)
	p.dock.Answer("admin/cluster/state", `{"clusterInitialized":true,"dnsServerDomain":"dock.cluster.example","version":"15.6","clusterDomain":"cluster.example","configRefreshIntervalSeconds":900,"clusterNodes":[`+nodeJSON(2, "dock", "Primary", "Self", "15.6")+`]}`)
	found = auditFindings(t, suite, "audit_cluster", nil)
	want(t, found, "single_node", "cluster.example", "has one node, its primary dock.cluster.example", "dock")
	want(t, found, "outside_cluster", "cluster.example", "dock are in the cluster cluster.example and rpi in none", "rpi")
	if len(found) != 2 {
		t.Errorf("%d findings, want the two: %v", len(found), found)
	}
	p.dock.Answer("admin/cluster/state", `{"clusterInitialized":true,"dnsServerDomain":"dock.cluster.example","version":"15.6","clusterDomain":"cluster.example","configRefreshIntervalSeconds":900,"clusterNodes":[`+nodeJSON(2, "dock", "Secondary", "Self", "15.6")+`,`+nodeJSON(3, "rpi", "Primary", "Connected", "15.6")+`]}`)
	p.rpi.Answer("admin/cluster/state", `{"clusterInitialized":true,"dnsServerDomain":"rpi.cluster.example","version":"15.6","clusterDomain":"cluster.example","clusterNodes":[`+nodeJSON(2, "dock", "Secondary", "Connected", "15.6")+`,`+nodeJSON(3, "rpi", "Primary", "Self", "15.6")+`]}`)
	// a secondary that gives no time it last fetched has only just joined, and is not said to be behind
	if found = auditFindings(t, suite, "audit_cluster", nil); len(found) != 0 {
		t.Errorf("a secondary that has only just joined: %v", found)
	}

	// servers in no cluster have nothing to find; one that cannot say is said
	p.both("admin/cluster/state", `{"clusterInitialized":false,"dnsServerDomain":"dock","version":"15.6"}`)
	if found = auditFindings(t, suite, "audit_cluster", nil); len(found) != 0 {
		t.Errorf("servers in no cluster: %v", found)
	}
	p.rpi.Fail("admin/cluster/state", "error", "Access was denied.")
	if got := suite.Call(t, "audit_cluster", nil); len(acctest.Rows(t, got["findings"], "findings")) != 0 {
		t.Errorf("a server that will not say how it stands = %v", got)
	}
}

func TestAuditAccess(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	suite := p.session(t, Options{})
	out := suite.Call(t, "audit_access", nil)
	found := acctest.Rows(t, out["findings"], "findings")

	want(t, found, "admin_no_two_factor", "admin", "the administrator admin signs in with a password alone", "dock")
	want(t, found, "account_never_used", "never", "has never signed in and has no token", "dock")
	want(t, found, "disabled_with_tokens", "off", "is switched off and still has 1 API tokens", "dock")
	want(t, found, "everyone_may_change", "Cache", "every account, whatever its groups, may modify in Cache", "dock")
	// the account the server ships with, on beside another administrator
	want(t, found, "stock_admin", "admin", "the account admin, which every server ships with and which whoever tries the console tries first, is switched on beside careful", "dock")
	none(t, found, "admin_no_two_factor", "careful")
	none(t, found, "everyone_may_change", "Zones")
	if len(found) != 5 {
		t.Errorf("%d findings, want the five: %v", len(found), found)
	}
	// what a server will not give is said beside the findings
	if !strings.Contains(acctest.Str(out["note"]), "rpi would not give its accounts (admin/users/list: Access was denied.)") {
		t.Errorf("note = %v", out["note"])
	}
}

func TestAuditDNSSEC(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	suite := p.session(t, Options{})
	found := auditFindings(t, suite, "audit_dnssec", nil)

	want(t, found, "nsec_walkable", "van.example.com", "lets anyone list every name the zone has", "dock")
	want(t, found, "ds_wanted_at_parent", "van.example.com", "the key signing key 11 of van.example.com is ready and waits for its DS record", "dock")
	want(t, found, "key_not_published", "van.example.com", "the ZoneSigningKey 33 of van.example.com was made on 2026-09-01T00:00:00Z and has never been put in the zone", "dock")
	want(t, found, "key_never_replaced", "van.example.com", "the zone signing key 22 of van.example.com is in use and is never replaced", "dock")
	want(t, found, "weak_algorithm", "van.example.com", "the ZoneSigningKey 44 of van.example.com signs with RSASHA1", "dock")
	want(t, found, "signature_expired", "van.example.com", "1 signatures in van.example.com on dock are past their expiration, the oldest since 2020-01-01T00:00:00Z", "dock")
	if len(found) != 6 {
		t.Errorf("%d findings, want the six: %v", len(found), found)
	}
	// the zones were listed once, and the keys read once for the one that is signed
	if len(p.dock.Requests("zones/list")) != 1 || len(p.dock.Requests("zones/dnssec/properties/get")) != 1 || len(p.rpi.Requests("zones/dnssec/properties/get")) != 0 {
		t.Errorf("dock's zones were listed %d times and its keys read %d", len(p.dock.Requests("zones/list")), len(p.dock.Requests("zones/dnssec/properties/get")))
	}

	// keys that will not be read are said, and nothing is found there
	p.dock.Fail("zones/dnssec/properties/get", "error", "Access was denied.")
	// what the zone's own records say, the expired signature, is found all the same
	if out := suite.Call(t, "audit_dnssec", nil); acctest.Num(t, out["total"], "total") != 1 || acctest.NumOr0(acctest.Object(t, out["counts"], "counts")["signature_expired"]) != 1 || !strings.Contains(acctest.Str(out["note"]), "dock would not give the keys of van.example.com") {
		t.Errorf("keys that would not be read = %v", out)
	}
}

func TestAuditQueries(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	// dock sends what it does not know to four forwarders: one that answers at once, one that is not there, one that takes its time and one that fails
	answered := func(took, result string) string {
		return `{"result":{"Metadata":{"NameServer":"a forwarder","RoundTripTime":"` + took + `"},"RCODE":"` + result + `","Answer":[]}}`
	}
	p.dock.Answer("settings/get", `{"forwarders":["10.0.0.53","10.0.0.54","10.0.0.55","10.0.0.56"],"forwarderProtocol":"Tcp"}`)
	p.dock.AnswerWhen("dnsClient/resolve", "server", "10.0.0.53", answered("12.5 ms", "NoError"))
	p.dock.FailWhen("dnsClient/resolve", "server", "10.0.0.54", "error", "DnsClient failed to resolve the request '. NS IN': request timed out for name server [10.0.0.54].")
	p.dock.AnswerWhen("dnsClient/resolve", "server", "10.0.0.55", answered("812.4 ms", "NoError"))
	p.dock.AnswerWhen("dnsClient/resolve", "server", "10.0.0.56", answered("20 ms", "ServerFailure"))
	suite := p.session(t, Options{})
	found := auditFindings(t, suite, "audit_queries", nil)

	// each forwarder is asked for the root's name servers, which every resolver knows, the way the server asks its forwarders
	asked := p.dock.Requests("dnsClient/resolve")
	if len(asked) != 4 || asked[0].Params.Get("domain") != "." || asked[0].Params.Get("type") != "NS" || asked[0].Params.Get("protocol") != "Tcp" || len(p.rpi.Requests("dnsClient/resolve")) != 0 {
		t.Errorf("the forwarders were asked with %v", asked)
	}
	want(t, found, "forwarder_unanswering", "10.0.0.54", "the forwarder 10.0.0.54 gave the server no answer when it was asked for the root's name servers, which every resolver knows: dnsClient/resolve: DnsClient failed to resolve the request", "dock")
	want(t, found, "forwarder_slow", "10.0.0.55", "the forwarder 10.0.0.55 took 812ms to answer the server", "dock")
	want(t, found, "forwarder_failing", "10.0.0.56", "the forwarder 10.0.0.56 answered ServerFailure", "dock")
	none(t, found, "forwarder_slow", "10.0.0.53")

	// what is a server's own and at no name
	own := func(problem, says, server string) {
		t.Helper()
		i := slices.IndexFunc(found, func(f map[string]any) bool { return f["problem"] == problem })
		if i < 0 || !strings.Contains(acctest.Str(found[i]["detail"]), says) || !slices.Equal(acctest.Texts(found[i]["servers"]), []string{server}) || found[i]["fix"] == nil {
			t.Errorf("%s on %s saying %q is not among %v", problem, server, says, found)
		}
	}
	own("not_resolving", "could not resolve a name for itself just now: dnsClient/healthCheck: DNS Server failed to resolve the request.", "rpi")
	own("no_query_log", "no app on the server keeps a log of queries", "rpi")
	own("failing", "200 of the last day's 2000 queries were answered with a server failure, 10 in every hundred", "dock")
	want(t, found, "one_client", "10.0.0.50", "10.0.0.50 (busy.van.example.com) asked 1500 of the last day's 2000 queries, 75 in every hundred", "dock")
	// a name asked for often that is under a zone the servers hold; one asked for twice and one under nobody's zone are not said
	want(t, found, "name_not_found", "nothing.van.example.com", "nothing.van.example.com was asked for 6 times in the last day and does not exist in van.example.com")
	none(t, found, "name_not_found", "rare.example.com")
	none(t, found, "name_not_found", "elsewhere.example.net")
	// a busy client with no name, and not a quiet one; a name of the servers' own asked for far beyond its TTL, and not one asked for little or one that is not theirs
	want(t, found, "client_unnamed", "10.0.0.51", "10.0.0.51 asked 1000 queries in the last day and has no name", "dock")
	none(t, found, "client_unnamed", "10.0.0.52")
	want(t, found, "client_not_caching", "emby.van.example.com", "emby.van.example.com was asked for 1200 times in the last day, where its TTL of 3600 seconds lets a client that caches ask 24 times", "dock")
	none(t, found, "client_not_caching", "dock.van.example.com")
	none(t, found, "client_not_caching", "www.example.org")
	if len(found) != 10 {
		t.Errorf("%d findings, want the ten: %v", len(found), found)
	}
	if asked := p.dock.Last("logs/query"); asked.Params.Get("rcode") != "NxDomain" || asked.Params.Get("entriesPerPage") != "2000" || asked.Params.Get("start") == "" {
		t.Errorf("the log was asked with %v", asked.Params)
	}

	// one zone's: the name asked for that is not there, and the one asked for too often
	if got := auditFindings(t, suite, "audit_queries", map[string]any{"zone": "van.example.com"}); len(got) != 2 || got[0]["problem"] != "client_not_caching" || got[1]["problem"] != "name_not_found" {
		t.Errorf("one zone's = %v", got)
	}
}

func TestAuditApps(t *testing.T) {
	t.Parallel()

	p := auditPair(t)
	suite := p.session(t, Options{})
	found := auditFindings(t, suite, "audit_apps", nil)

	want(t, found, "app_update", "Split Horizon", "the app Split Horizon is installed at version 1.0 and the store has 1.1", "dock")
	want(t, found, "app_only_on", "Split Horizon", "the app Split Horizon is installed on dock and not on rpi", "dock")
	want(t, found, "app_only_on", "Query Logs (Sqlite)", "is installed on dock and not on rpi", "dock")
	if len(found) != 3 {
		t.Errorf("%d findings, want the three: %v", len(found), found)
	}

	// both run it, a version apart and configured differently; a store that cannot be asked says nothing is behind
	p.rpi.Answer("apps/list", `{"apps":[`+appJSON("Query Logs (Sqlite)", "7", true)+`,`+appJSON("Split Horizon", "1.0", false)+`]}`)
	p.rpi.Answer("apps/config/get", `{"config":"{\"enableLogging\":true,\"maxLogDays\":30}"}`)
	found = auditFindings(t, suite, "audit_apps", nil)
	want(t, found, "app_versions_differ", "Query Logs (Sqlite)", "dock has 8, rpi has 7")
	want(t, found, "app_config_differs", "Query Logs (Sqlite)", "is not configured alike on every server")
	want(t, found, "app_config_differs", "Split Horizon", "is not configured alike on every server")
	want(t, found, "app_update", "Split Horizon", "the store has 1.1", "dock")
	none(t, found, "app_only_on", "Split Horizon")
	if len(found) != 4 {
		t.Errorf("%d findings, want the four: %v", len(found), found)
	}

	// one server has nobody to differ from
	if alone := auditFindings(t, suite, "audit_apps", map[string]any{"server": "rpi"}); len(alone) != 0 {
		t.Errorf("rpi alone, which cannot ask the store = %v", alone)
	}
}
