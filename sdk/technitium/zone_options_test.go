package technitium_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

func TestZoneOptions(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	// a primary as the document shows one, and a cluster's copy as a 15.6 server gave it
	fake.Answer("zones/options/get", `{"name":"example.com","type":"Primary","internal":false,"dnssecStatus":"Unsigned","notifyFailed":true,"notifyFailedFor":["192.168.10.5"],"disabled":false,"catalog":"catalog1","queryAccess":"Allow","queryAccessNetworkACL":[],"zoneTransfer":"AllowOnlyZoneNameServers","zoneTransferNetworkACL":["10.0.0.0/24"],"zoneTransferTsigKeyNames":["key.example.com"],"notify":"ZoneNameServers","notifyNameServers":[],"update":"UseSpecifiedNetworkACL","updateNetworkACL":["192.168.180.0/24"],"updateSecurityPolicies":[{"tsigKeyName":"key.example.com","domain":"*.example.com","allowedTypes":["A","AAAA"]}],"availableCatalogZoneNames":["catalog1"]}`)
	fake.AnswerWhen("zones/options/get", "zone", "copy.example.com", `{"name":"copy.example.com","type":"Secondary","disabled":false,"catalog":"catalog1","primaryNameServerAddresses":["10.0.0.2"],"primaryZoneTransferProtocol":"Tls","primaryZoneTransferTsigKeyName":"catalog1","queryAccess":"Allow","zoneTransfer":"Deny","notify":"None","update":"Deny"}`)
	fake.Answer("zones/options/set", `{}`)
	fake.AnswerText("zones/export", "$ORIGIN example.com.\n@   900   IN  SOA   dock. hostadmin 2 900 300 604800 900\na   3600  IN  A     10.3.3.3\t\t\t;a host\n")
	fake.Answer("admin/sessions/list", `{"sessions":[{"username":"admin","isCurrentSession":true,"partialToken":"4d213404705d0749","type":"ApiToken","tokenName":"technitium-mcp","lastSeen":"2026-10-10T02:57:45.5498694Z","lastSeenRemoteAddress":"10.0.0.9","lastSeenUserAgent":"technitium-mcp"},{"username":"kt","isCurrentSession":false,"partialToken":"aaaaaaaaaaaaaaaa","type":"Standard","tokenName":null,"lastSeen":"2026-10-01T00:00:00Z","lastSeenRemoteAddress":"10.0.0.7","lastSeenUserAgent":"Mozilla"}]}`)
	c := client(t, fake)

	got, err := c.ZoneOptions(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/options/get"); len(asked.Params) != 3 || asked.Params.Get("zone") != "example.com" || asked.Params.Get("includeAvailableCatalogZoneNames") != "true" || asked.Params.Get("includeAvailableTsigKeyNames") != "true" {
		t.Errorf("the options were asked for with %v", asked.Params)
	}
	if got.Name != "example.com" || got.Type != "Primary" || got.Disabled || got.Catalog != "catalog1" || got.DNSSECStatus != "Unsigned" || got.QueryAccess != "Allow" || got.ZoneTransfer != "AllowOnlyZoneNameServers" || len(got.ZoneTransferNetworkACL) != 1 || len(got.ZoneTransferTSIGKeyNames) != 1 || got.Notify != "ZoneNameServers" || !got.NotifyFailed || len(got.NotifyFailedFor) != 1 || got.Update != "UseSpecifiedNetworkACL" || len(got.UpdateNetworkACL) != 1 {
		t.Errorf("a primary's options = %+v", got)
	}
	if len(got.UpdateSecurityPolicies) != 1 || got.UpdateSecurityPolicies[0].TSIGKeyName != "key.example.com" || got.UpdateSecurityPolicies[0].Domain != "*.example.com" || len(got.UpdateSecurityPolicies[0].AllowedTypes) != 2 {
		t.Errorf("who may update it = %+v", got.UpdateSecurityPolicies)
	}
	if got, err = c.ZoneOptions(t.Context(), "copy.example.com"); err != nil || got.Type != "Secondary" || len(got.PrimaryNameServerAddresses) != 1 || got.PrimaryZoneTransferProtocol != "Tls" || got.PrimaryZoneTransferTSIGKeyName != "catalog1" || got.ZoneTransfer != technitium.PolicyDeny || got.Notify != technitium.NotifyNone {
		t.Errorf("a copy's options = %+v, %v", got, err)
	}

	// only the policies given are sent, so the rest stay as they are
	if err := c.SetZoneOptions(t.Context(), "example.com", technitium.ZoneChange{ZoneTransfer: technitium.PolicyAllow, Update: technitium.PolicyAllow}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/options/set"); asked.Method != http.MethodPost || len(asked.Params) != 3 || asked.Params.Get("zone") != "example.com" || asked.Params.Get("zoneTransfer") != "Allow" || asked.Params.Get("update") != "Allow" || asked.Params.Has("notify") {
		t.Errorf("the policies were set with %v", asked.Params)
	}
	if err := c.SetZoneOptions(t.Context(), "example.com", technitium.ZoneChange{Notify: technitium.NotifyNone}); err != nil || fake.Last("zones/options/set").Params.Get("notify") != "None" {
		t.Errorf("notify was set with %v, %v", fake.Last("zones/options/set").Params, err)
	}

	text, err := c.ExportZone(t.Context(), "example.com")
	if err != nil || !strings.HasPrefix(text, "$ORIGIN example.com.\n") || !strings.Contains(text, ";a host") || fake.Last("zones/export").Params.Get("zone") != "example.com" {
		t.Errorf("ExportZone = %q, %v", text, err)
	}
	fake.Fail("zones/export", "error", "No such zone was found: nope.example.com")
	if _, err := c.ExportZone(t.Context(), "nope.example.com"); err == nil || !strings.Contains(err.Error(), "No such zone was found") {
		t.Errorf("a zone that is not there, exported = %v", err)
	}

	sessions, err := c.Sessions(t.Context())
	if err != nil || len(sessions) != 2 {
		t.Fatalf("Sessions = %+v, %v", sessions, err)
	}
	if s := sessions[0]; s.Username != "admin" || s.Type != technitium.SessionAPIToken || s.TokenName != "technitium-mcp" || !s.IsCurrentSession || s.LastSeen == "" || s.LastSeenRemoteAddress != "10.0.0.9" || s.LastSeenUserAgent != "technitium-mcp" {
		t.Errorf("a token's session = %+v", s)
	}
	if s := sessions[1]; s.Type != "Standard" || s.TokenName != "" || s.IsCurrentSession {
		t.Errorf("a console session = %+v", s)
	}

	// what names nothing is not sent
	sent := len(fake.Requests("zones/options/get")) + len(fake.Requests("zones/options/set")) + len(fake.Requests("zones/export"))
	if _, err := c.ZoneOptions(t.Context(), ""); err == nil {
		t.Error("the options of no zone were read")
	}
	if err := c.SetZoneOptions(t.Context(), "", technitium.ZoneChange{Notify: technitium.NotifyNone}); err == nil {
		t.Error("the policies of no zone were set")
	}
	if err := c.SetZoneOptions(t.Context(), "example.com", technitium.ZoneChange{}); err == nil || !strings.Contains(err.Error(), "nothing was given to set") {
		t.Errorf("no policy at all = %v", err)
	}
	if _, err := c.ExportZone(t.Context(), ""); err == nil {
		t.Error("no zone was exported")
	}
	if now := len(fake.Requests("zones/options/get")) + len(fake.Requests("zones/options/set")) + len(fake.Requests("zones/export")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}

// A zone's options are set by what is given, a list cleared by an empty one;
// a copy is resynced; and an SOA is set whole, with what it is to keep.
func TestZoneChanges(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/options/set", `{}`)
	fake.Answer("zones/resync", `{}`)
	fake.Answer("zones/records/update", `{"updatedRecord":{"name":"example.com","type":"SOA","ttl":900,"rData":{"primaryNameServer":"dock.example.com","responsiblePerson":"kt@example.com","serial":8,"refresh":600,"retry":300,"expire":604800,"minimum":300}}}`)
	c := client(t, fake)

	if err := c.SetZoneOptions(t.Context(), "example.com", technitium.ZoneChange{Disabled: new(true), Catalog: "catalog1", QueryAccess: "AllowOnlyPrivateNetworks", ZoneTransfer: "UseSpecifiedNetworkACL", ZoneTransferNetworks: []string{"10.0.0.3", "!10.0.0.9"}, Notify: "SpecifiedNameServers", NotifyNameServers: []string{"10.0.0.3"}, UpdateNetworks: []string{}}); err != nil {
		t.Fatal(err)
	}
	asked := fake.Last("zones/options/set")
	for param, want := range map[string]string{"zone": "example.com", "disabled": "true", "catalog": "catalog1", "queryAccess": "AllowOnlyPrivateNetworks", "zoneTransfer": "UseSpecifiedNetworkACL", "zoneTransferNetworkACL": "10.0.0.3,!10.0.0.9", "notify": "SpecifiedNameServers", "notifyNameServers": "10.0.0.3", "updateNetworkACL": "false"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the options were set with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	// what was not given is not sent, so it stays as it is
	if asked.Params.Has("update") || asked.Params.Has("queryAccessNetworkACL") || len(asked.Params) != 9 {
		t.Errorf("the options were set with %v", asked.Params)
	}
	if err := c.SetZoneOptions(t.Context(), "example.com", technitium.ZoneChange{Disabled: new(false)}); err != nil || fake.Last("zones/options/set").Params.Get("disabled") != "false" {
		t.Errorf("the zone was switched on with %v, %v", fake.Last("zones/options/set").Params, err)
	}

	if err := c.ResyncZone(t.Context(), "copy.example.com"); err != nil || fake.Last("zones/resync").Params.Get("zone") != "copy.example.com" || fake.Last("zones/resync").Method != http.MethodPost {
		t.Errorf("the copy was resynced with %v, %v", fake.Last("zones/resync").Params, err)
	}
	if err := c.ResyncZone(t.Context(), ""); err == nil || len(fake.Requests("zones/resync")) != 1 {
		t.Errorf("no zone was resynced = %v", err)
	}

	// an SOA: everything it has is sent, the TTL and comment it keeps and the serial as it stands among it
	current := &technitium.Record{Name: "example.com", Type: "SOA", TTL: 900, Comments: "ours", Data: technitium.RData{"primaryNameServer": "oldname", "responsiblePerson": "hostadmin@example.com", "serial": float64(7), "refresh": float64(900), "retry": float64(300), "expire": float64(604800), "minimum": float64(900)}}
	want := current.SOA()
	want.Primary, want.Responsible, want.Refresh, want.Minimum = "dock.example.com", "kt@example.com", 600, 300
	got, err := c.UpdateSOA(t.Context(), "example.com", current, want)
	if err != nil || got.SOA().Primary != "dock.example.com" || got.SOA().Serial != 8 {
		t.Errorf("UpdateSOA = %+v, %v", got, err)
	}
	asked = fake.Last("zones/records/update")
	for param, value := range map[string]string{"zone": "example.com", "domain": "example.com", "type": "SOA", "primaryNameServer": "dock.example.com", "responsiblePerson": "kt@example.com", "serial": "7", "refresh": "600", "retry": "300", "expire": "604800", "minimum": "300", "ttl": "900", "comments": "ours", "disable": "false", "expiryTtl": "0"} {
		if asked.Params.Get(param) != value {
			t.Errorf("the SOA was set with %s=%q, want %q", param, asked.Params.Get(param), value)
		}
	}
	if _, err := c.UpdateSOA(t.Context(), "example.com", &technitium.Record{Name: "example.com", Type: "NS"}, want); err == nil || len(fake.Requests("zones/records/update")) != 1 {
		t.Errorf("a record that is no SOA was set as one = %v", err)
	}
}
