//go:build acceptance

package technitium_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// recordOf reads the one record of a type at a name, nil when there is none.
func recordOf(t *testing.T, c *technitium.Client, zoneName, name, recordType string) *technitium.Record {
	t.Helper()

	at, err := c.RecordsAt(t.Context(), name, zoneName)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	for i := range at.Records {
		if at.Records[i].Type == recordType && strings.EqualFold(at.Records[i].Name, name) {
			return &at.Records[i]
		}
	}

	return nil
}

// Every record type the server has a layout for is added from its one line,
// read back as that line, changed with its options kept, and deleted; and a
// type it has none for is written as bytes.
func TestEveryRecordType(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	const own, forwarding = "types.it.test", "forward-types.it.test"
	const hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	zone(t, c, own)
	makeZone(t, c, technitium.NewZone{Name: forwarding, Type: technitium.ZoneForwarder, EmptyForwarder: true})

	for _, tc := range []struct {
		zone, name, recordType, value string
		options                       map[string]string
	}{
		{own, "a." + own, "A", "10.71.0.4", nil},
		{own, "a." + own, "AAAA", "fd00::71:4", nil},
		{own, "sub." + own, "NS", "ns.sub." + own, map[string]string{"glue": "10.71.0.9"}},
		{own, "sub." + own, "DS", "12345 ECDSAP256SHA256 SHA256 " + hash, nil},
		{own, "alias." + own, "CNAME", "a." + own, nil},
		{own, "ptr." + own, "PTR", "a." + own, nil},
		{own, own, "MX", "10 mail." + own, nil},
		{own, "txt." + own, "TXT", "v=spf1 -all", nil},
		{own, own, "RP", "admin@" + own + " info." + own, nil},
		{own, "_sip._udp." + own, "SRV", "1 2 5060 sip." + own, nil},
		{own, "naptr." + own, "NAPTR", `100 10 "S" "SIP+D2U" "" _sip._udp.` + own, nil},
		{own, "moved." + own, "DNAME", "elsewhere.it.test", nil},
		{own, "ssh." + own, "SSHFP", "Ed25519 SHA256 " + hash, nil},
		{own, "_443._tcp." + own, "TLSA", "DANE-EE SPKI SHA2-256 " + hash, nil},
		{own, "_dns." + own, "SVCB", "1 a." + own + " alpn=h2,h3 port=53443", nil},
		{own, "www." + own, "HTTPS", "1 . alpn=h2", map[string]string{"autoIpv4Hint": "true"}},
		{own, "_http._tcp." + own, "URI", "10 1 https://" + own + "/", nil},
		{own, own, "CAA", "0 issue letsencrypt.org", nil},
		{own, "flat." + own, "ANAME", "a." + own, nil},
		{own, "app." + own, "APP", "Query Logs (Sqlite) QueryLogsSqlite.App", map[string]string{"recordData": "{}"}},
		{own, "where." + own, "LOC", "01:02:03", nil},
		{forwarding, "lab." + forwarding, "FWD", "Udp 10.71.0.53", map[string]string{"forwarderPriority": "5", "dnssecValidation": "true", "proxyType": "NoProxy"}},
	} {
		data, err := technitium.ParseValue(tc.recordType, tc.value)
		if err != nil {
			t.Errorf("%s: %v", tc.recordType, err)

			continue
		}
		for option, value := range tc.options {
			if err := technitium.SetOption(data, tc.recordType, option, value); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: tc.zone, Name: tc.name, Type: tc.recordType, TTL: 300, Data: data}); err != nil {
			t.Errorf("adding a %s: %v", tc.recordType, err)

			continue
		}
		held := recordOf(t, c, tc.zone, tc.name, tc.recordType)
		if held == nil || !strings.EqualFold(held.Value(), tc.value) {
			t.Errorf("a %s added as %q reads back as %+v", tc.recordType, tc.value, held)

			continue
		}
		for option, value := range tc.options {
			if got := held.Options()[option]; got != value {
				t.Errorf("a %s added with %s=%q has it as %q", tc.recordType, option, value, got)
			}
		}

		// changed in nothing but its TTL: it is still what it was, with what it had beside its value
		want := technitium.UpdateOf(held)
		want.TTL = 600
		if _, err := c.UpdateRecord(ctx, tc.zone, held, want); err != nil {
			t.Errorf("changing a %s: %v", tc.recordType, err)

			continue
		}
		// a forwarder record has no TTL: the server keeps it at 0 whatever it is sent
		after, ttl := recordOf(t, c, tc.zone, tc.name, tc.recordType), 600
		if tc.recordType == "FWD" {
			ttl = 0
		}
		if after == nil || after.TTL != ttl || after.Value() != held.Value() || !sameOptions(after.Options(), held.Options()) {
			t.Errorf("a %s after its TTL was changed = %+v, with %v beside its value where it had %v", tc.recordType, after, optionsOrNone(after), held.Options())

			continue
		}
		if err := c.DeleteRecord(ctx, tc.zone, after); err != nil {
			t.Errorf("deleting a %s: %v", tc.recordType, err)
		}
		if left := recordOf(t, c, tc.zone, tc.name, tc.recordType); left != nil {
			t.Errorf("a %s deleted is still there: %+v", tc.recordType, left)
		}
	}

	// a TXT record split into strings at its line ends is named by its strings from then on: its text alone does not say where they part
	if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: own, Name: "split." + own, Type: "TXT", TTL: 300, Data: technitium.RData{"text": "one\ntwo", "splitText": true}}); err != nil {
		t.Fatal(err)
	}
	split := recordOf(t, c, own, "split."+own, "TXT")
	if split == nil || split.Data["characterStringsBase64"] == nil || split.Options()["splitText"] != "true" {
		t.Fatalf("a TXT record split at its line ends = %+v", split)
	}
	longer := technitium.UpdateOf(split)
	longer.TTL = 900
	if _, err := c.UpdateRecord(ctx, own, split, longer); err != nil {
		t.Errorf("changing a split TXT record's TTL: %v", err)
	}
	if now := recordOf(t, c, own, "split."+own, "TXT"); now == nil || now.TTL != 900 || now.Value() != split.Value() {
		t.Errorf("the split TXT record after its TTL was changed = %+v", now)
	} else if err := c.DeleteRecord(ctx, own, now); err != nil || recordOf(t, c, own, "split."+own, "TXT") != nil {
		t.Errorf("deleting a split TXT record = %v", err)
	}

	// an address deleted with the hints that follow it brought up to date, and a type that is the server's own to make refused before it is asked
	if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: own, Name: "gone." + own, Type: "A", Data: technitium.RData{"ipAddress": "10.71.0.8"}, UpdateSVCBHints: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteAddress(ctx, own, recordOf(t, c, own, "gone."+own, "A")); err != nil || recordOf(t, c, own, "gone."+own, "A") != nil {
		t.Errorf("DeleteAddress = %v", err)
	}
	if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: own, Name: own, Type: "SOA", Data: technitium.RData{"primaryNameServer": "x"}}); err == nil {
		t.Error("an SOA was added as a record is")
	}
}

func sameOptions(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, value := range a {
		if b[name] != value {
			return false
		}
	}

	return true
}

func optionsOrNone(rec *technitium.Record) map[string]string {
	if rec == nil {
		return nil
	}

	return rec.Options()
}

// Every option a zone has is set and read back: the keys a transfer and an
// update are signed with, a copy's primary, a catalog's members, and a serial
// by the day; zones are listed a page at a time and deleted several at once.
//
//nolint:paralleltest // it gives the server a transfer key, which the tests that read its settings would see beside what they expect
func TestZonesWhole(t *testing.T) {
	c := first(t)
	ctx := t.Context()
	const own, replica, catalog, key = "whole.it.test", "copy.whole.it.test", "catalog.whole.it.test", "key.whole.it.test"
	makeZone(t, c, technitium.NewZone{Name: own, Type: technitium.ZonePrimary, SerialByDate: true})
	if err := c.SetTSIGKey(ctx, key, "", technitium.DefaultTSIGAlgorithm); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.DeleteTSIGKey(noCancel(t), key) })

	// a zone made to number its changes by the day does, and stops when told
	soa := recordOf(t, c, own, own, "SOA")
	if soa == nil || !soa.SOA().SerialByDate || soa.SOA().Serial < 2026010100 {
		t.Fatalf("the SOA of a zone made with a serial by the day = %+v", soa)
	}
	counting := soa.SOA()
	counting.SerialByDate = false
	if _, err := c.UpdateSOA(ctx, own, soa, counting); err != nil {
		t.Fatal(err)
	}
	if now := recordOf(t, c, own, own, "SOA"); now == nil || now.SOA().SerialByDate {
		t.Errorf("the SOA told to count up = %+v", now)
	}

	// the keys a transfer and an update are signed with, set and cleared
	policies := []technitium.UpdatePolicy{{TSIGKeyName: key, Domain: "*." + own, AllowedTypes: []string{"A", "AAAA"}}, {TSIGKeyName: key, Domain: "_acme-challenge." + own, AllowedTypes: []string{"TXT"}}}
	if err := c.SetZoneOptions(ctx, own, technitium.ZoneChange{ZoneTransferTSIGKeyNames: []string{key}, UpdatePolicies: policies, QueryAccess: "UseSpecifiedNetworkACL", QueryAccessNetworks: []string{"10.71.0.0/24"}}); err != nil {
		t.Fatalf("setting a zone's keys: %v", err)
	}
	got, err := c.ZoneOptions(ctx, own)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.ZoneTransferTSIGKeyNames, []string{key}) || len(got.UpdateSecurityPolicies) != 2 || !slices.Contains(got.AvailableTSIGKeyNames, key) || !slices.Equal(got.QueryAccessNetworkACL, []string{"10.71.0.0/24"}) {
		t.Errorf("the zone's keys read back = transfer %v, update %+v, of the server's %v", got.ZoneTransferTSIGKeyNames, got.UpdateSecurityPolicies, got.AvailableTSIGKeyNames)
	}
	if err := c.SetZoneOptions(ctx, own, technitium.ZoneChange{ZoneTransferTSIGKeyNames: []string{}, UpdatePolicies: []technitium.UpdatePolicy{}}); err != nil {
		t.Fatalf("clearing a zone's keys: %v", err)
	}
	if got, err = c.ZoneOptions(ctx, own); err != nil || len(got.ZoneTransferTSIGKeyNames) != 0 || len(got.UpdateSecurityPolicies) != 0 {
		t.Errorf("the zone's keys cleared = %v and %+v, %v", got.ZoneTransferTSIGKeyNames, got.UpdateSecurityPolicies, err)
	}

	// a catalog, a member that keeps its own word on who is told, and who the catalog itself tells
	makeZone(t, c, technitium.NewZone{Name: catalog, Type: technitium.ZoneCatalog})
	if err := c.SetZoneOptions(ctx, catalog, technitium.ZoneChange{Notify: "SeparateNameServersForCatalogAndMemberZones", NotifyNameServers: []string{"10.71.0.3"}, NotifySecondaryCatalogsNameServers: []string{"10.71.0.4"}}); err != nil {
		t.Errorf("a catalog told whom to tell: %v", err)
	}
	if got, err = c.ZoneOptions(ctx, catalog); err != nil || !slices.Equal(got.NotifySecondaryCatalogsNameServers, []string{"10.71.0.4"}) {
		t.Errorf("the catalog's own servers to tell = %+v, %v", got, err)
	}
	if err := c.SetZoneOptions(ctx, own, technitium.ZoneChange{Catalog: catalog, OverrideCatalogQueryAccess: new(true), OverrideCatalogZoneTransfer: new(false), OverrideCatalogNotify: new(true)}); err != nil {
		t.Fatalf("a zone made a member that keeps its own settings: %v", err)
	}
	if got, err = c.ZoneOptions(ctx, own); err != nil || got.Catalog != catalog || !got.OverrideCatalogQueryAccess || got.OverrideCatalogZoneTransfer || !got.OverrideCatalogNotify || !slices.Contains(got.AvailableCatalogZoneNames, catalog) {
		t.Errorf("the member's options = %+v, %v", got, err)
	}

	// a copy is made only of a zone its primary answers for, so it takes a second server: made with how it transfers, and told otherwise
	makeZone(t, c, technitium.NewZone{Name: replica, Type: technitium.ZonePrimary})
	if world.Topology != testenv.Single {
		if err := c.SetZoneOptions(ctx, replica, technitium.ZoneChange{ZoneTransfer: technitium.PolicyAllow}); err != nil {
			t.Fatal(err)
		}
		other, from := server(t, world.Second), world.Address(world.First)
		makeZone(t, other, technitium.NewZone{Name: replica, Type: technitium.ZoneSecondary, PrimaryNameServerAddresses: []string{from}, TransferProtocol: "Tcp"})
		if got, err = other.ZoneOptions(ctx, replica); err != nil || !slices.Equal(got.PrimaryNameServerAddresses, []string{from}) || got.PrimaryZoneTransferProtocol != "Tcp" || got.PrimaryZoneTransferTSIGKeyName != "" {
			t.Errorf("a copy as it was made = %+v, %v", got, err)
		}
		if err := other.SetZoneOptions(ctx, replica, technitium.ZoneChange{PrimaryNameServerAddresses: []string{from, "10.71.0.3"}, PrimaryZoneTransferProtocol: "Tls", ValidateZone: new(true)}); err != nil {
			t.Fatalf("a copy told where its primary is now: %v", err)
		}
		// told to transfer over TLS, the server gives the addresses back with the port for it
		if got, err = other.ZoneOptions(ctx, replica); err != nil || !slices.Equal(got.PrimaryNameServerAddresses, []string{from + ":853", "10.71.0.3:853"}) || got.PrimaryZoneTransferProtocol != "Tls" || !got.ValidateZone {
			t.Errorf("a copy told otherwise = %+v, %v", got, err)
		}
		// the key a copy signs its transfers with, set by name and taken off again: a key is a setting, which on a cluster is the primary's and reaches every node
		if world.Topology == testenv.Pair {
			if err := other.SetTSIGKey(ctx, key, "", technitium.DefaultTSIGAlgorithm); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = other.DeleteTSIGKey(noCancel(t), key) })
		}
		if err := other.SetZoneOptions(ctx, replica, technitium.ZoneChange{PrimaryZoneTransferTSIGKeyName: new(key)}); err != nil {
			t.Fatalf("a copy given a key: %v", err)
		}
		if got, err = other.ZoneOptions(ctx, replica); err != nil || got.PrimaryZoneTransferTSIGKeyName != key {
			t.Errorf("a copy given a key = %q, %v", got.PrimaryZoneTransferTSIGKeyName, err)
		}
		if err := other.SetZoneOptions(ctx, replica, technitium.ZoneChange{PrimaryZoneTransferTSIGKeyName: new("")}); err != nil {
			t.Fatalf("a copy's key taken off: %v", err)
		}
		if got, err = other.ZoneOptions(ctx, replica); err != nil || got.PrimaryZoneTransferTSIGKeyName != "" {
			t.Errorf("a copy's key taken off = %q, %v", got.PrimaryZoneTransferTSIGKeyName, err)
		}
		// a copy of a zone nobody answers for is not made
		if _, err := other.CreateZone(ctx, technitium.NewZone{Name: "nowhere.whole.it.test", Type: technitium.ZoneSecondary, PrimaryNameServerAddresses: []string{"10.71.0.1"}}); err == nil {
			_ = other.DeleteZone(ctx, "nowhere.whole.it.test")
			t.Error("a copy was made of a zone whose primary does not answer: the server refused one when this was written")
		}
	}

	// the list a page at a time, and several zones deleted at once
	page, err := c.ZonesPage(ctx, technitium.ZoneFilter{}, 1, 2)
	if err != nil || page.PageNumber != 1 || len(page.Zones) != 2 || page.TotalZones < 3 || page.TotalPages < 2 {
		t.Errorf("ZonesPage = %+v, %v", page, err)
	}
	for _, gone := range []string{"gone-a.whole.it.test", "gone-b.whole.it.test"} {
		_ = c.DeleteZone(ctx, gone)
		if _, err := c.CreateZone(ctx, technitium.NewZone{Name: gone, Type: technitium.ZonePrimary}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.DeleteZones(ctx, []string{"gone-a.whole.it.test", "gone-b.whole.it.test"}); err != nil {
		t.Fatalf("DeleteZones = %v", err)
	}
	left, err := c.Zones(ctx, technitium.ZoneFilter{Name: "gone-*.whole.it.test"})
	if err != nil || len(left) != 0 {
		t.Errorf("after deleting two zones at once, %d of them are left: %v", len(left), err)
	}
}

// A forwarder zone is made with how its name server is reached, and a name's
// records are copied in from where they are held.
func TestForwardersAndImports(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	const forwarding, source = "reached.it.test", "source.imports.it.test"
	makeZone(t, c, technitium.NewZone{Name: forwarding, Type: technitium.ZoneForwarder, Forwarder: "10.71.0.53", ForwarderProtocol: "Tcp", DNSSECValidation: true, Proxy: &technitium.Proxy{Type: "NoProxy"}})
	fwd := recordOf(t, c, forwarding, forwarding, "FWD")
	if fwd == nil || fwd.Value() != "Tcp 10.71.0.53" || fwd.Options()["dnssecValidation"] != "true" || fwd.Options()["proxyType"] != "NoProxy" {
		t.Errorf("the record a forwarder zone was made with = %+v", fwd)
	}

	// the server asked for a name it holds itself and told to take the answer in: the records are written over with what was answered
	zone(t, c, source)
	if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: source, Name: "www." + source, Type: "A", TTL: 300, Comments: "by hand", Data: technitium.RData{"ipAddress": "10.71.0.20"}}); err != nil {
		t.Fatal(err)
	}
	res, err := c.ImportResolved(ctx, technitium.ResolveQuery{Name: "www." + source, Type: "A", Via: technitium.ResolveThisServer})
	if err != nil || res.RCode != "NoError" || len(res.Answer) != 1 {
		t.Fatalf("ImportResolved = %+v, %v", res, err)
	}
	if got := valuesAt(t, c, source, "www."+source, "A"); !slices.Equal(got, []string{"10.71.0.20"}) {
		t.Errorf("after the import www holds %v", got)
	}
	if _, err := c.ImportResolved(ctx, technitium.ResolveQuery{}); err == nil {
		t.Error("the answer to no question was imported")
	}
	// asked as if from a network, which changes nothing here and is taken
	if res, err = c.Resolve(ctx, technitium.ResolveQuery{Name: "www." + source, ClientSubnet: "203.0.113.0/24"}); err != nil || res.RCode != "NoError" {
		t.Errorf("Resolve as if from a network = %+v, %v", res, err)
	}
}

// The lists and the cache walked upward, and the statistics asked for their
// other ways.
func TestWalksAndCounts(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	const blocked, allowed = "tree.above-blocked.example", "tree.above-allowed.example"
	if err := c.BlockName(ctx, blocked); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.UnblockName(noCancel(t), blocked) })
	if err := c.AllowName(ctx, allowed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.UnallowName(noCancel(t), allowed) })

	// a name that only leads on - nothing listed at it and one name under it - is answered for the one below, or walking upward for the nearest above that is listed or branches
	middle := strings.TrimPrefix(blocked, "tree.")
	down, err := c.BlockedUnder(ctx, middle)
	if err != nil || down.Domain != blocked || len(down.Records) == 0 {
		t.Errorf("BlockedUnder(%s) = %+v, %v", middle, down, err)
	}
	up, err := c.BlockedAbove(ctx, middle)
	if err != nil || up.Domain == blocked || up.Domain == middle || !strings.HasSuffix(middle, up.Domain) {
		t.Errorf("BlockedAbove(%s) = %+v, %v", middle, up, err)
	}
	// a listed name is answered for itself either way, and so is one the list knows nothing of
	if up, err = c.BlockedAbove(ctx, blocked); err != nil || up.Domain != blocked {
		t.Errorf("BlockedAbove(%s) = %+v, %v", blocked, up, err)
	}
	if up, err = c.BlockedAbove(ctx, "a.b."+blocked); err != nil || up.Domain != "a.b."+blocked || len(up.Records) != 0 {
		t.Errorf("BlockedAbove of a name under a listed one = %+v, %v", up, err)
	}
	middle = strings.TrimPrefix(allowed, "tree.")
	if up, err = c.AllowedAbove(ctx, middle); err != nil || up.Domain == allowed || up.Domain == middle || !strings.HasSuffix(middle, up.Domain) {
		t.Errorf("AllowedAbove(%s) = %+v, %v", middle, up, err)
	}
	const kept = "nothing.kept.above.it.test"
	held, err := c.CacheAbove(ctx, kept)
	if err != nil || !strings.HasSuffix(kept, held.Domain) {
		t.Errorf("CacheAbove = %+v, %v", held, err)
	}

	if _, err := c.Stats(ctx, technitium.StatsWindow{Type: technitium.StatsLastHour, EveryQueryType: true}); err != nil {
		t.Errorf("Stats with every query type: %v", err)
	}
	if top, err := c.TopStats(ctx, technitium.StatsWindow{Type: technitium.StatsLastHour, NoReverseLookup: true, OnlyRateLimited: true}, technitium.TopClients, 5); err != nil || len(top.TopClients) != 0 {
		t.Errorf("the clients held back, of which a test server has none = %+v, %v", top, err)
	}
	// a token made by name and password is one more of the administrator's, and is deleted again
	token, err := c.CreateTokenFor(ctx, "admin", world.Password(), "", "sdk-whole-"+time.Now().UTC().Format("150405"))
	if err != nil || len(token) < 32 {
		t.Fatalf("CreateTokenFor = %d characters, %v", len(token), err)
	}
	if err := c.DeleteSession(ctx, token[:16]); err != nil {
		t.Errorf("deleting the token made: %v", err)
	}
}

// A scope is set with everything it can hand out, read back, cleared and
// renamed.
func TestScopeWhole(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	const scope, renamed = "sdk-whole", "sdk-whole-renamed"
	_ = c.DeleteScope(ctx, scope)
	_ = c.DeleteScope(ctx, renamed)
	base := technitium.NewScope{Name: scope, StartingAddress: "10.79.0.10", EndingAddress: "10.79.0.20", SubnetMask: "255.255.255.0"}
	if err := c.SetScope(ctx, &base); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.DeleteScope(noCancel(t), scope)
		_ = c.DeleteScope(noCancel(t), renamed)
	})
	// the server switches a scope on as it makes it: this one is for a network no machine is on, and is switched off all the same
	if err := c.DisableScope(ctx, scope); err != nil {
		t.Fatal(err)
	}

	whole := base
	whole.OfferDelayTime, whole.PingCheckTimeout, whole.PingCheckRetries, whole.DNSTTL = new(250), new(500), new(3), new(600)
	whole.PingCheckEnabled, whole.DNSOverwriteForDynamicLease, whole.BlockLocallyAdministeredMACAddresses, whole.IgnoreClientIdentifierOption = new(true), new(true), new(true), new(true)
	whole.ServerAddress, whole.ServerHostName, whole.BootFileName = new("10.79.0.5"), new("tftp"), new("boot.bin")
	whole.DomainSearchList, whole.WINSServers, whole.NTPServers, whole.NTPServerDomainNames, whole.CAPWAPAddresses, whole.TFTPServerAddresses = []string{"whole.it.test", "it.test"}, []string{"10.79.0.6"}, []string{"10.79.0.7"}, []string{"ntp.whole.it.test"}, []string{"10.79.0.8"}, []string{"10.79.0.5"}
	whole.StaticRoutes = []technitium.StaticRoute{{Destination: "10.80.0.0", SubnetMask: "255.255.0.0", Router: "10.79.0.2"}}
	whole.VendorInfo = []technitium.VendorInfo{{Identifier: "PXEClient", Information: "06:01:03"}}
	whole.GenericOptions = []technitium.GenericOption{{Code: 160, Value: "0A:4F:00:05"}}
	whole.ReservedLeases = []technitium.Reservation{{HostName: "nas", HardwareAddress: "AA-00-00-00-79-01", Address: "10.79.0.15", Comments: "the nas"}}
	if err := c.SetScope(ctx, &whole); err != nil {
		t.Fatalf("setting a scope whole: %v", err)
	}
	got, err := c.Scope(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if got.OfferDelayTime != 250 || !got.PingCheckEnabled || got.PingCheckTimeout != 500 || got.PingCheckRetries != 3 || got.DNSTTL != 600 || !got.DNSOverwriteForDynamicLease || !got.BlockLocallyAdministeredMACAddresses || !got.IgnoreClientIdentifierOption {
		t.Errorf("how the scope leases, read back = %+v", got)
	}
	if got.ServerAddress != "10.79.0.5" || got.ServerHostName != "tftp" || got.BootFileName != "boot.bin" || !slices.Equal(got.DomainSearchList, []string{"whole.it.test", "it.test"}) || !slices.Equal(got.WINSServers, []string{"10.79.0.6"}) || !slices.Equal(got.NTPServers, []string{"10.79.0.7"}) || !slices.Equal(got.NTPServerDomainNames, []string{"ntp.whole.it.test"}) || !slices.Equal(got.CAPWAPAddresses, []string{"10.79.0.8"}) || !slices.Equal(got.TFTPServerAddresses, []string{"10.79.0.5"}) {
		t.Errorf("what the scope hands out, read back = %+v", got)
	}
	if !slices.Equal(got.StaticRoutes, whole.StaticRoutes) || !slices.Equal(got.VendorInfo, whole.VendorInfo) || !slices.Equal(got.GenericOptions, whole.GenericOptions) || len(got.ReservedLeases) != 1 || got.ReservedLeases[0].Address != "10.79.0.15" || got.ReservedLeases[0].HostName != "nas" {
		t.Errorf("the scope's tables, read back = routes %+v, vendors %+v, options %+v, reservations %+v", got.StaticRoutes, got.VendorInfo, got.GenericOptions, got.ReservedLeases)
	}

	// cleared, and renamed: what was not given again is kept
	cleared := base
	cleared.NewName = renamed
	cleared.NTPServers, cleared.StaticRoutes, cleared.VendorInfo, cleared.GenericOptions, cleared.ReservedLeases, cleared.BootFileName = []string{}, []technitium.StaticRoute{}, []technitium.VendorInfo{}, []technitium.GenericOption{}, []technitium.Reservation{}, new("")
	if err := c.SetScope(ctx, &cleared); err != nil {
		t.Fatalf("clearing and renaming a scope: %v", err)
	}
	if got, err = c.Scope(ctx, renamed); err != nil || len(got.NTPServers) != 0 || len(got.StaticRoutes) != 0 || len(got.VendorInfo) != 0 || len(got.GenericOptions) != 0 || len(got.ReservedLeases) != 0 || got.BootFileName != "" || !slices.Equal(got.WINSServers, []string{"10.79.0.6"}) {
		t.Errorf("the scope cleared and renamed = %+v, %v", got, err)
	}
	if _, err := c.Scope(ctx, scope); err == nil {
		t.Error("the scope is still there under its old name")
	}
}
