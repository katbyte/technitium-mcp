package technitium_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// A zone is signed with what its algorithm takes and nothing else; a private
// key given goes in the body of a POST.
func TestSignZone(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/dnssec/sign", `{}`)
	fake.Answer("zones/dnssec/unsign", `{}`)
	c := client(t, fake)

	if err := c.SignZone(t.Context(), "example.com", technitium.Signing{Algorithm: technitium.AlgorithmECDSA, Curve: "P256"}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/dnssec/sign"); asked.Method != http.MethodPost || len(asked.Params) != 3 || asked.Params.Get("zone") != "example.com" || asked.Params.Get("algorithm") != "ECDSA" || asked.Params.Get("curve") != "P256" {
		t.Errorf("the zone was signed with %s %v", asked.Method, asked.Params)
	}

	how := technitium.Signing{Algorithm: technitium.AlgorithmRSA, HashAlgorithm: "SHA256", KSKKeySize: 2048, ZSKKeySize: 1024, DNSKeyTTL: 3600, ZSKRolloverDays: new(0), NXProof: technitium.ProofNSEC3, Iterations: 0, SaltLength: 8, PEMKSKPrivateKey: "-----BEGIN PRIVATE KEY-----"}
	if err := c.SignZone(t.Context(), "example.com", how); err != nil {
		t.Fatal(err)
	}
	asked := fake.Last("zones/dnssec/sign")
	for param, want := range map[string]string{"zone": "example.com", "algorithm": "RSA", "hashAlgorithm": "SHA256", "kskKeySize": "2048", "zskKeySize": "1024", "dnsKeyTtl": "3600", "zskRolloverDays": "0", "nxProof": "NSEC3", "iterations": "0", "saltLength": "8", "pemKskPrivateKey": "-----BEGIN PRIVATE KEY-----"} {
		if !asked.Params.Has(param) || asked.Params.Get(param) != want {
			t.Errorf("the zone was signed with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if len(asked.Params) != 11 {
		t.Errorf("the zone was signed with %v", asked.Params)
	}

	if err := c.UnsignZone(t.Context(), "example.com"); err != nil || fake.Last("zones/dnssec/unsign").Params.Get("zone") != "example.com" || fake.Last("zones/dnssec/unsign").Method != http.MethodPost {
		t.Errorf("UnsignZone = %v, sent %v", err, fake.Last("zones/dnssec/unsign").Params)
	}

	sent := len(fake.Requests("zones/dnssec/sign")) + len(fake.Requests("zones/dnssec/unsign"))
	for what, how := range map[string]technitium.Signing{"no algorithm": {}, "RSA with no hash": {KeyOptions: technitium.KeyOptions{Algorithm: technitium.AlgorithmRSA}}, "RSA with no sizes": {KeyOptions: technitium.KeyOptions{Algorithm: technitium.AlgorithmRSA, HashAlgorithm: "SHA256"}}, "ECDSA with no curve": {KeyOptions: technitium.KeyOptions{Algorithm: technitium.AlgorithmECDSA}}} {
		if err := c.SignZone(t.Context(), "example.com", how); err == nil {
			t.Errorf("%s: the zone was signed", what)
		}
	}
	if err := c.SignZone(t.Context(), "", technitium.Signing{Algorithm: technitium.AlgorithmECDSA, Curve: "P256"}); err == nil {
		t.Error("no zone was signed")
	}
	if err := c.UnsignZone(t.Context(), ""); err == nil {
		t.Error("no zone was unsigned")
	}
	if now := len(fake.Requests("zones/dnssec/sign")) + len(fake.Requests("zones/dnssec/unsign")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}

func TestDNSSECProperties(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/dnssec/viewDS", `{"name":"example.com","type":"Primary","internal":false,"disabled":false,"dnssecStatus":"SignedWithNSEC","dsRecords":[{"keyTag":47972,"dnsKeyState":"Published","dnsKeyStateReadyBy":"2023-10-29T16:20:08.8007369Z","algorithm":"ECDSAP256SHA256","publicKey":"TK5a8pXPMspDwuh4Z3evOfNZm9kkc8IzwZDiCgIX6imxwkbpY9FTvhoI/ttZiLWZ5hvLbvrpsbd0liqSwqNmPg==","digests":[{"digestType":"SHA256","digest":"D59EBB413C88576B519B2980DF50493689A4A260383D0CB2F260251D5CA2E144"},{"digestType":"SHA384","digest":"F8235EEA"}]}]}`)
	fake.Answer("zones/dnssec/properties/get", `{"name":"example.com","type":"Primary","internal":false,"disabled":false,"dnssecStatus":"SignedWithNSEC","dnsKeyTtl":3600,"dnssecPrivateKeys":[{"keyTag":15048,"keyType":"KeySigningKey","algorithm":"ECDSAP256SHA256","state":"Published","stateChangedOn":"2022-12-18T14:39:50.0328321Z","stateReadyBy":"2022-12-18T16:14:50.0328321Z","isRetiring":false,"rolloverDays":0},{"keyTag":46152,"keyType":"ZoneSigningKey","algorithm":"ECDSAP256SHA256","state":"Active","stateChangedOn":"2022-12-18T14:39:50.0661173Z","isRetiring":false,"rolloverDays":90}]}`)
	for _, path := range []string{"convertToNSEC", "convertToNSEC3", "updateNSEC3Params", "updateDnsKeyTtl", "addPrivateKey", "updatePrivateKey", "deletePrivateKey", "publishAllPrivateKeys", "rolloverDnsKey", "retireDnsKey"} {
		fake.Answer("zones/dnssec/properties/"+path, `{}`)
	}
	c := client(t, fake)

	ds, err := c.DSInfo(t.Context(), "example.com")
	if err != nil || ds.Name != "example.com" || ds.DNSSECStatus != "SignedWithNSEC" || len(ds.DSRecords) != 1 || fake.Last("zones/dnssec/viewDS").Params.Get("zone") != "example.com" {
		t.Fatalf("DSInfo = %+v, %v", ds, err)
	}
	if r := ds.DSRecords[0]; r.KeyTag != 47972 || r.DNSKeyState != "Published" || r.DNSKeyStateReadyBy == "" || r.Algorithm != "ECDSAP256SHA256" || !strings.HasPrefix(r.PublicKey, "TK5a") || len(r.Digests) != 2 || r.Digests[0].DigestType != "SHA256" || !strings.HasPrefix(r.Digests[0].Digest, "D59E") {
		t.Errorf("a DS record = %+v", r)
	}
	got, err := c.DNSSEC(t.Context(), "example.com")
	if err != nil || got.DNSKeyTTL != 3600 || got.DNSSECStatus != "SignedWithNSEC" || len(got.Keys) != 2 || fake.Last("zones/dnssec/properties/get").Params.Get("zone") != "example.com" {
		t.Fatalf("DNSSEC = %+v, %v", got, err)
	}
	if k := got.Keys[0]; k.KeyTag != 15048 || k.KeyType != technitium.KeySigningKey || k.State != "Published" || k.StateReadyBy == "" || k.IsRetiring || k.RolloverDays != 0 || got.Keys[1].KeyType != technitium.ZoneSigningKey || got.Keys[1].RolloverDays != 90 {
		t.Errorf("the keys = %+v", got.Keys)
	}

	// each change is a POST of the zone and what the change takes, no more
	rsaKey := technitium.NewSigningKey{Algorithm: technitium.AlgorithmRSA, HashAlgorithm: "SHA256", KeyType: technitium.ZoneSigningKey, KeySize: 1024, RolloverDays: new(30)}
	calls := map[string]struct {
		do   func() error
		want map[string]string
	}{
		"convertToNSEC":         {func() error { return c.ConvertToNSEC(t.Context(), "example.com") }, map[string]string{}},
		"convertToNSEC3":        {func() error { return c.ConvertToNSEC3(t.Context(), "example.com") }, map[string]string{}},
		"updateNSEC3Params":     {func() error { return c.UpdateNSEC3Params(t.Context(), "example.com", 5, 8) }, map[string]string{"iterations": "5", "saltLength": "8"}},
		"updateDnsKeyTtl":       {func() error { return c.UpdateDNSKeyTTL(t.Context(), "example.com", 86400) }, map[string]string{"ttl": "86400"}},
		"addPrivateKey":         {func() error { return c.AddSigningKey(t.Context(), "example.com", rsaKey) }, map[string]string{"keyType": "ZoneSigningKey", "algorithm": "RSA", "hashAlgorithm": "SHA256", "keySize": "1024", "rolloverDays": "30"}},
		"updatePrivateKey":      {func() error { return c.UpdateSigningKey(t.Context(), "example.com", 46152, 0) }, map[string]string{"keyTag": "46152", "rolloverDays": "0"}},
		"deletePrivateKey":      {func() error { return c.DeleteSigningKey(t.Context(), "example.com", 46152) }, map[string]string{"keyTag": "46152"}},
		"publishAllPrivateKeys": {func() error { return c.PublishSigningKeys(t.Context(), "example.com") }, map[string]string{}},
		"rolloverDnsKey":        {func() error { return c.RolloverDNSKey(t.Context(), "example.com", 15048) }, map[string]string{"keyTag": "15048"}},
		"retireDnsKey":          {func() error { return c.RetireDNSKey(t.Context(), "example.com", 15048) }, map[string]string{"keyTag": "15048"}},
	}
	for path, call := range calls {
		if err := call.do(); err != nil {
			t.Errorf("%s: %v", path, err)

			continue
		}
		asked := fake.Last("zones/dnssec/properties/" + path)
		if asked.Method != http.MethodPost || asked.Params.Get("zone") != "example.com" || len(asked.Params) != len(call.want)+1 {
			t.Errorf("%s was sent %s %v", path, asked.Method, asked.Params)
		}
		for param, want := range call.want {
			if !asked.Params.Has(param) || asked.Params.Get(param) != want {
				t.Errorf("%s was sent %s=%q, want %q", path, param, asked.Params.Get(param), want)
			}
		}
	}
	if err := c.AddSigningKey(t.Context(), "example.com", technitium.NewSigningKey{Algorithm: technitium.AlgorithmEDDSA, Curve: "ED25519", KeyType: technitium.KeySigningKey, PEMPrivateKey: "-----BEGIN PRIVATE KEY-----"}); err != nil || fake.Last("zones/dnssec/properties/addPrivateKey").Params.Get("pemPrivateKey") == "" || fake.Last("zones/dnssec/properties/addPrivateKey").Params.Has("rolloverDays") {
		t.Errorf("a key of one's own was added with %v, %v", fake.Last("zones/dnssec/properties/addPrivateKey").Params, err)
	}

	// what names no zone or no key, or cannot be, is not sent
	sent := 0
	for path := range calls {
		sent += len(fake.Requests("zones/dnssec/properties/" + path))
	}
	refused := map[string]error{
		"no zone to NSEC":          c.ConvertToNSEC(t.Context(), ""),
		"no zone to NSEC3":         c.ConvertToNSEC3(t.Context(), ""),
		"no zone's NSEC3":          c.UpdateNSEC3Params(t.Context(), "", 0, 0),
		"fewer than no iterations": c.UpdateNSEC3Params(t.Context(), "example.com", -1, 0),
		"no TTL":                   c.UpdateDNSKeyTTL(t.Context(), "example.com", 0),
		"a key of no type":         c.AddSigningKey(t.Context(), "example.com", technitium.NewSigningKey{Algorithm: technitium.AlgorithmECDSA, Curve: "P256"}),
		"an RSA key of no size":    c.AddSigningKey(t.Context(), "example.com", technitium.NewSigningKey{Algorithm: technitium.AlgorithmRSA, HashAlgorithm: "SHA256", KeyType: technitium.ZoneSigningKey}),
		"a key with no curve":      c.AddSigningKey(t.Context(), "example.com", technitium.NewSigningKey{Algorithm: technitium.AlgorithmECDSA, KeyType: technitium.ZoneSigningKey}),
		"no key updated":           c.UpdateSigningKey(t.Context(), "example.com", 0, 30),
		"a rollover of two years":  c.UpdateSigningKey(t.Context(), "example.com", 46152, 730),
		"no key deleted":           c.DeleteSigningKey(t.Context(), "example.com", 0),
		"no zone's keys published": c.PublishSigningKeys(t.Context(), ""),
		"no key rolled over":       c.RolloverDNSKey(t.Context(), "", 15048),
		"no key retired":           c.RetireDNSKey(t.Context(), "example.com", 0),
	}
	_, refused["no zone's DS"] = c.DSInfo(t.Context(), "")
	_, refused["no zone's DNSSEC"] = c.DNSSEC(t.Context(), "")
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	now := 0
	for path := range calls {
		now += len(fake.Requests("zones/dnssec/properties/" + path))
	}
	if now != sent || len(fake.Requests("zones/dnssec/viewDS")) != 1 || len(fake.Requests("zones/dnssec/properties/get")) != 1 {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}

// A zone is made from another, turned into another type, switched off and
// on, and given the records of a zone file - which is sent as a file, with
// the call's parameters in the address.
func TestZoneCopiesAndImports(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/catalogs/list", `{"catalogZoneNames":["catalog1","cluster-catalog.example.com"]}`)
	for _, path := range []string{"zones/import", "zones/clone", "zones/convert", "zones/enable", "zones/disable"} {
		fake.Answer(path, `{}`)
	}
	c := client(t, fake)

	catalogs, err := c.CatalogZones(t.Context())
	if err != nil || len(catalogs) != 2 || catalogs[0] != "catalog1" {
		t.Errorf("CatalogZones = %v, %v", catalogs, err)
	}

	const zoneFile = "$ORIGIN example.com.\n@ 900 IN SOA ns1 hostadmin 2 900 300 604800 900\nwww 3600 IN A 192.0.2.10\n"
	if err := c.ImportZone(t.Context(), "example.com", zoneFile, technitium.ZoneImport{}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/import"); asked.Method != http.MethodPost || string(asked.File) != zoneFile || asked.FileName != "example.com.zone" || len(asked.Params) != 1 || asked.Params.Get("zone") != "example.com" {
		t.Errorf("the zone file was sent as %q (%s) with %v", asked.File, asked.FileName, asked.Params)
	}
	if err := c.ImportZone(t.Context(), "example.com", zoneFile, technitium.ZoneImport{KeepExisting: true, ReplaceZone: true, OverwriteSOASerial: true}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/import"); len(asked.Params) != 4 || asked.Params.Get("overwrite") != "false" || asked.Params.Get("overwriteZone") != "true" || asked.Params.Get("overwriteSoaSerial") != "true" {
		t.Errorf("the zone file was sent with %v", asked.Params)
	}

	if err := c.CloneZone(t.Context(), "copy.example.com", "example.com"); err != nil || fake.Last("zones/clone").Method != http.MethodPost || fake.Last("zones/clone").Params.Get("zone") != "copy.example.com" || fake.Last("zones/clone").Params.Get("sourceZone") != "example.com" {
		t.Errorf("CloneZone = %v, sent %v", err, fake.Last("zones/clone").Params)
	}
	if err := c.ConvertZone(t.Context(), "example.com", technitium.ZoneForwarder); err != nil || fake.Last("zones/convert").Method != http.MethodPost || fake.Last("zones/convert").Params.Get("zone") != "example.com" || fake.Last("zones/convert").Params.Get("type") != "Forwarder" {
		t.Errorf("ConvertZone = %v, sent %v", err, fake.Last("zones/convert").Params)
	}
	if err := c.DisableZone(t.Context(), "example.com"); err != nil || fake.Last("zones/disable").Method != http.MethodPost || fake.Last("zones/disable").Params.Get("zone") != "example.com" {
		t.Errorf("DisableZone = %v, sent %v", err, fake.Last("zones/disable").Params)
	}
	if err := c.EnableZone(t.Context(), "example.com"); err != nil || fake.Last("zones/enable").Method != http.MethodPost || fake.Last("zones/enable").Params.Get("zone") != "example.com" {
		t.Errorf("EnableZone = %v, sent %v", err, fake.Last("zones/enable").Params)
	}

	refused := map[string]error{
		"no zone imported into":  c.ImportZone(t.Context(), "", zoneFile, technitium.ZoneImport{}),
		"an empty zone file":     c.ImportZone(t.Context(), "example.com", "", technitium.ZoneImport{}),
		"a clone of nothing":     c.CloneZone(t.Context(), "copy.example.com", ""),
		"a clone with no name":   c.CloneZone(t.Context(), "", "example.com"),
		"no zone converted":      c.ConvertZone(t.Context(), "", "Primary"),
		"a zone made of no type": c.ConvertZone(t.Context(), "example.com", ""),
		"no zone switched on":    c.EnableZone(t.Context(), ""),
		"no zone switched off":   c.DisableZone(t.Context(), ""),
	}
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	if len(fake.Requests("zones/import")) != 2 || len(fake.Requests("zones/clone")) != 1 || len(fake.Requests("zones/convert")) != 1 || len(fake.Requests("zones/enable")) != 1 || len(fake.Requests("zones/disable")) != 1 {
		t.Error("a refused call reached the server")
	}
}

func TestMetricsAndStatsDeleted(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("dashboard/metrics/json", `{"uptimestamp":"2026-04-19T12:14:07.6191241Z","uptimeSeconds":9,"lifetimeCounters":{"totalQueries":120,"totalNoError":100,"totalServerFailure":1,"totalNxDomain":19,"totalRefused":0,"totalAuthoritative":40,"totalRecursive":50,"totalCached":20,"totalBlocked":10,"totalDropped":0,"totalClients":3}}`)
	fake.AnswerText("dashboard/metrics/text", "# TYPE total_queries counter\ntotal_queries 120\n")
	fake.Answer("dashboard/stats/deleteAll", `{}`)
	c := client(t, fake)

	got, err := c.Metrics(t.Context())
	if err != nil || got.UptimeSeconds != 9 || got.UpSince == "" || got.Lifetime.Queries != 120 || got.Lifetime.NxDomain != 19 || got.Lifetime.Blocked != 10 || got.Lifetime.Clients != 3 {
		t.Errorf("Metrics = %+v, %v", got, err)
	}
	text, err := c.MetricsText(t.Context())
	if err != nil || !strings.Contains(text, "total_queries 120") {
		t.Errorf("MetricsText = %q, %v", text, err)
	}
	if err := c.DeleteAllStats(t.Context()); err != nil || fake.Last("dashboard/stats/deleteAll").Method != http.MethodPost || len(fake.Last("dashboard/stats/deleteAll").Params) != 0 {
		t.Errorf("DeleteAllStats = %v, sent %v", err, fake.Last("dashboard/stats/deleteAll").Params)
	}
}
