//go:build integration

package integration

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// heldBy is a zone as a server lists it, nil when it does not hold it.
func heldBy(t *testing.T, c *technitium.Client, name string) *technitium.Zone {
	t.Helper()

	zones, err := c.Zones(t.Context(), technitium.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.IndexFunc(zones, func(z technitium.Zone) bool { return z.Name == name }); i >= 0 {
		return &zones[i]
	}

	return nil
}

// valuesAt are the values of the records of a type at a name in a zone.
func valuesAt(t *testing.T, c *technitium.Client, zoneName, name, recordType string) []string {
	t.Helper()

	at, err := c.RecordsAt(t.Context(), name, zoneName)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	var values []string
	for _, r := range at.Records {
		if r.Type == recordType && strings.EqualFold(r.Name, name) {
			values = append(values, r.Value())
		}
	}
	slices.Sort(values)

	return values
}

// A zone is made from another, switched off and on, turned into another
// type, and given the records of a zone file.
func TestZoneCopiesAndImports(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	const src, clone, into, catalog = "source.copies.it.test", "clone.copies.it.test", "into.copies.it.test", "catalog.copies.it.test"
	zone(t, c, src)
	zone(t, c, into)
	if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: src, Name: "www." + src, Type: "A", Comments: "kept by a clone", Data: technitium.RData{"ipAddress": "10.6.6.1"}}); err != nil {
		t.Fatal(err)
	}

	// a clone has what its source had at the time, under its own name
	_ = c.DeleteZone(ctx, clone)
	if err := c.CloneZone(ctx, clone, src); err != nil {
		t.Fatalf("CloneZone = %v", err)
	}
	t.Cleanup(func() { _ = c.DeleteZone(noCancel(t), clone) })
	if got := valuesAt(t, c, clone, "www."+clone, "A"); !slices.Equal(got, []string{"10.6.6.1"}) {
		t.Errorf("the clone's www = %v, want what the source had", got)
	}
	if err := c.CloneZone(ctx, clone, src); err == nil {
		t.Error("a zone was cloned over one that is there")
	}
	if err := c.CloneZone(ctx, "other."+clone, "nothing.copies.it.test"); err == nil {
		t.Error("a zone that is not there was cloned")
	}

	// switched off and on by the two calls of their own
	if err := c.DisableZone(ctx, clone); err != nil || !heldBy(t, c, clone).Disabled {
		t.Errorf("DisableZone = %v, and the zone is %+v", err, heldBy(t, c, clone))
	}
	if err := c.EnableZone(ctx, clone); err != nil || heldBy(t, c, clone).Disabled {
		t.Errorf("EnableZone = %v, and the zone is %+v", err, heldBy(t, c, clone))
	}

	// turned into a forwarder and back
	if err := c.ConvertZone(ctx, clone, technitium.ZoneForwarder); err != nil || heldBy(t, c, clone).Type != technitium.ZoneForwarder {
		t.Errorf("ConvertZone = %v, and the zone is %+v", err, heldBy(t, c, clone))
	}
	if err := c.ConvertZone(ctx, clone, technitium.ZonePrimary); err != nil || heldBy(t, c, clone).Type != technitium.ZonePrimary {
		t.Errorf("converted back = %v, and the zone is %+v", err, heldBy(t, c, clone))
	}
	if err := c.ConvertZone(ctx, clone, "NoSuchType"); err == nil {
		t.Error("a zone was turned into a type that is not one")
	}

	// a zone file: what the source exports, taken into another zone under that zone's name
	text, err := c.ExportZone(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	file := strings.ReplaceAll(text, src, into) + "added 300 IN A 10.6.6.2\nadded 300 IN A 10.6.6.3\n"
	if err := c.ImportZone(ctx, into, file, technitium.ZoneImport{}); err != nil {
		t.Fatalf("ImportZone = %v", err)
	}
	if got := valuesAt(t, c, into, "www."+into, "A"); !slices.Equal(got, []string{"10.6.6.1"}) {
		t.Errorf("the imported www = %v", got)
	}
	if got := valuesAt(t, c, into, "added."+into, "A"); !slices.Equal(got, []string{"10.6.6.2", "10.6.6.3"}) {
		t.Errorf("the imported added = %v", got)
	}
	// again, the file's records replace the ones at a name; kept, they are left as they are
	if err := c.ImportZone(ctx, into, "$ORIGIN "+into+".\nadded 300 IN A 10.6.6.9\n", technitium.ZoneImport{}); err != nil {
		t.Fatal(err)
	}
	if got := valuesAt(t, c, into, "added."+into, "A"); !slices.Equal(got, []string{"10.6.6.9"}) {
		t.Errorf("imported over what was there, added = %v, want the file's alone", got)
	}
	if err := c.ImportZone(ctx, into, "$ORIGIN "+into+".\nadded 300 IN A 10.6.6.4\n", technitium.ZoneImport{KeepExisting: true}); err != nil {
		t.Fatal(err)
	}
	if got := valuesAt(t, c, into, "added."+into, "A"); !slices.Equal(got, []string{"10.6.6.4", "10.6.6.9"}) {
		t.Errorf("imported keeping what was there, added = %v, want both", got)
	}
	// and with the zone replaced, nothing is left but the file's
	if err := c.ImportZone(ctx, into, "$ORIGIN "+into+".\nonly 300 IN A 10.6.6.5\n", technitium.ZoneImport{ReplaceZone: true}); err != nil {
		t.Fatal(err)
	}
	if www, only := valuesAt(t, c, into, "www."+into, "A"), valuesAt(t, c, into, "only."+into, "A"); len(www) != 0 || !slices.Equal(only, []string{"10.6.6.5"}) {
		t.Errorf("imported in place of the zone, www = %v and only = %v", www, only)
	}
	if err := c.ImportZone(ctx, "nothing.copies.it.test", file, technitium.ZoneImport{}); err == nil {
		t.Error("a zone file was imported into a zone that is not there")
	}

	// a catalog zone is listed among the catalogs once there is one
	makeZone(t, c, technitium.NewZone{Name: catalog, Type: technitium.ZoneCatalog})
	catalogs, err := c.CatalogZones(ctx)
	if err != nil || !slices.Contains(catalogs, catalog) || slices.Contains(catalogs, src) {
		t.Errorf("CatalogZones = %v, %v", catalogs, err)
	}
}

// publishedZSK reports whether a key is a zone signing key that is in the
// zone and not yet in use.
func publishedZSK(k technitium.SigningKey) bool {
	return k.KeyType == technitium.ZoneSigningKey && k.State == "Published"
}

// A zone signed, its keys read, added to, published, rolled over and
// retired, its proof of what is not there changed, and unsigned again.
func TestDNSSEC(t *testing.T) {
	t.Parallel()

	c := first(t)
	ctx := t.Context()
	const z = "signed.it.test"
	zone(t, c, z)

	// a zone that is not signed says so, and has no keys
	if unsigned, err := c.DNSSEC(ctx, z); err != nil || unsigned.DNSSECStatus != "Unsigned" || len(unsigned.Keys) != 0 {
		t.Errorf("the DNSSEC of a zone that is not signed = %+v, %v", unsigned, err)
	}
	if err := c.SignZone(ctx, z, technitium.Signing{Algorithm: technitium.AlgorithmECDSA, Curve: "P256", DNSKeyTTL: 3600, ZSKRolloverDays: new(0)}); err != nil {
		t.Fatalf("SignZone = %v", err)
	}
	if err := c.SignZone(ctx, z, technitium.Signing{Algorithm: technitium.AlgorithmECDSA, Curve: "P256"}); err == nil {
		t.Error("a zone was signed twice")
	}
	if held := heldBy(t, c, z); !held.Signed() || held.DNSSECStatus != "SignedWithNSEC" {
		t.Errorf("signed, the zone is %+v", held)
	}

	got, err := c.DNSSEC(ctx, z)
	if err != nil || got.Name != z || got.DNSSECStatus != "SignedWithNSEC" || got.DNSKeyTTL != 3600 || len(got.Keys) != 2 {
		t.Fatalf("DNSSEC = %+v, %v", got, err)
	}
	key := func(of *technitium.DNSSEC, keyType string) technitium.SigningKey {
		t.Helper()
		i := slices.IndexFunc(of.Keys, func(k technitium.SigningKey) bool { return k.KeyType == keyType && !k.IsRetiring })
		if i < 0 {
			t.Fatalf("the zone has no %s among %+v", keyType, of.Keys)
		}

		return of.Keys[i]
	}
	ksk, zsk := key(got, technitium.KeySigningKey), key(got, technitium.ZoneSigningKey)
	// the zone signing key is in use at once; the key signing key is published and waits, for hours, to be ready
	if ksk.KeyTag == 0 || zsk.KeyTag == 0 || ksk.Algorithm != "ECDSAP256SHA256" || ksk.State != "Published" || ksk.StateChangedOn == "" || ksk.StateReadyBy == "" || zsk.State != "Active" || zsk.RolloverDays != 0 {
		t.Errorf("the keys = %+v and %+v", ksk, zsk)
	}

	ds, err := c.DSInfo(ctx, z)
	if err != nil || ds.Name != z || ds.DNSSECStatus != "SignedWithNSEC" || len(ds.DSRecords) != 1 || ds.DSRecords[0].KeyTag != ksk.KeyTag || ds.DSRecords[0].DNSKeyState != "Published" || ds.DSRecords[0].PublicKey == "" || len(ds.DSRecords[0].Digests) != 2 || ds.DSRecords[0].Digests[0].DigestType != "SHA256" || len(ds.DSRecords[0].Digests[0].Digest) != 64 {
		t.Errorf("DSInfo = %+v, %v", ds, err)
	}

	// the proof of what is not there: to NSEC3, its parameters set, and back
	if err := c.ConvertToNSEC3(ctx, z); err != nil || heldBy(t, c, z).DNSSECStatus != "SignedWithNSEC3" {
		t.Errorf("ConvertToNSEC3 = %v, and the zone is %s", err, heldBy(t, c, z).DNSSECStatus)
	}
	if err := c.UpdateNSEC3Params(ctx, z, 2, 4); err != nil {
		t.Errorf("UpdateNSEC3Params = %v", err)
	}
	if at := valuesAt(t, c, z, z, "NSEC3PARAM"); len(at) != 1 || !strings.Contains(at[0], "iterations=2") {
		t.Errorf("the zone's NSEC3PARAM = %v, want its two iterations", at)
	}
	if err := c.ConvertToNSEC(ctx, z); err != nil || heldBy(t, c, z).DNSSECStatus != "SignedWithNSEC" {
		t.Errorf("ConvertToNSEC = %v, and the zone is %s", err, heldBy(t, c, z).DNSSECStatus)
	}
	if err := c.ConvertToNSEC(ctx, z); err == nil {
		t.Error("a zone on NSEC was converted to it")
	}

	// the TTL of the keys is only changed once every key is ready or in use, which a key signing key just made is not
	if err := c.UpdateDNSKeyTTL(ctx, z, 7200); err == nil || !strings.Contains(err.Error(), "state other than Ready or Active") {
		t.Errorf("UpdateDNSKeyTTL while a key is only published = %v", err)
	}

	// a key: added, which only generates it; its rollover set; deleted while it is only generated
	if err := c.AddSigningKey(ctx, z, technitium.NewSigningKey{Algorithm: technitium.AlgorithmECDSA, Curve: "P256", KeyType: technitium.ZoneSigningKey, RolloverDays: new(30)}); err != nil {
		t.Fatalf("AddSigningKey = %v", err)
	}
	generated := func() []technitium.SigningKey {
		t.Helper()
		now, readErr := c.DNSSEC(ctx, z)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var keys []technitium.SigningKey
		for _, k := range now.Keys {
			if k.State == "Generated" {
				keys = append(keys, k)
			}
		}

		return keys
	}
	added := generated()
	if len(added) != 1 || added[0].KeyType != technitium.ZoneSigningKey || added[0].RolloverDays != 30 {
		t.Fatalf("the key added = %+v", added)
	}
	if err := c.UpdateSigningKey(ctx, z, added[0].KeyTag, 60); err != nil || generated()[0].RolloverDays != 60 {
		t.Errorf("UpdateSigningKey = %v, and the key is %+v", err, generated())
	}
	if err := c.DeleteSigningKey(ctx, z, added[0].KeyTag); err != nil || len(generated()) != 0 {
		t.Errorf("DeleteSigningKey = %v, and what is generated is %+v", err, generated())
	}
	if err := c.DeleteSigningKey(ctx, z, zsk.KeyTag); err == nil {
		t.Error("a key in use was deleted")
	}

	// added again and published, it is in the zone
	if err := c.AddSigningKey(ctx, z, technitium.NewSigningKey{Algorithm: technitium.AlgorithmECDSA, Curve: "P256", KeyType: technitium.ZoneSigningKey}); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishSigningKeys(ctx, z); err != nil || len(generated()) != 0 {
		t.Errorf("PublishSigningKeys = %v, and what is still only generated is %+v", err, generated())
	}
	now, err := c.DNSSEC(ctx, z)
	if err != nil || len(now.Keys) != 3 || !slices.ContainsFunc(now.Keys, publishedZSK) {
		t.Fatalf("published, the keys = %+v, %v", now, err)
	}

	// rolled over, the key in use is marked as on its way out and a new one is published beside it
	if err := c.RolloverDNSKey(ctx, z, zsk.KeyTag); err != nil {
		t.Errorf("RolloverDNSKey = %v", err)
	}
	if now, err = c.DNSSEC(ctx, z); err != nil || len(now.Keys) != 4 || !slices.ContainsFunc(now.Keys, func(k technitium.SigningKey) bool { return k.KeyTag == zsk.KeyTag && k.IsRetiring }) {
		t.Errorf("rolled over, the keys = %+v, %v", now, err)
	}
	// and a key is only retired once another of its kind is in use, which a key just published is not yet
	if err := c.RetireDNSKey(ctx, z, zsk.KeyTag); err == nil || !strings.Contains(err.Error(), "no successor key") {
		t.Errorf("RetireDNSKey with nothing to take the key's place = %v", err)
	}
	if err := c.RolloverDNSKey(ctx, z, 1); err == nil {
		t.Error("a key the zone does not have was rolled over")
	}

	if err := c.UnsignZone(ctx, z); err != nil || heldBy(t, c, z).Signed() {
		t.Errorf("UnsignZone = %v, and the zone is %+v", err, heldBy(t, c, z))
	}
	if _, err := c.DSInfo(ctx, z); err == nil {
		t.Error("the DS of a zone that is not signed was read")
	}
}
