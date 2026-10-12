//go:build acceptance

package tools_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

// The zones the tests of whole zones make and delete again: one to copy, the
// copy, and one to sign.
const (
	sourceZone = "acc-source.test"
	cloneZone  = "acc-clone.test"
	signedZone = "acc-signed.test"
)

// values of a type at a name, as zone_records gives them.
func recordValues(t *testing.T, zone, name, recordType string) []string {
	t.Helper()

	got := suite.Call(t, "zone_records", on(map[string]any{"zone": zone, "name": name, "types": []string{recordType}}))
	var values []string
	for _, row := range acctest.Rows(t, got["records"], "records") {
		if row["name"] == name {
			values = append(values, acctest.Str(row["value"]))
		}
	}
	slices.Sort(values)

	return values
}

// A zone copied, given the records of a zone file, turned into another type
// and back, and deleted - each first as a dry run that changes nothing.
//
// It does not run beside the other tests: it makes and deletes zones, which
// a test reading every zone beside it would list and then not find.
//
//nolint:paralleltest // it makes and deletes zones, which a test reading every zone beside it would list and then not find
func TestZonesCopiedImportedAndDeleted(t *testing.T) {
	names(t)
	first := world.First
	held := func(zone string) map[string]any {
		t.Helper()
		for _, row := range acctest.Rows(t, suite.Call(t, "zone_list", on(map[string]any{"name": zone}))["zones"], "zones") {
			if row["zone"] == zone {
				return row
			}
		}

		return nil
	}

	suite.Call(t, "zone_create", on(map[string]any{"zone": sourceZone}))
	suite.Call(t, "record_set", on(map[string]any{"name": "www." + sourceZone, "type": "A", "value": "10.5.5.1", "comment": "kept by a clone"}))

	// a clone: a dry run makes nothing, then it has what the source had under its own name, and its name is then taken
	dry := suite.Call(t, "zone_clone", on(map[string]any{"zone": cloneZone, "source": sourceZone, "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have made " + cloneZone + " on " + first + " as a copy of " + sourceZone}) || dry["after"] != nil || held(cloneZone) != nil {
		t.Errorf("a dry run of a clone = %v", dry)
	}
	cloned := suite.Call(t, "zone_clone", on(map[string]any{"zone": cloneZone, "source": sourceZone}))
	if after := acctest.Object(t, cloned["after"], "after"); !acctest.BoolOf(cloned["changed"]) || after["type"] != "Primary" || cloned["zone"] != cloneZone {
		t.Errorf("cloned = %v", cloned)
	}
	if got := recordValues(t, cloneZone, "www."+cloneZone, "A"); !slices.Equal(got, []string{"10.5.5.1"}) {
		t.Errorf("the clone's www = %v, want what the source had", got)
	}
	if msg := suite.CallErr(t, "zone_clone", on(map[string]any{"zone": cloneZone, "source": sourceZone})); !strings.Contains(msg, "holds "+cloneZone+" already") {
		t.Errorf("cloned over a zone that is there = %q", msg)
	}
	if msg := suite.CallErr(t, "zone_clone", on(map[string]any{"zone": "acc-other.test", "source": "acc-nothing.test"})); !strings.Contains(msg, "holds no zone named acc-nothing.test") {
		t.Errorf("a clone of nothing = %q", msg)
	}

	// a zone file: counted by a dry run, then its records replace the ones at the same names, are added beside them, or are all the zone has
	file := "$ORIGIN " + cloneZone + ".\n; a comment is no record\nwww 300 IN A 10.5.5.2\nadded 300 IN A 10.5.5.3\n"
	dry = suite.Call(t, "zone_import", on(map[string]any{"zone": cloneZone, "zone_file": file, "dry_run": true}))
	if acctest.Num(t, dry["in_file"], "in_file") != 2 || len(acctest.Strs(t, dry["changes"], "changes")) != 1 || dry["records"] != nil || len(recordValues(t, cloneZone, "added."+cloneZone, "A")) != 0 {
		t.Errorf("a dry run of an import = %v", dry)
	}
	imported := suite.Call(t, "zone_import", on(map[string]any{"zone": cloneZone, "zone_file": file}))
	if acctest.Num(t, imported["records"], "records") != acctest.Num(t, imported["before"], "before")+1 {
		t.Errorf("imported = %v, want one record more than before", imported)
	}
	if www, added := recordValues(t, cloneZone, "www."+cloneZone, "A"), recordValues(t, cloneZone, "added."+cloneZone, "A"); !slices.Equal(www, []string{"10.5.5.2"}) || !slices.Equal(added, []string{"10.5.5.3"}) {
		t.Errorf("after the import www = %v and added = %v", www, added)
	}
	suite.Call(t, "zone_import", on(map[string]any{"zone": cloneZone, "zone_file": "www 300 IN A 10.5.5.9\n", "keep_existing": true}))
	if www := recordValues(t, cloneZone, "www."+cloneZone, "A"); !slices.Equal(www, []string{"10.5.5.2", "10.5.5.9"}) {
		t.Errorf("imported beside what was there, www = %v", www)
	}
	suite.Call(t, "zone_import", on(map[string]any{"zone": cloneZone, "zone_file": "only 300 IN A 10.5.5.5\n", "replace_zone": true}))
	if www, only := recordValues(t, cloneZone, "www."+cloneZone, "A"), recordValues(t, cloneZone, "only."+cloneZone, "A"); len(www) != 0 || !slices.Equal(only, []string{"10.5.5.5"}) {
		t.Errorf("imported in place of the zone, www = %v and only = %v", www, only)
	}
	if msg := suite.CallErr(t, "zone_import", on(map[string]any{"zone": cloneZone, "zone_file": "; nothing\n"})); !strings.Contains(msg, "holds no records") {
		t.Errorf("an empty zone file = %q", msg)
	}
	if msg := suite.CallErr(t, "zone_import", on(map[string]any{"zone": cloneZone, "zone_file": file, "keep_existing": true, "replace_zone": true})); !strings.Contains(msg, "opposite things") {
		t.Errorf("an import that keeps and replaces = %q", msg)
	}

	// turned into a forwarder and back; a type that is none is refused, and the type it has changes nothing
	dry = suite.Call(t, "zone_convert", on(map[string]any{"zone": cloneZone, "type": "forwarder", "dry_run": true}))
	typeOf := func(zone string) any {
		t.Helper()

		return acctest.Rows(t, suite.Call(t, "zone_get", on(map[string]any{"zone": zone}))["servers"], "servers")[0]["type"]
	}
	if len(acctest.Strs(t, dry["changes"], "changes")) != 1 || dry["after"] != nil || typeOf(cloneZone) != "Primary" {
		t.Errorf("a dry run of a conversion = %v, and the zone is a %v zone", dry, typeOf(cloneZone))
	}
	converted := suite.Call(t, "zone_convert", on(map[string]any{"zone": cloneZone, "type": "Forwarder"}))
	if acctest.Object(t, converted["after"], "after")["type"] != "Forwarder" || !acctest.BoolOf(converted["changed"]) {
		t.Errorf("converted = %v", converted)
	}
	if again := suite.Call(t, "zone_convert", on(map[string]any{"zone": cloneZone, "type": "Forwarder"})); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 {
		t.Errorf("converted to what it is = %v", again)
	}
	if back := suite.Call(t, "zone_convert", on(map[string]any{"zone": cloneZone, "type": "Primary"})); acctest.Object(t, back["after"], "after")["type"] != "Primary" {
		t.Errorf("converted back = %v", back)
	}
	if msg := suite.CallErr(t, "zone_convert", on(map[string]any{"zone": cloneZone, "type": "Tertiary"})); !strings.Contains(msg, `type "Tertiary": a zone is one of Primary`) {
		t.Errorf("a type that is none = %q", msg)
	}

	// deleted: a dry run says what would go and leaves it; then it is gone, and a zone that is not there is said to be
	dry = suite.Call(t, "zone_delete", on(map[string]any{"zone": cloneZone, "dry_run": true}))
	if dry["type"] != "Primary" || acctest.Num(t, dry["records"], "records") < 3 || !strings.HasPrefix(acctest.Strs(t, dry["changes"], "changes")[0], "would have deleted the Primary zone "+cloneZone) || held(cloneZone) == nil {
		t.Errorf("a dry run of a deletion = %v", dry)
	}
	for _, zone := range []string{cloneZone, sourceZone} {
		if deleted := suite.Call(t, "zone_delete", on(map[string]any{"zone": zone})); !acctest.BoolOf(deleted["changed"]) || held(zone) != nil {
			t.Errorf("deleted %s = %v, and the zone is %v", zone, deleted, held(zone))
		}
	}
	if msg := suite.CallErr(t, "zone_delete", on(map[string]any{"zone": cloneZone})); !strings.Contains(msg, "holds no zone named "+cloneZone) {
		t.Errorf("a zone that is not there, deleted = %q", msg)
	}
	// the zones a server makes for itself are not among the ones a change is made to at all
	if msg := suite.CallErr(t, "zone_delete", on(map[string]any{"zone": "localhost"})); !strings.Contains(msg, "holds no zone named localhost") {
		t.Errorf("a zone of the server's own, deleted = %q", msg)
	}
}

// A zone signed, its keys read and moved along, its proof of what is not
// there changed, and unsigned again.
//
// It does not run beside the other tests: it makes and deletes a zone.
//
//nolint:paralleltest // it makes and deletes a zone, which a test reading every zone beside it would list and then not find
func TestDNSSEC(t *testing.T) {
	names(t)
	first := world.First
	suite.Call(t, "zone_create", on(map[string]any{"zone": signedZone}))
	t.Cleanup(func() { _, _ = suite.Invoke("zone_delete", on(map[string]any{"zone": signedZone})) })
	signing := func() map[string]any {
		t.Helper()

		return rowFor(t, acctest.Rows(t, suite.Call(t, "dnssec_get", on(map[string]any{"zone": signedZone}))["servers"], "servers"), "server", first)
	}
	key := func(of map[string]any, keyType, state string) map[string]any {
		t.Helper()
		for _, k := range acctest.Rows(t, of["keys"], "keys") {
			if k["type"] == keyType && k["state"] == state && !acctest.BoolOf(k["retiring"]) {
				return k
			}
		}
		t.Fatalf("the zone has no %s that is %s among %v", keyType, state, of["keys"])

		return nil
	}

	if got := signing(); got["status"] != "Unsigned" || got["keys"] != nil || got["ds"] != nil {
		t.Errorf("before it is signed = %v", got)
	}
	if msg := suite.CallErr(t, "dnssec_edit", on(map[string]any{"zone": signedZone, "nx_proof": "NSEC3"})); !strings.Contains(msg, "is not signed") {
		t.Errorf("a zone that is not signed, edited = %q", msg)
	}

	// signed: a dry run signs nothing; then it has its two keys, and the DS its parent is to hold
	dry := suite.Call(t, "dnssec_sign", on(map[string]any{"zone": signedZone, "dry_run": true}))
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have signed " + signedZone + " on " + first + " with ECDSA P256, proving what is not there with NSEC"}) || signing()["status"] != "Unsigned" {
		t.Errorf("a dry run of signing = %v", dry)
	}
	signed := suite.Call(t, "dnssec_sign", on(map[string]any{"zone": signedZone, "zsk_rollover_days": 0}))
	after := acctest.Object(t, signed["after"], "after")
	ksk, zsk := key(after, "KeySigningKey", "Published"), key(after, "ZoneSigningKey", "Active")
	ds := acctest.Rows(t, after["ds"], "ds")
	if after["status"] != "SignedWithNSEC" || len(acctest.Rows(t, after["keys"], "keys")) != 2 || len(ds) != 1 || ds[0]["key_tag"] != ksk["key_tag"] || len(acctest.Strs(t, ds[0]["digests"], "digests")) != 2 || !strings.HasPrefix(acctest.Strs(t, ds[0]["digests"], "digests")[0], "SHA256 ") || ksk["ready_by"] == nil || zsk["rollover_days"] != nil {
		t.Errorf("signed = %v", after)
	}
	if msg := suite.CallErr(t, "dnssec_sign", on(map[string]any{"zone": signedZone})); !strings.Contains(msg, "is signed already") {
		t.Errorf("signed twice = %q", msg)
	}
	if msg := suite.CallErr(t, "dnssec_sign", on(map[string]any{"zone": firstZone, "algorithm": "DSA"})); !strings.Contains(msg, `algorithm "DSA"`) {
		t.Errorf("an algorithm that is none = %q", msg)
	}

	// the audit of signed zones says what this one's keys leave open: anyone can list its names, and its zone signing key is never replaced
	audited := acctest.Rows(t, suite.Call(t, "audit_dnssec", map[string]any{"zone": signedZone})["findings"], "findings")
	one(t, audited, "nsec_walkable", signedZone)
	if never := one(t, audited, "key_never_replaced", signedZone); !strings.Contains(acctest.Str(never["detail"]), fmt.Sprint(zsk["key_tag"])) || len(audited) != 2 {
		t.Errorf("audit_dnssec of the zone just signed = %v", audited)
	}

	// the proof of what is not there: to NSEC3 with its parameters in one call, and back
	edited := suite.Call(t, "dnssec_edit", on(map[string]any{"zone": signedZone, "nx_proof": "nsec3", "iterations": 2, "salt_length": 4}))
	if acctest.Object(t, edited["after"], "after")["status"] != "SignedWithNSEC3" || len(acctest.Strs(t, edited["changes"], "changes")) != 2 {
		t.Errorf("put on NSEC3 = %v", edited)
	}
	if got := recordValues(t, signedZone, signedZone, "NSEC3PARAM"); len(got) != 1 || !strings.Contains(got[0], "iterations=2") {
		t.Errorf("the zone's NSEC3PARAM = %v", got)
	}
	if msg := suite.CallErr(t, "dnssec_edit", on(map[string]any{"zone": signedZone, "nx_proof": "NSEC", "iterations": 1})); !strings.Contains(msg, "NSEC3's") {
		t.Errorf("iterations for NSEC = %q", msg)
	}
	if back := suite.Call(t, "dnssec_edit", on(map[string]any{"zone": signedZone, "nx_proof": "NSEC"})); acctest.Object(t, back["after"], "after")["status"] != "SignedWithNSEC" {
		t.Errorf("put back on NSEC = %v", back)
	}
	// the TTL of the keys is the server's to refuse while a key is only published, and it says why
	if msg := suite.CallErr(t, "dnssec_edit", on(map[string]any{"zone": signedZone, "dnskey_ttl": 7200})); !strings.Contains(msg, "Ready or Active") {
		t.Errorf("the DNSKEY TTL while a key is only published = %q", msg)
	}

	// a key added is only generated: its rollover is set, and it is deleted again; one that is in the zone is not
	added := suite.Call(t, "dnssec_key_add", on(map[string]any{"zone": signedZone, "key_type": "zsk", "rollover_days": 30}))
	generated := key(acctest.Object(t, added["after"], "after"), "ZoneSigningKey", "Generated")
	if acctest.Num(t, generated["rollover_days"], "rollover_days") != 30 {
		t.Errorf("the key added = %v", generated)
	}
	set := suite.Call(t, "dnssec_key_edit", on(map[string]any{"zone": signedZone, "key_tag": generated["key_tag"], "rollover_days": 60}))
	if got := key(acctest.Object(t, set["after"], "after"), "ZoneSigningKey", "Generated"); acctest.Num(t, got["rollover_days"], "rollover_days") != 60 {
		t.Errorf("its rollover set = %v", got)
	}
	if msg := suite.CallErr(t, "dnssec_key_delete", on(map[string]any{"zone": signedZone, "key_tag": zsk["key_tag"]})); !strings.Contains(msg, "is Active: only a key that was generated") {
		t.Errorf("a key in use, deleted = %q", msg)
	}
	dry = suite.Call(t, "dnssec_key_delete", on(map[string]any{"zone": signedZone, "key_tag": generated["key_tag"], "dry_run": true}))
	if len(acctest.Strs(t, dry["changes"], "changes")) != 1 || len(acctest.Rows(t, signing()["keys"], "keys")) != 3 {
		t.Errorf("a dry run of deleting a key = %v", dry)
	}
	if deleted := suite.Call(t, "dnssec_key_delete", on(map[string]any{"zone": signedZone, "key_tag": generated["key_tag"]})); len(acctest.Rows(t, acctest.Object(t, deleted["after"], "after")["keys"], "keys")) != 2 {
		t.Errorf("the key deleted = %v", deleted)
	}

	// added and published at once it is in the zone; the key in use is rolled over to a new one; and it is not retired while nothing has taken its place
	published := suite.Call(t, "dnssec_key_add", on(map[string]any{"zone": signedZone, "key_type": "ZoneSigningKey", "publish": true}))
	if key(acctest.Object(t, published["after"], "after"), "ZoneSigningKey", "Published") == nil || len(acctest.Strs(t, published["changes"], "changes")) != 2 {
		t.Errorf("added and published = %v", published)
	}
	rolled := suite.Call(t, "dnssec_key_edit", on(map[string]any{"zone": signedZone, "action": "rollover", "key_tag": zsk["key_tag"]}))
	keys := acctest.Rows(t, acctest.Object(t, rolled["after"], "after")["keys"], "keys")
	old := slices.IndexFunc(keys, func(k map[string]any) bool { return k["key_tag"] == zsk["key_tag"] })
	if len(keys) != 4 || old < 0 || !acctest.BoolOf(keys[old]["retiring"]) {
		t.Errorf("rolled over = %v", rolled)
	}
	if msg := suite.CallErr(t, "dnssec_key_edit", on(map[string]any{"zone": signedZone, "action": "retire", "key_tag": zsk["key_tag"]})); !strings.Contains(msg, "no successor key") {
		t.Errorf("retired with nothing to take its place = %q", msg)
	}
	if nothing := suite.Call(t, "dnssec_key_edit", on(map[string]any{"zone": signedZone, "action": "publish"})); acctest.BoolOf(nothing["changed"]) {
		t.Errorf("publishing when nothing is only generated = %v", nothing)
	}
	if msg := suite.CallErr(t, "dnssec_key_edit", on(map[string]any{"zone": signedZone, "action": "rollover", "key_tag": 1})); !strings.Contains(msg, "has no key with the tag 1") {
		t.Errorf("a key the zone does not have = %q", msg)
	}

	// unsigned: a dry run says what would go; then it has no keys, and a second time there is nothing to take off
	dry = suite.Call(t, "dnssec_unsign", on(map[string]any{"zone": signedZone, "dry_run": true}))
	if !strings.Contains(acctest.Strs(t, dry["changes"], "changes")[0], "deleting its 4 keys") || signing()["status"] != "SignedWithNSEC" {
		t.Errorf("a dry run of unsigning = %v", dry)
	}
	if unsigned := suite.Call(t, "dnssec_unsign", on(map[string]any{"zone": signedZone})); acctest.Object(t, unsigned["after"], "after")["status"] != "Unsigned" {
		t.Errorf("unsigned = %v", unsigned)
	}
	if again := suite.Call(t, "dnssec_unsign", on(map[string]any{"zone": signedZone})); acctest.BoolOf(again["changed"]) {
		t.Errorf("unsigned twice = %v", again)
	}
	if left := suite.Call(t, "audit_dnssec", map[string]any{"zone": signedZone}); acctest.Num(t, left["total"], "total") != 0 {
		t.Errorf("audit_dnssec of a zone that is no longer signed = %v", left)
	}
}
