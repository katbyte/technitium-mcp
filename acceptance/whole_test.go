//go:build integration

package acceptance

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// The zones the tests of every kind of record and of a zone's keys make and
// delete again.
const (
	kindsZone    = "acc-kinds.test"
	kindsForward = "acc-forward.test"
	keyedZone    = "acc-keyed.test"
	importZone   = "acc-import.test"
)

// heldRecord reads a record of a type at a name from the first server
// itself, nil when it holds none.
func heldRecord(t *testing.T, zone, name, recordType string) *technitium.Record {
	t.Helper()

	at, err := mustClient(t, world.First).RecordsAt(context.WithoutCancel(t.Context()), name, zone)
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

// Every kind of record the server has is set from its one line, read back
// from the server as that line with what it was given beside it, left alone
// when set again, and deleted.
//
//nolint:paralleltest // it makes and deletes zones, which a test reading every zone beside it would list and then not find
func TestRecordsOfEveryKind(t *testing.T) {
	names(t)
	const hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	suite.Call(t, "zone_create", on(map[string]any{"zone": kindsZone}))
	made := suite.Call(t, "zone_create", on(map[string]any{"zone": kindsForward, "type": "Forwarder", "empty_forwarder": true}))
	if after := acctest.Object(t, made["after"], "after"); after["type"] != "Forwarder" || heldRecord(t, kindsForward, kindsForward, "FWD") != nil {
		t.Errorf("a forwarder zone made with nothing in it = %v", made)
	}

	for _, tc := range []struct {
		zone, name, recordType, value string
		options                       map[string]string
	}{
		{kindsZone, "sub." + kindsZone, "NS", "ns.sub." + kindsZone, map[string]string{"glue": "10.69.1.9"}},
		{kindsZone, "www." + kindsZone, "HTTPS", "1 . alpn=h2,h3", map[string]string{"autoIpv4Hint": "true"}},
		{kindsZone, "_dns." + kindsZone, "SVCB", "1 www." + kindsZone + " port=53443", nil},
		{kindsZone, "_443._tcp." + kindsZone, "TLSA", "DANE-EE SPKI SHA2-256 " + hash, nil},
		{kindsZone, "ssh." + kindsZone, "SSHFP", "Ed25519 SHA256 " + hash, nil},
		{kindsZone, "sub." + kindsZone, "DS", "12345 ECDSAP256SHA256 SHA256 " + hash, nil},
		{kindsZone, "naptr." + kindsZone, "NAPTR", `100 10 "S" "SIP+D2U" "" _sip._udp.` + kindsZone, nil},
		{kindsZone, "_http._tcp." + kindsZone, "URI", "10 1 https://" + kindsZone + "/", nil},
		{kindsZone, kindsZone, "RP", "admin@" + kindsZone + " info." + kindsZone, nil},
		{kindsZone, "app." + kindsZone, "APP", "Query Logs (Sqlite) QueryLogsSqlite.App", map[string]string{"recordData": "{}"}},
		{kindsZone, "where." + kindsZone, "LOC", "01:02:03", nil},
		{kindsForward, "lab." + kindsForward, "FWD", "Udp 10.69.1.53", map[string]string{"forwarderPriority": "5", "dnssecValidation": "true", "proxyType": "NoProxy"}},
	} {
		args := map[string]any{"zone": tc.zone, "name": tc.name, "type": tc.recordType, "value": tc.value}
		if tc.options != nil {
			args["options"] = tc.options
		}
		set := suite.Call(t, "record_set", on(args))
		held := heldRecord(t, tc.zone, tc.name, tc.recordType)
		if held == nil || !strings.EqualFold(held.Value(), tc.value) || !acctest.BoolOf(set["changed"]) {
			t.Errorf("a %s set as %q: the server holds %+v, and the tool said %v", tc.recordType, tc.value, held, set["changes"])

			continue
		}
		for option, value := range tc.options {
			if got := held.Options()[option]; got != value {
				t.Errorf("a %s set with %s=%q: the server has it as %q", tc.recordType, option, value, got)
			}
		}
		if again := suite.Call(t, "record_set", on(args)); acctest.BoolOf(again["changed"]) {
			t.Errorf("a %s set again as it is = %v", tc.recordType, again["changes"])
		}
	}

	// what a record has beside its value is in the rows, and a change of one option leaves the others
	rows := acctest.Rows(t, suite.Call(t, "zone_records", on(map[string]any{"zone": kindsForward, "types": []string{"FWD"}}))["records"], "records")
	if len(rows) != 1 || acctest.Object(t, rows[0]["options"], "options")["forwarderPriority"] != "5" || rows[0]["value"] != "Udp 10.69.1.53" {
		t.Errorf("the forwarder's row = %v", rows)
	}
	changed := suite.Call(t, "record_set", on(map[string]any{"zone": kindsForward, "name": "lab." + kindsForward, "type": "FWD", "value": "Udp 10.69.1.53", "options": map[string]string{"forwarderPriority": "9"}}))
	if now := heldRecord(t, kindsForward, "lab."+kindsForward, "FWD"); now == nil || now.Options()["forwarderPriority"] != "9" || now.Options()["dnssecValidation"] != "true" || now.Options()["proxyType"] != "NoProxy" || !slices.Equal(acctest.Strs(t, changed["changes"], "changes"), []string{`changed the FWD record at lab.` + kindsForward + `: its forwarderPriority from "5" to "9"`}) {
		t.Errorf("the forwarder with one option changed = %+v, and the tool said %v", now, changed["changes"])
	}
	// an NS record's TTL changed keeps its glue, which the server would drop
	suite.Call(t, "record_set", on(map[string]any{"zone": kindsZone, "name": "sub." + kindsZone, "type": "NS", "value": "ns.sub." + kindsZone, "ttl": 1200}))
	if now := heldRecord(t, kindsZone, "sub."+kindsZone, "NS"); now == nil || now.TTL != 1200 || now.Options()["glue"] != "10.69.1.9" {
		t.Errorf("the name server record after its TTL was changed = %+v", now)
	}
	for msg, args := range map[string]map[string]any{
		"a FWD record has no TTL":                   {"zone": kindsForward, "name": "lab." + kindsForward, "type": "FWD", "value": "Udp 10.69.1.53", "ttl": 300},
		"a TLSA record has no options":              {"zone": kindsZone, "name": "x." + kindsZone, "type": "TLSA", "value": "DANE-EE SPKI SHA2-256 " + hash, "options": map[string]string{"glue": "10.69.1.9"}},
		"is not added, changed or deleted as other": {"zone": kindsZone, "name": kindsZone, "type": "SOA", "value": "a b 1 2 3 4 5"},
	} {
		if got := suite.CallErr(t, "record_set", on(args)); !strings.Contains(got, msg) {
			t.Errorf("record_set %v = %q, want %q in it", args, got, msg)
		}
	}

	// each deleted by its one line
	gone := suite.Call(t, "record_delete", on(map[string]any{"zone": kindsZone, "name": "www." + kindsZone, "type": "HTTPS", "value": "1 . alpn=h2,h3"}))
	if len(acctest.Rows(t, gone["deleted"], "deleted")) != 1 || heldRecord(t, kindsZone, "www."+kindsZone, "HTTPS") != nil {
		t.Errorf("the HTTPS record deleted = %v", gone)
	}
	suite.Call(t, "record_delete", on(map[string]any{"zone": kindsForward, "name": "lab." + kindsForward, "type": "FWD", "all": true}))
	if heldRecord(t, kindsForward, "lab."+kindsForward, "FWD") != nil {
		t.Error("the forwarder record is still there after it was deleted")
	}
	suite.Call(t, "zone_delete", on(map[string]any{"zone": kindsZone}))
	suite.Call(t, "zone_delete", on(map[string]any{"zone": kindsForward}))
}

// A zone is given the keys a transfer and an update must be signed with, and
// loses them again; it numbers its changes by the day when told to; and with
// a second server, a copy of it is told where its primary is and how to
// transfer.
//
//nolint:paralleltest // it makes and deletes zones and gives the server a transfer key, which the tests reading the zones and the settings beside it would see
func TestZoneKeysSerialAndCopies(t *testing.T) {
	names(t)
	ctx := context.WithoutCancel(t.Context())
	first := mustClient(t, world.First)
	const key = "acc-zone-key.test"

	made := suite.Call(t, "zone_create", on(map[string]any{"zone": keyedZone, "serial_by_date": true}))
	if after := acctest.Object(t, made["after"], "after"); !acctest.BoolOf(after["serial_by_date"]) || acctest.Num(t, after["serial"], "serial") < 2026010100 {
		t.Errorf("a zone made to number its changes by the day = %v", made["after"])
	}
	suite.Call(t, "tsig_key_set", on(map[string]any{"name": key}))
	t.Cleanup(func() { _ = first.DeleteTSIGKey(ctx, key) })

	// a key the server has not got is refused, with the ones it has
	if msg := suite.CallErr(t, "zone_edit", on(map[string]any{"zone": keyedZone, "transfer_keys": []string{"acc-nothing.test"}})); !strings.Contains(msg, "has no transfer key named acc-nothing.test") || !strings.Contains(msg, key) {
		t.Errorf("a key that is not there = %q", msg)
	}
	keys := []map[string]any{{"key": key, "name": "*." + keyedZone, "types": []string{"A", "AAAA"}}, {"key": key, "name": "_acme-challenge." + keyedZone, "types": []string{"txt"}}}
	set := suite.Call(t, "zone_edit", on(map[string]any{"zone": keyedZone, "transfer_keys": []string{key}, "update_keys": keys, "serial_by_date": false}))
	options, err := first.ZoneOptions(ctx, keyedZone)
	if err != nil {
		t.Fatal(err)
	}
	if after := acctest.Object(t, set["after"], "after"); !slices.Equal(options.ZoneTransferTSIGKeyNames, []string{key}) || len(options.UpdateSecurityPolicies) != 2 || !slices.Equal(acctest.Strs(t, after["transfer_keys"], "transfer_keys"), []string{key}) || len(acctest.Strs(t, after["update_keys"], "update_keys")) != 2 || acctest.BoolOf(after["serial_by_date"]) || len(acctest.Strs(t, set["changes"], "changes")) != 3 {
		t.Errorf("the keys set = %v: the server holds transfer %v and update %+v", set["changes"], options.ZoneTransferTSIGKeyNames, options.UpdateSecurityPolicies)
	}
	if same := suite.Call(t, "zone_edit", on(map[string]any{"zone": keyedZone, "transfer_keys": []string{key}, "update_keys": keys})); acctest.BoolOf(same["changed"]) {
		t.Errorf("the keys set again as they are = %v", same["changes"])
	}
	suite.Call(t, "zone_edit", on(map[string]any{"zone": keyedZone, "transfer_keys": []string{}, "update_keys": []map[string]any{}}))
	if options, err = first.ZoneOptions(ctx, keyedZone); err != nil || len(options.ZoneTransferTSIGKeyNames) != 0 || len(options.UpdateSecurityPolicies) != 0 {
		t.Errorf("the keys cleared: the server holds transfer %v and update %+v, %v", options.ZoneTransferTSIGKeyNames, options.UpdateSecurityPolicies, err)
	}

	// a copy on the second server, told where its primary is and how to transfer
	if !alone() {
		second, from := mustClient(t, world.Second), world.Address(world.First)
		suite.Call(t, "zone_edit", on(map[string]any{"zone": keyedZone, "transfer": "Allow"}))
		copied := suite.Call(t, "zone_create", map[string]any{"server": world.Second, "zone": keyedZone, "type": "Secondary", "primary_addresses": []string{from}, "primary_protocol": "tcp"})
		t.Cleanup(func() { _ = second.DeleteZone(ctx, keyedZone) })
		if after := acctest.Object(t, copied["after"], "after"); after["type"] != "Secondary" || !slices.Equal(acctest.Strs(t, after["primary_addresses"], "primary_addresses"), []string{from}) || after["primary_protocol"] != "Tcp" {
			t.Errorf("a copy as it was made = %v", copied["after"])
		}
		moved := suite.Call(t, "zone_edit", map[string]any{"server": world.Second, "zone": keyedZone, "primary_addresses": []string{from, "10.69.1.3"}, "primary_protocol": "Tls", "validate_zone": true})
		held, readErr := second.ZoneOptions(ctx, keyedZone)
		// told to transfer over TLS, the server holds the addresses with the port for it, which the tool does not take for a difference: the same again changes nothing
		if readErr != nil || !slices.Equal(held.PrimaryNameServerAddresses, []string{from + ":853", "10.69.1.3:853"}) || held.PrimaryZoneTransferProtocol != "Tls" || !held.ValidateZone || len(acctest.Strs(t, moved["changes"], "changes")) != 3 {
			t.Errorf("a copy told otherwise = %v: the server holds %+v, %v", moved["changes"], held, readErr)
		}
		if again := suite.Call(t, "zone_edit", map[string]any{"server": world.Second, "zone": keyedZone, "primary_addresses": []string{from, "10.69.1.3"}, "primary_protocol": "Tls", "validate_zone": true}); acctest.BoolOf(again["changed"]) {
			t.Errorf("a copy told the same again = %v", again["changes"])
		}
		suite.Call(t, "zone_delete", map[string]any{"server": world.Second, "zone": keyedZone})
	}

	suite.Call(t, "tsig_key_delete", on(map[string]any{"name": key}))
	suite.Call(t, "zone_delete", on(map[string]any{"zone": keyedZone}))
}

// A scope is made with the rest of what it can hand out, read back with it,
// left alone when set again, renamed and deleted.
//
//nolint:paralleltest // it makes a scope, which the tests of the servers' DHCP beside it would count
func TestScopeTheRest(t *testing.T) {
	names(t)
	ctx := context.WithoutCancel(t.Context())
	first := mustClient(t, world.First)
	const scope, renamed = "acc-whole", "acc-whole-renamed"
	_ = first.DeleteScope(ctx, scope)
	_ = first.DeleteScope(ctx, renamed)
	t.Cleanup(func() {
		_ = first.DeleteScope(ctx, scope)
		_ = first.DeleteScope(ctx, renamed)
	})

	args := map[string]any{"scope": scope, "first": "10.69.9.10", "last": "10.69.9.20", "mask": "24", "ntp_servers": []string{"10.69.9.7"}, "ntp_server_names": []string{"ntp.acc-whole.test"}, "domain_search": []string{"acc-whole.test"}, "static_routes": []string{"10.70.0.0/16 via 10.69.9.2"}, "boot_server": "10.69.9.5", "boot_file": "boot.bin", "tftp_servers": []string{"10.69.9.5"}, "generic_options": []map[string]any{{"code": 160, "value": "0A:45:09:05"}}, "vendor_info": []map[string]any{{"identifier": "PXEClient", "information": "06:01:03"}}, "ping_check": true, "ping_retries": 3, "offer_delay_ms": 250, "block_local_mac": true}
	made := suite.Call(t, "dhcp_scope_set", on(args))
	more := acctest.Object(t, acctest.Object(t, made["after"], "after")["more"], "more")
	if !slices.Equal(acctest.Strs(t, more["static_routes"], "static_routes"), []string{"10.70.0.0/16 via 10.69.9.2"}) || !slices.Equal(acctest.Strs(t, more["ntp_servers"], "ntp_servers"), []string{"10.69.9.7"}) || more["boot_file"] != "boot.bin" || !acctest.BoolOf(more["ping_check"]) || acctest.Num(t, more["ping_retries"], "ping_retries") != 3 || acctest.Num(t, more["offer_delay_ms"], "offer_delay_ms") != 250 || !acctest.BoolOf(more["block_local_mac"]) {
		t.Errorf("the scope as it was made = %v", more)
	}
	held, err := first.Scope(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(held.GenericOptions) != 1 || held.GenericOptions[0].Code != 160 || len(held.VendorInfo) != 1 || held.ServerAddress != "10.69.9.5" || !slices.Equal(held.TFTPServerAddresses, []string{"10.69.9.5"}) || !slices.Equal(held.NTPServerDomainNames, []string{"ntp.acc-whole.test"}) || !slices.Equal(held.DomainSearchList, []string{"acc-whole.test"}) {
		t.Errorf("the scope on the server = %+v", held)
	}
	if again := suite.Call(t, "dhcp_scope_set", on(args)); acctest.BoolOf(again["changed"]) {
		t.Errorf("the scope set again as it is = %v", again["changes"])
	}

	// one list cleared and the scope renamed: the rest is kept
	moved := suite.Call(t, "dhcp_scope_set", on(map[string]any{"scope": scope, "new_name": renamed, "static_routes": []string{}}))
	if held, err = first.Scope(ctx, renamed); err != nil || len(held.StaticRoutes) != 0 || held.BootFileName != "boot.bin" || moved["scope"] != renamed {
		t.Errorf("the scope renamed with its routes cleared = %v: the server holds %+v, %v", moved["changes"], held, err)
	}
	if msg := suite.CallErr(t, "dhcp_scope_set", on(map[string]any{"scope": renamed, "static_routes": []string{"somewhere via nothing"}})); !strings.Contains(msg, "is not one") {
		t.Errorf("a route that is none = %q", msg)
	}
	suite.Call(t, "dhcp_scope_delete", on(map[string]any{"scope": renamed}))
	if _, err := first.Scope(ctx, renamed); err == nil {
		t.Error("the scope is still there after it was deleted")
	}
}

// A name's records are copied in from a name server, and the smaller things
// the reading tools pass on are taken by a real server.
//
//nolint:paralleltest // it makes and deletes a zone, which a test reading every zone beside it would list and then not find
func TestImportAndTheRest(t *testing.T) {
	names(t)
	suite.Call(t, "zone_create", on(map[string]any{"zone": importZone}))
	suite.Call(t, "record_set", on(map[string]any{"zone": importZone, "name": "www." + importZone, "type": "A", "value": "10.69.2.10", "comment": "by hand"}))

	// asked of the server itself at its own loopback: what it answers is written over what it holds, which is the same records without their comment
	dry := suite.Call(t, "dns_import", on(map[string]any{"name": "www." + importZone, "from": "127.0.0.1", "dry_run": true}))
	if dry["zone"] != importZone || len(acctest.Strs(t, dry["records"], "records")) != 1 || !strings.HasPrefix(acctest.Strs(t, dry["changes"], "changes")[0], "would have copied 1 records for A www."+importZone) {
		t.Errorf("a dry run = %v", dry)
	}
	if held := heldRecord(t, importZone, "www."+importZone, "A"); held == nil || held.Comments != "by hand" {
		t.Errorf("the record after a dry run = %+v", held)
	}
	out := suite.Call(t, "dns_import", on(map[string]any{"name": "www." + importZone, "from": "127.0.0.1"}))
	if after := acctest.Rows(t, out["after"], "after"); len(after) != 1 || after[0]["value"] != "10.69.2.10" || !acctest.BoolOf(out["changed"]) {
		t.Errorf("copied in = %v", out)
	}
	if nothing := suite.Call(t, "dns_import", on(map[string]any{"name": "gone." + importZone, "from": "127.0.0.1"})); acctest.BoolOf(nothing["changed"]) || !strings.Contains(acctest.Str(nothing["note"]), "there is nothing to copy in") {
		t.Errorf("a name with no record, copied in = %v", nothing)
	}

	// asked as if from a network; the statistics their other ways; a list walked upward; the log by the class asked in
	if rows := acctest.Rows(t, suite.Call(t, "dns_resolve", on(map[string]any{"name": "www." + importZone, "client_subnet": "203.0.113.0/24"}))["answers"], "answers"); len(rows) == 0 || rows[0]["result"] != "NoError" {
		t.Errorf("asked as if from a network = %v", rows)
	}
	if rows := acctest.Rows(t, suite.Call(t, "server_stats", map[string]any{"every_type": true, "rate_limited": true, "by_address_only": true})["servers"], "servers"); len(rows) != len(world.Names()) {
		t.Errorf("the statistics asked for their other ways = %v", rows)
	}
	suite.Call(t, "block_set", on(map[string]any{"name": "tree.acc-above.example"}))
	up := acctest.Rows(t, suite.Call(t, "block_tree", on(map[string]any{"under": "acc-above.example", "above": true}))["servers"], "servers")[0]
	down := acctest.Rows(t, suite.Call(t, "block_tree", on(map[string]any{"under": "acc-above.example"}))["servers"], "servers")[0]
	if down["at"] != "tree.acc-above.example" || !acctest.BoolOf(down["listed"]) || up["at"] == down["at"] || up["at"] == "acc-above.example" {
		t.Errorf("a name that only leads on: below is %v and above is %v", down, up)
	}
	suite.Call(t, "block_delete", on(map[string]any{"name": "tree.acc-above.example"}))
	if searched := suite.Call(t, "log_search", map[string]any{"class": "ch", "last": "1h"}); acctest.Num(t, searched["total"], "total") != 0 {
		t.Errorf("queries asked in the CH class, of which a test makes none = %v", searched["total"])
	}
	suite.Call(t, "log_export", map[string]any{"class": "IN", "last": "1h", "limit": 5})
	suite.Call(t, "zone_delete", on(map[string]any{"zone": importZone}))
}

// A forwarder that is not there is found by asking it: the server is given
// one, the audit says so by its address, and with the forwarder taken off
// again it has nothing to say of it.
//
//nolint:paralleltest // it sets the server's forwarders, which every test that has the server resolve a name beside it would be sent to
func TestAuditFindsAForwarderThatIsNotThere(t *testing.T) {
	names(t)
	ctx := context.WithoutCancel(t.Context())
	first := mustClient(t, world.First)
	const nowhere = "10.255.255.1"
	before, err := first.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Forwarders) != 0 {
		t.Fatalf("the test servers resolve for themselves, and %s has the forwarders %v", world.First, before.Forwarders)
	}
	// in a cluster the forwarders are the primary's to set and reach the other node a few seconds later: the test ends only when no server has one, or the tests after it would be sent there
	gone := func() bool {
		for _, name := range world.Names() {
			if now, readErr := mustClient(t, name).Settings(ctx); readErr != nil || len(now.Forwarders) != 0 {
				return false
			}
		}

		return true
	}
	t.Cleanup(func() {
		_, _ = first.SetSettings(ctx, map[string]string{"forwarders": "false"})
		if !acctest.EventuallyWithin(2*time.Minute, gone) {
			t.Error("a server still has the forwarder this test set")
		}
	})

	suite.Call(t, "settings_set", on(map[string]any{"settings": map[string]string{"forwarders": nowhere}}))
	found := acctest.Rows(t, suite.Call(t, "audit_queries", on(map[string]any{"limit": 1000}))["findings"], "findings")
	if !has(found, "forwarder_unanswering", nowhere) {
		t.Errorf("with a forwarder that is not there the audit found %v", found)
	}
	suite.Call(t, "settings_set", on(map[string]any{"settings": map[string]string{"forwarders": "false"}}))
	if found = acctest.Rows(t, suite.Call(t, "audit_queries", on(map[string]any{"limit": 1000}))["findings"], "findings"); has(found, "forwarder_unanswering", nowhere) {
		t.Errorf("with the forwarder taken off again the audit still found %v", found)
	}
}
