package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// The keys of a signed zone, and its DS, as a server gives them.
const (
	signedKeys = `{"name":"example.com","type":"Primary","dnssecStatus":"SignedWithNSEC","dnsKeyTtl":3600,"dnssecPrivateKeys":[{"keyTag":11,"keyType":"KeySigningKey","algorithm":"ECDSAP256SHA256","state":"Published","stateChangedOn":"2026-10-01T00:00:00Z","stateReadyBy":"2026-10-01T05:00:00Z","rolloverDays":0},{"keyTag":22,"keyType":"ZoneSigningKey","algorithm":"ECDSAP256SHA256","state":"Active","rolloverDays":30},{"keyTag":33,"keyType":"ZoneSigningKey","algorithm":"ECDSAP256SHA256","state":"Generated","rolloverDays":0}]}`
	signedDS   = `{"name":"example.com","type":"Primary","dnssecStatus":"SignedWithNSEC","dsRecords":[{"keyTag":11,"dnsKeyState":"Published","dnsKeyStateReadyBy":"2026-10-01T05:00:00Z","algorithm":"ECDSAP256SHA256","publicKey":"cHVibGlj","digests":[{"digestType":"SHA256","digest":"AB12"},{"digestType":"SHA384","digest":"CD34"}]}]}`
)

// signedPair is the pair with dock's zone signed, and every call that
// changes a zone's signing answered.
func signedPair(t *testing.T) *pair {
	t.Helper()

	p := setupPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7,"dnssecStatus":"SignedWithNSEC"},{"name":"only.example","type":"Primary","soaSerial":1,"dnssecStatus":"Unsigned"}]}`)
	p.dock.Answer("zones/dnssec/properties/get", signedKeys)
	p.dock.AnswerWhen("zones/dnssec/properties/get", "zone", "only.example", `{"name":"only.example","type":"Primary","dnssecStatus":"Unsigned","dnsKeyTtl":0,"dnssecPrivateKeys":[]}`)
	p.dock.Answer("zones/dnssec/viewDS", signedDS)
	for _, call := range []string{"sign", "unsign", "properties/convertToNSEC", "properties/convertToNSEC3", "properties/updateNSEC3Params", "properties/updateDnsKeyTtl", "properties/addPrivateKey", "properties/updatePrivateKey", "properties/deletePrivateKey", "properties/publishAllPrivateKeys", "properties/rolloverDnsKey", "properties/retireDnsKey"} {
		p.dock.Answer("zones/dnssec/"+call, `{}`)
	}

	return p
}

// signingCalls are how many calls that change a zone's signing a server got.
func signingCalls(server *technitiumtest.Server) int {
	n := 0
	for _, call := range []string{"sign", "unsign", "properties/convertToNSEC", "properties/convertToNSEC3", "properties/updateNSEC3Params", "properties/updateDnsKeyTtl", "properties/addPrivateKey", "properties/updatePrivateKey", "properties/deletePrivateKey", "properties/publishAllPrivateKeys", "properties/rolloverDnsKey", "properties/retireDnsKey"} {
		n += len(server.Requests("zones/dnssec/" + call))
	}

	return n
}

func TestDNSSECGet(t *testing.T) {
	t.Parallel()

	p := signedPair(t)
	suite := p.session(t, Options{})

	out := suite.Call(t, "dnssec_get", map[string]any{"zone": "Example.com."})
	rows := acctest.Rows(t, out["servers"], "servers")
	if len(rows) != 2 || out["missing_on"] != nil {
		t.Fatalf("dnssec_get = %v", out)
	}
	d := rows[0]
	keys := acctest.Rows(t, d["keys"], "keys")
	if d["server"] != "dock" || d["status"] != "SignedWithNSEC" || acctest.Num(t, d["dnskey_ttl"], "dnskey_ttl") != 3600 || len(keys) != 3 {
		t.Fatalf("dock's signing = %v", d)
	}
	if k := keys[0]; acctest.Num(t, k["key_tag"], "key_tag") != 11 || k["type"] != "KeySigningKey" || k["state"] != "Published" || k["changed_on"] != "2026-10-01T00:00:00Z" || k["ready_by"] != "2026-10-01T05:00:00Z" || k["rollover_days"] != nil {
		t.Errorf("the key signing key = %v", k)
	}
	if ds := acctest.Rows(t, d["ds"], "ds"); len(ds) != 1 || acctest.Num(t, ds[0]["key_tag"], "key_tag") != 11 || !slices.Equal(acctest.Strs(t, ds[0]["digests"], "digests"), []string{"SHA256 AB12", "SHA384 CD34"}) || ds[0]["public_key"] != "cHVibGlj" {
		t.Errorf("the DS = %v", d["ds"])
	}
	// a copy has no keys to read, and is not asked for any
	if r := rows[1]; r["server"] != "rpi" || r["type"] != "Secondary" || r["keys"] != nil || len(p.rpi.Requests("zones/dnssec/properties/get")) != 0 {
		t.Errorf("the copy's signing = %v", r)
	}
	// a zone that is not signed says so, and its DS is not asked for
	if only := acctest.Rows(t, suite.Call(t, "dnssec_get", map[string]any{"zone": "only.example"})["servers"], "servers"); len(only) != 1 || only[0]["status"] != "Unsigned" || only[0]["ds"] != nil || len(p.dock.Requests("zones/dnssec/viewDS")) != 1 {
		t.Errorf("a zone that is not signed = %v", only)
	}
	if msg := suite.CallErr(t, "dnssec_get", map[string]any{"zone": "nothing.example"}); !strings.Contains(msg, "no server asked holds a zone named nothing.example") {
		t.Errorf("a zone nobody holds = %q", msg)
	}
}

func TestDNSSECSignAndUnsign(t *testing.T) {
	t.Parallel()

	p := signedPair(t)
	suite := p.session(t, everything)

	// what an algorithm needs is filled in, and nothing else is sent
	dry := suite.Call(t, "dnssec_sign", map[string]any{"server": "dock", "zone": "only.example", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have signed only.example on dock with ECDSA P256, proving what is not there with NSEC"}) || signingCalls(p.dock) != 0 {
		t.Errorf("a dry run of signing = %v", dry)
	}
	suite.Call(t, "dnssec_sign", map[string]any{"server": "dock", "zone": "only.example"})
	if asked := p.dock.Last("zones/dnssec/sign"); len(asked.Params) != 3 || asked.Params.Get("zone") != "only.example" || asked.Params.Get("algorithm") != "ECDSA" || asked.Params.Get("curve") != "P256" {
		t.Errorf("signed with %v", asked.Params)
	}
	rsa := suite.Call(t, "dnssec_sign", map[string]any{"server": "dock", "zone": "only.example", "algorithm": "rsa", "nx_proof": "nsec3", "salt_length": 8, "zsk_rollover_days": 0, "dnskey_ttl": 7200})
	asked := p.dock.Last("zones/dnssec/sign")
	for param, want := range map[string]string{"algorithm": "RSA", "hashAlgorithm": "SHA256", "kskKeySize": "2048", "zskKeySize": "1280", "nxProof": "NSEC3", "iterations": "0", "saltLength": "8", "zskRolloverDays": "0", "dnsKeyTtl": "7200"} {
		if asked.Params.Get(param) != want {
			t.Errorf("signed with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if asked.Params.Has("curve") || !strings.Contains(acctest.Strs(t, rsa["changes"], "changes")[0], "RSA SHA256 with keys of 2048 and 1280 bits, proving what is not there with NSEC3") {
		t.Errorf("signed with RSA = %v, with %v", rsa["changes"], asked.Params)
	}

	sent := signingCalls(p.dock) + signingCalls(p.rpi)
	for msg, args := range map[string]map[string]any{
		"example.com is signed already on dock":     {"server": "dock", "zone": "example.com"},
		"rpi holds example.com as a Secondary zone": {"server": "rpi", "zone": "example.com"},
		`algorithm "DSA"`:                           {"server": "dock", "zone": "only.example", "algorithm": "dsa"},
		`nx_proof "NSEC5"`:                          {"server": "dock", "zone": "only.example", "nx_proof": "NSEC5"},
		"zsk_rollover_days is 0 to 365":             {"server": "dock", "zone": "only.example", "zsk_rollover_days": 400},
		"dock holds no zone named nothing.example":  {"server": "dock", "zone": "nothing.example"},
	} {
		if got := suite.CallErr(t, "dnssec_sign", args); !strings.Contains(got, msg) {
			t.Errorf("dnssec_sign %v = %q, want %q in it", args, got, msg)
		}
	}

	// unsigned: what would go is counted, and a zone that is not signed has nothing to take off
	dry = suite.Call(t, "dnssec_unsign", map[string]any{"server": "dock", "zone": "example.com", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have removed DNSSEC from example.com on dock, deleting its 3 keys"}) || len(p.dock.Requests("zones/dnssec/unsign")) != 0 {
		t.Errorf("a dry run of unsigning = %v", dry)
	}
	if nothing := suite.Call(t, "dnssec_unsign", map[string]any{"server": "dock", "zone": "only.example"}); acctest.BoolOf(nothing["changed"]) || !strings.Contains(acctest.Str(nothing["note"]), "is not signed") {
		t.Errorf("a zone that is not signed, unsigned = %v", nothing)
	}
	if now := signingCalls(p.dock) + signingCalls(p.rpi); now != sent {
		t.Errorf("%d calls reached a server that should not have", now-sent)
	}
	if out := suite.Call(t, "dnssec_unsign", map[string]any{"server": "dock", "zone": "example.com"}); !acctest.BoolOf(out["changed"]) || p.dock.Last("zones/dnssec/unsign").Params.Get("zone") != "example.com" || !strings.Contains(acctest.Str(out["note"]), "DS record") {
		t.Errorf("unsigned = %v", out)
	}
}

func TestDNSSECEditAndKeys(t *testing.T) {
	t.Parallel()

	p := signedPair(t)
	suite := p.session(t, everything)

	// the proof and its parameters, each sent only when it is to change
	out := suite.Call(t, "dnssec_edit", map[string]any{"server": "dock", "zone": "example.com", "nx_proof": "NSEC3", "iterations": 2, "salt_length": 4, "dnskey_ttl": 7200})
	if got := acctest.Strs(t, out["changes"], "changes"); len(got) != 3 || got[0] != "changed example.com on dock from NSEC to NSEC3" || got[1] != "set the NSEC3 of example.com on dock to 2 iterations and a salt of 4 bytes" || got[2] != "set the TTL of the DNSKEY records of example.com on dock to 7200 seconds" {
		t.Errorf("edited = %v", got)
	}
	if params := p.dock.Last("zones/dnssec/properties/updateNSEC3Params").Params; params.Get("iterations") != "2" || params.Get("saltLength") != "4" || p.dock.Last("zones/dnssec/properties/updateDnsKeyTtl").Params.Get("ttl") != "7200" || len(p.dock.Requests("zones/dnssec/properties/convertToNSEC3")) != 1 {
		t.Errorf("the NSEC3 was set with %v", params)
	}
	if same := suite.Call(t, "dnssec_edit", map[string]any{"server": "dock", "zone": "example.com", "nx_proof": "NSEC"}); acctest.BoolOf(same["changed"]) || len(p.dock.Requests("zones/dnssec/properties/convertToNSEC")) != 0 {
		t.Errorf("set to the proof it has = %v", same)
	}
	for msg, args := range map[string]map[string]any{
		"nothing was given to change":            {"server": "dock", "zone": "example.com"},
		"iterations and salt_length are NSEC3's": {"server": "dock", "zone": "example.com", "iterations": 1},
		"only.example is not signed on dock":     {"server": "dock", "zone": "only.example", "nx_proof": "NSEC3"},
	} {
		if got := suite.CallErr(t, "dnssec_edit", args); !strings.Contains(got, msg) {
			t.Errorf("dnssec_edit %v = %q, want %q in it", args, got, msg)
		}
	}

	// a key added: its type is read as it is written or by its initials, and it is published only when asked
	added := suite.Call(t, "dnssec_key_add", map[string]any{"server": "dock", "zone": "example.com", "key_type": "zsk", "rollover_days": 30, "publish": true})
	if asked := p.dock.Last("zones/dnssec/properties/addPrivateKey"); asked.Params.Get("keyType") != "ZoneSigningKey" || asked.Params.Get("algorithm") != "ECDSA" || asked.Params.Get("curve") != "P256" || asked.Params.Get("rolloverDays") != "30" || len(p.dock.Requests("zones/dnssec/properties/publishAllPrivateKeys")) != 1 || len(acctest.Strs(t, added["changes"], "changes")) != 2 {
		t.Errorf("a key added = %v, with %v", added["changes"], asked.Params)
	}
	suite.Call(t, "dnssec_key_add", map[string]any{"server": "dock", "zone": "example.com", "key_type": "KeySigningKey", "algorithm": "RSA"})
	if asked := p.dock.Last("zones/dnssec/properties/addPrivateKey"); asked.Params.Get("keySize") != "2048" || asked.Params.Get("hashAlgorithm") != "SHA256" || len(p.dock.Requests("zones/dnssec/properties/publishAllPrivateKeys")) != 1 {
		t.Errorf("an RSA key signing key was added with %v", asked.Params)
	}
	if msg := suite.CallErr(t, "dnssec_key_add", map[string]any{"server": "dock", "zone": "example.com", "key_type": "csk"}); !strings.Contains(msg, `key_type "csk"`) {
		t.Errorf("a key of no type = %q", msg)
	}

	// a key moved along: published only when one is only generated, rolled over and retired by its tag, its rollover set only when it differs
	if got := acctest.Strs(t, suite.Call(t, "dnssec_key_edit", map[string]any{"server": "dock", "zone": "example.com", "action": "publish"})["changes"], "changes"); !slices.Equal(got, []string{"published the 1 keys of example.com that were only generated"}) {
		t.Errorf("published = %v", got)
	}
	if got := acctest.Strs(t, suite.Call(t, "dnssec_key_edit", map[string]any{"server": "dock", "zone": "example.com", "action": "Rollover", "key_tag": 22, "rollover_days": 60})["changes"], "changes"); !slices.Equal(got, []string{"set the key 22 of example.com to be replaced every 60 days", "rolled the ZoneSigningKey 22 of example.com over to a new key"}) || p.dock.Last("zones/dnssec/properties/updatePrivateKey").Params.Get("rolloverDays") != "60" || p.dock.Last("zones/dnssec/properties/rolloverDnsKey").Params.Get("keyTag") != "22" {
		t.Errorf("rolled over = %v", got)
	}
	if same := suite.Call(t, "dnssec_key_edit", map[string]any{"server": "dock", "zone": "example.com", "key_tag": 22, "rollover_days": 30}); acctest.BoolOf(same["changed"]) || len(p.dock.Requests("zones/dnssec/properties/updatePrivateKey")) != 1 {
		t.Errorf("a rollover set to what it is = %v", same)
	}
	if got := acctest.Strs(t, suite.Call(t, "dnssec_key_edit", map[string]any{"server": "dock", "zone": "example.com", "action": "retire", "key_tag": 22, "dry_run": true})["changes"], "changes"); !slices.Equal(got, []string{"would have retired the ZoneSigningKey 22 of example.com"}) || len(p.dock.Requests("zones/dnssec/properties/retireDnsKey")) != 0 {
		t.Errorf("a dry run of retiring = %v", got)
	}
	for msg, args := range map[string]map[string]any{
		"has no key with the tag 99": {"server": "dock", "zone": "example.com", "action": "retire", "key_tag": 99},
		`action "revoke"`:            {"server": "dock", "zone": "example.com", "action": "revoke", "key_tag": 22},
		"nothing was given to do":    {"server": "dock", "zone": "example.com", "key_tag": 22},
		"rollover_days is 0 to 365":  {"server": "dock", "zone": "example.com", "key_tag": 22, "rollover_days": -1},
	} {
		if got := suite.CallErr(t, "dnssec_key_edit", args); !strings.Contains(got, msg) {
			t.Errorf("dnssec_key_edit %v = %q, want %q in it", args, got, msg)
		}
	}

	// a key is deleted only while it is only generated
	if msg := suite.CallErr(t, "dnssec_key_delete", map[string]any{"server": "dock", "zone": "example.com", "key_tag": 22}); !strings.Contains(msg, "the key 22 of example.com is Active") || len(p.dock.Requests("zones/dnssec/properties/deletePrivateKey")) != 0 {
		t.Errorf("a key in use, deleted = %q", msg)
	}
	if gone := suite.Call(t, "dnssec_key_delete", map[string]any{"server": "dock", "zone": "example.com", "key_tag": 33}); !acctest.BoolOf(gone["changed"]) || p.dock.Last("zones/dnssec/properties/deletePrivateKey").Params.Get("keyTag") != "33" {
		t.Errorf("a generated key deleted = %v", gone)
	}
}
