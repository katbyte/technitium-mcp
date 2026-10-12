//go:build acceptance

// Journeys: the tools chained the way a real session chains them, against
// state the server changes underneath, across accounts, and repeated. The
// per-tool tests prove each tool answers; these prove that what one tool
// changed is what the next one sees, and that the server did what the tool
// said it did - an ok from Technitium is not proof, so what a journey changes
// is read back from the server itself, by the client and not by a tool.
//
// A journey makes the zones it needs and takes them away again, so none of
// them runs beside the other tests: several tools read every zone a server
// lists, and a zone deleted between the listing and the reading is one they
// could not read.
package tools_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// The zones the journeys make and delete again.
const (
	hostZone     = "acc-j-host.test"
	hostReverse  = "0.66.10.in-addr.arpa"
	messZone     = "acc-j-mess.test"
	messReverse  = "0.67.10.in-addr.arpa"
	lifeZone     = "acc-j-life.test"
	lifeClone    = "acc-j-life-two.test"
	restoredZone = "acc-j-restored.test"
	busyZone     = "acc-j-busy.test"
	bothZone     = "acc-j-both.test"
)

// journeyZones makes zones on the first server for the length of a journey,
// through the tool, and takes them away from every server when it ends,
// whatever state the journey left them in.
func journeyZones(t *testing.T, zones ...string) {
	t.Helper()

	names(t)
	ctx := context.WithoutCancel(t.Context())
	remove := func() {
		for _, srv := range world.Set.Every() {
			for _, zone := range zones {
				_ = srv.Client.DeleteZone(ctx, zone)
			}
		}
	}
	remove()
	t.Cleanup(remove)
	for _, zone := range zones {
		// a reverse zone is asked for by its network
		asked := zone
		if labels := strings.Split(strings.TrimSuffix(zone, ".in-addr.arpa"), "."); strings.HasSuffix(zone, ".in-addr.arpa") && len(labels) == 3 {
			asked = labels[2] + "." + labels[1] + "." + labels[0] + ".0/24"
		}
		if made := suite.Call(t, "zone_create", on(map[string]any{"zone": asked})); made["zone"] != zone {
			t.Fatalf("zone_create %s made %v", asked, made["zone"])
		}
	}
}

// onServer are the values of the records of a type at a name as a server
// itself holds them, read by the client and not by a tool.
func onServer(t *testing.T, server, zone, name, recordType string) []string {
	t.Helper()

	at, err := mustClient(t, server).RecordsAt(t.Context(), name, zone)
	if err != nil {
		t.Fatalf("reading %s on %s: %v", name, server, err)
	}
	var values []string
	for i := range at.Records {
		if rec := &at.Records[i]; rec.Type == recordType && strings.EqualFold(rec.Name, name) && !rec.Disabled {
			values = append(values, rec.Value())
		}
	}
	slices.Sort(values)

	return values
}

// findingsIn are what an audit finds in one zone.
func findingsIn(t *testing.T, audit, zone string) []map[string]any {
	t.Helper()

	return acctest.Rows(t, suite.Call(t, audit, on(map[string]any{"zone": zone, "limit": 1000}))["findings"], "findings")
}

// has reports whether findings hold one of a kind at a name.
func has(found []map[string]any, problem, name string) bool {
	return slices.ContainsFunc(found, func(f map[string]any) bool { return f["problem"] == problem && f["name"] == name })
}

// A host moved to a new address: everything that reaches the old address is
// found, the move is rehearsed and changes nothing, then made, and every name
// and the PTR follow - which the server says for itself, and the audits
// agree. Asked again, there is nothing left to move.
//
//nolint:paralleltest // it makes and deletes zones, which a test reading every zone beside it would list and then not find
func TestJourneyAHostMovedToANewAddress(t *testing.T) {
	journeyZones(t, hostZone, hostReverse)
	first := world.First
	const was, now = "10.66.0.4", "10.66.0.7"
	media, other, tv, films := "media."+hostZone, "other."+hostZone, "tv."+hostZone, "films."+hostZone

	// the host as it stands: two names at the address, with the PTR, and two aliases down a chain
	suite.Call(t, "record_set", on(map[string]any{"name": media, "type": "A", "value": was, "ptr": true, "comment": "the media server"}))
	suite.Call(t, "record_set", on(map[string]any{"name": other, "type": "A", "value": was}))
	suite.Call(t, "record_set", on(map[string]any{"name": tv, "type": "CNAME", "value": media}))
	suite.Call(t, "record_set", on(map[string]any{"name": films, "type": "CNAME", "value": tv}))
	if ptr := onServer(t, first, hostReverse, "4."+hostReverse, "PTR"); !slices.Equal(ptr, []string{media}) {
		t.Fatalf("the PTR record_set made with the address = %v", ptr)
	}

	// what reaches the old address: both names, the PTR, and the aliases by their chain
	reaching := func(address string) []string {
		t.Helper()
		rows := acctest.Rows(t, suite.Call(t, "record_find", on(map[string]any{"address": address}))["records"], "records")
		names := make([]string, 0, len(rows))
		for _, row := range rows {
			names = append(names, acctest.Str(row["name"])+" "+acctest.Str(row["type"]))
		}
		slices.Sort(names)

		return names
	}
	if got := reaching(was); !slices.Equal(got, []string{"4." + hostReverse + " PTR", films + " CNAME", media + " A", other + " A", tv + " CNAME"}) {
		t.Fatalf("what reaches %s = %v", was, got)
	}
	// the names a session was asked about: the two that exist end at the address, and the one that does not is said not to
	checked := suite.Call(t, "audit_names", on(map[string]any{"names": []string{films, tv, "music." + hostZone}}))
	counts := acctest.Object(t, checked["counts"], "counts")
	if films := rowFor(t, acctest.Rows(t, checked["names"], "names"), "name", films); acctest.Num(t, counts["exists"], "exists") != 2 || acctest.Num(t, counts["missing"], "missing") != 1 || !slices.Equal(acctest.Strs(t, films["ends_at"], "ends_at"), []string{was}) || rowFor(t, acctest.Rows(t, checked["names"], "names"), "name", "music."+hostZone)["status"] != "missing" {
		t.Errorf("audit_names of two names that exist and one that does not = %v", checked)
	}

	// rehearsed, nothing moves: the server still has every record where it was
	dry := suite.Call(t, "record_repoint", on(map[string]any{"from": was, "to": now, "dry_run": true}))
	if len(acctest.Strs(t, dry["changes"], "changes")) < 3 || !slices.Equal(onServer(t, first, hostZone, media, "A"), []string{was}) || len(onServer(t, first, hostReverse, "4."+hostReverse, "PTR")) != 1 || len(onServer(t, first, hostReverse, "7."+hostReverse, "PTR")) != 0 {
		t.Fatalf("a dry run of the move = %v, and the server has media at %v", dry["changes"], onServer(t, first, hostZone, media, "A"))
	}

	// made: both names are at the new address, the PTR is at the new one and gone from the old, and the comment is kept
	moved := suite.Call(t, "record_repoint", on(map[string]any{"from": was, "to": now}))
	if len(acctest.Rows(t, moved["repointed"], "repointed")) != 2 {
		t.Errorf("repointed = %v", moved["repointed"])
	}
	for _, name := range []string{media, other} {
		if got := onServer(t, first, hostZone, name, "A"); !slices.Equal(got, []string{now}) {
			t.Errorf("after the move the server has %s at %v", name, got)
		}
	}
	if oldPTR, newPTR := onServer(t, first, hostReverse, "4."+hostReverse, "PTR"), onServer(t, first, hostReverse, "7."+hostReverse, "PTR"); len(oldPTR) != 0 || !slices.Equal(newPTR, []string{media}) {
		t.Errorf("after the move the PTR at the old address = %v and at the new = %v", oldPTR, newPTR)
	}
	at, err := mustClient(t, first).RecordsAt(t.Context(), media, hostZone)
	if err != nil || len(at.Records) != 1 || at.Records[0].Comments != "the media server" {
		t.Errorf("the record's comment after the move = %+v, %v", at, err)
	}

	// the next tools see what the last one did: nothing reaches the old address, everything the new, and the alias resolves there
	if got := reaching(was); len(got) != 0 {
		t.Errorf("what still reaches %s = %v", was, got)
	}
	if got := reaching(now); !slices.Equal(got, []string{"7." + hostReverse + " PTR", films + " CNAME", media + " A", other + " A", tv + " CNAME"}) {
		t.Errorf("what reaches %s = %v", now, got)
	}
	if resolved := fmt.Sprint(suite.Call(t, "dns_resolve", on(map[string]any{"name": films}))["answers"]); !strings.Contains(resolved, now) || strings.Contains(resolved, was) {
		t.Errorf("films resolves to %v", resolved)
	}
	for _, audit := range []string{"audit_reverse", "audit_targets"} {
		for _, zone := range []string{hostZone, hostReverse} {
			if found := findingsIn(t, audit, zone); len(found) != 0 {
				t.Errorf("%s finds this in %s after the move: %v", audit, zone, found)
			}
		}
	}

	// asked again there is nothing at the old address to move, and the server is as it was left
	again := suite.Call(t, "record_repoint", on(map[string]any{"from": was, "to": now}))
	if len(acctest.RowsOf(again["repointed"])) != 0 || len(acctest.Texts(again["changes"])) != 0 || !slices.Equal(onServer(t, first, hostZone, media, "A"), []string{now}) {
		t.Errorf("the move made twice = %v", again)
	}
}

// What the audits find, the tools they name put right, and the audits then
// find nothing: a CNAME that ends nowhere, a TTL of seconds, a host with an
// underscore, a record switched off, and an address with no PTR.
//
//nolint:paralleltest // it makes and deletes zones, which a test reading every zone beside it would list and then not find
func TestJourneyEveryFixableFindingIsFixed(t *testing.T) {
	journeyZones(t, messZone, messReverse)
	gone, fast, bad, off, bare := "gone."+messZone, "fast."+messZone, "bad_host."+messZone, "off."+messZone, "bare."+messZone

	suite.Call(t, "record_set", on(map[string]any{"name": gone, "type": "CNAME", "value": "nothing." + messZone}))
	suite.Call(t, "record_set", on(map[string]any{"name": fast, "type": "A", "value": "10.67.0.5", "ttl": 30, "ptr": true}))
	suite.Call(t, "record_set", on(map[string]any{"name": bad, "type": "A", "value": "10.67.0.6", "ptr": true}))
	suite.Call(t, "record_set", on(map[string]any{"name": off, "type": "A", "value": "10.67.0.7", "ptr": true, "disabled": true}))
	suite.Call(t, "record_set", on(map[string]any{"name": bare, "type": "A", "value": "10.67.0.9"}))

	// each is found by the audit whose kind of thing it is; an address with no PTR is found where the PTR belongs
	for _, c := range []struct{ audit, zone, problem, name string }{{"audit_targets", messZone, "dangling", gone}, {"audit_naming", messZone, "ttl_short", fast}, {"audit_naming", messZone, "underscore", bad}, {"audit_state", messZone, "record_disabled", off}, {"audit_reverse", messReverse, "no_ptr", "9." + messReverse}} {
		if found := findingsIn(t, c.audit, c.zone); !has(found, c.problem, c.name) {
			t.Fatalf("%s finds no %s at %s in the mess: %v", c.audit, c.problem, c.name, found)
		}
	}
	// audit_all counts for the zone what each audit finds there, no more and no fewer
	all := suite.Call(t, "audit_all", on(map[string]any{"zone": messZone}))
	for _, row := range acctest.Rows(t, all["audits"], "audits") {
		tool := acctest.Str(row["audit"])
		if own := suite.Call(t, tool, on(map[string]any{"zone": messZone, "limit": 1000})); acctest.Num(t, own["total"], "total") != acctest.Num(t, row["total"], "total") {
			t.Errorf("audit_all counts %v for %s in the mess, and the audit itself finds %v", row["total"], tool, own["total"])
		}
	}
	if acctest.Num(t, all["total"], "total") < 4 {
		t.Errorf("audit_all finds %v things in the mess, want the four put in that zone at least", all["total"])
	}

	// each put right with the tool for it
	suite.Call(t, "record_delete", on(map[string]any{"name": gone, "type": "CNAME"}))
	// the TTL is the host's, so its PTR is brought to it too
	raised := suite.Call(t, "record_set", on(map[string]any{"name": fast, "type": "A", "value": "10.67.0.5", "ttl": 3600, "ptr": true}))
	if got := acctest.Strs(t, raised["changes"], "changes"); len(got) != 2 || got[1] != "changed the TTL of the PTR at 5."+messReverse+" from 30 to 3600 seconds" {
		t.Errorf("the TTL raised = %v", got)
	}
	suite.Call(t, "record_delete", on(map[string]any{"name": bad, "type": "A", "ptr": true}))
	suite.Call(t, "record_set", on(map[string]any{"name": "bad-host." + messZone, "type": "A", "value": "10.67.0.6", "ptr": true}))
	suite.Call(t, "record_set", on(map[string]any{"name": off, "type": "A", "value": "10.67.0.7", "disabled": false}))
	suite.Call(t, "record_set", on(map[string]any{"name": bare, "type": "A", "value": "10.67.0.9", "ptr": true}))

	// the server has what the tools said, and the audits have nothing left to say of either zone
	if got := onServer(t, world.First, messReverse, "9."+messReverse, "PTR"); !slices.Equal(got, []string{bare}) {
		t.Errorf("the PTR made for the bare address = %v", got)
	}
	if got := onServer(t, world.First, messReverse, "6."+messReverse, "PTR"); !slices.Equal(got, []string{"bad-host." + messZone}) {
		t.Errorf("the PTR at the renamed host's address = %v", got)
	}
	for _, audit := range []string{"audit_targets", "audit_naming", "audit_state", "audit_reverse"} {
		for _, zone := range []string{messZone, messReverse} {
			if found := findingsIn(t, audit, zone); len(found) != 0 {
				t.Errorf("%s still finds this in %s once everything was put right: %v", audit, zone, found)
			}
		}
	}
}

// A zone's whole life through the tools: made, filled from a file, read back
// as one, its options set, signed and unsigned, copied, and both deleted -
// each step read back from the server.
//
//nolint:paralleltest // it makes and deletes zones, which a test reading every zone beside it would list and then not find
func TestJourneyAZonesLife(t *testing.T) {
	journeyZones(t, lifeZone)
	first := world.First
	c := mustClient(t, first)
	held := func(zone string) *technitium.Zone {
		t.Helper()
		zones, err := c.Zones(t.Context(), technitium.ZoneFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if i := slices.IndexFunc(zones, func(z technitium.Zone) bool { return z.Name == zone }); i >= 0 {
			return &zones[i]
		}

		return nil
	}

	// filled from a file, and given back as one with every record the file had
	suite.Call(t, "zone_import", on(map[string]any{"zone": lifeZone, "zone_file": "www 600 IN A 10.68.0.1\nmail 600 IN A 10.68.0.2\n@ 600 IN MX 10 mail." + lifeZone + ".\n"}))
	export := acctest.Str(suite.Call(t, "zone_export", on(map[string]any{"zone": lifeZone}))["text"])
	for _, want := range []string{"10.68.0.1", "10.68.0.2", "MX"} {
		if !strings.Contains(export, want) {
			t.Errorf("the zone exported has no %s in it: %q", want, export)
		}
	}
	if got := onServer(t, first, lifeZone, lifeZone, "MX"); len(got) != 1 || !strings.Contains(got[0], "mail."+lifeZone) {
		t.Errorf("the MX the server holds = %v", got)
	}

	// its options: nobody may transfer it, which the server says for itself
	suite.Call(t, "zone_edit", on(map[string]any{"zone": lifeZone, "transfer": "Deny"}))
	if options, err := c.ZoneOptions(t.Context(), lifeZone); err != nil || options.ZoneTransfer != "Deny" {
		t.Errorf("the zone's transfer policy on the server = %+v, %v", options, err)
	}

	// signed, a record added to it is signed too; unsigned, it has no keys
	suite.Call(t, "dnssec_sign", on(map[string]any{"zone": lifeZone, "nx_proof": "NSEC3"}))
	if z := held(lifeZone); z == nil || z.DNSSECStatus != "SignedWithNSEC3" {
		t.Fatalf("signed, the server holds the zone as %+v", z)
	}
	suite.Call(t, "record_set", on(map[string]any{"name": "late." + lifeZone, "type": "A", "value": "10.68.0.3"}))
	if signed := onServer(t, first, lifeZone, "late."+lifeZone, "RRSIG"); len(signed) == 0 {
		t.Error("a record added to a signed zone has no signature on the server")
	}
	suite.Call(t, "dnssec_unsign", on(map[string]any{"zone": lifeZone}))
	if z, keys := held(lifeZone), onServer(t, first, lifeZone, lifeZone, "DNSKEY"); z == nil || z.Signed() || len(keys) != 0 {
		t.Errorf("unsigned, the server holds the zone as %+v with the keys %v", z, keys)
	}

	// copied under another name with everything it has, and both deleted
	t.Cleanup(func() { _ = c.DeleteZone(context.WithoutCancel(t.Context()), lifeClone) })
	suite.Call(t, "zone_clone", on(map[string]any{"zone": lifeClone, "source": lifeZone}))
	if got := onServer(t, first, lifeClone, "late."+lifeClone, "A"); !slices.Equal(got, []string{"10.68.0.3"}) {
		t.Errorf("the clone's late record on the server = %v", got)
	}
	for _, zone := range []string{lifeClone, lifeZone} {
		suite.Call(t, "zone_delete", on(map[string]any{"zone": zone}))
		if held(zone) != nil {
			t.Errorf("%s was deleted and the server still holds it", zone)
		}
	}
	if listed := suite.Call(t, "zone_list", on(map[string]any{"name": "acc-j-life"})); len(acctest.Rows(t, listed["zones"], "zones")) != 0 {
		t.Errorf("zone_list still gives the zones that were deleted: %v", listed["zones"])
	}
}
