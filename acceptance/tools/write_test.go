//go:build acceptance

package tools_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/lib/testenv"
)

// on is the server argument a change takes for the first server: nothing
// with one server, which is how one is configured, and its name with two.
func on(args map[string]any) map[string]any {
	if !alone() {
		args["server"] = world.First
	}

	return args
}

// values are the values of the rows of an answer, in order.
func values(t *testing.T, v any, field string) []string {
	t.Helper()

	rows := acctest.Rows(t, v, field)
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, acctest.Str(row["value"]))
	}

	return out
}

// The records a zone changes hands through: a host is given an address and
// its PTR, moved to another address, given a second, made to have one alone
// again, aliased, and taken away - each change first as a dry run that
// changes nothing, then for real, read back from the server.
func TestRecordSetAndDelete(t *testing.T) {
	t.Parallel()

	names(t)
	const host = "emby." + writeZone
	set := func(args map[string]any) map[string]any {
		t.Helper()
		args["name"], args["type"] = host, "A"

		return suite.Call(t, "record_set", on(args))
	}
	ptrs := func() []string {
		t.Helper()

		// the ones naming this host: another test's are in the zone too
		return found(t, map[string]any{"types": []string{"PTR"}, "zone": writeReverseZone, "server": world.First, "value": host})
	}

	// a dry run says what would be done, and nothing is
	dry := set(map[string]any{"value": "10.9.8.21", "ttl": 300, "comment": "the emby vm", "ptr": true, "dry_run": true})
	if got := acctest.Strs(t, dry["changes"], "changes"); !slices.Equal(got, []string{"would have added A 10.9.8.21 at " + host, "would have added PTR " + host + " at 21." + writeReverseZone}) || !acctest.BoolOf(dry["changed"]) || dry["after"] != nil {
		t.Fatalf("a dry run = %v", dry)
	}
	if got := ptrs(); len(got) != 0 {
		t.Fatalf("a dry run made %v", got)
	}

	// added, with its PTR
	out := set(map[string]any{"value": "10.9.8.21", "ttl": 300, "comment": "the emby vm", "ptr": true})
	if out["server"] != world.First || out["zone"] != writeZone || !acctest.BoolOf(out["changed"]) || len(acctest.Strs(t, out["changes"], "changes")) != 2 || len(acctest.Rows(t, out["before"], "before")) != 0 {
		t.Errorf("added = %v", out)
	}
	if after := acctest.Rows(t, out["after"], "after"); len(after) != 1 || after[0]["value"] != "10.9.8.21" || acctest.Num(t, after[0]["ttl"], "ttl") != 300 || after[0]["comment"] != "the emby vm" {
		t.Errorf("after adding = %v", out["after"])
	}
	if got := ptrs(); !slices.Equal(got, []string{"[" + writeReverseZone + "] 21." + writeReverseZone + " PTR " + host}) {
		t.Errorf("the PTRs after adding = %v", got)
	}

	// asked again, nothing changes
	if again := set(map[string]any{"value": "10.9.8.21", "ptr": true}); acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 || !slices.Equal(values(t, again["after"], "after"), []string{"10.9.8.21"}) {
		t.Errorf("set again = %v", again)
	}

	// moved to another address: the TTL and the comment stay, the PTR follows
	out = set(map[string]any{"value": "10.9.8.22", "replaces": "10.9.8.21", "ptr": true})
	if got := acctest.Strs(t, out["changes"], "changes"); len(got) != 3 || !strings.Contains(got[0], "its value from 10.9.8.21 to 10.9.8.22") {
		t.Errorf("moved = %v", got)
	}
	if after := acctest.Rows(t, out["after"], "after"); len(after) != 1 || after[0]["value"] != "10.9.8.22" || acctest.Num(t, after[0]["ttl"], "ttl") != 300 || after[0]["comment"] != "the emby vm" {
		t.Errorf("after moving = %v, want the TTL and the comment kept", out["after"])
	}
	if got := ptrs(); !slices.Equal(got, []string{"[" + writeReverseZone + "] 22." + writeReverseZone + " PTR " + host}) {
		t.Errorf("the PTRs after moving = %v, want the new address's alone", got)
	}

	// a second address beside the first takes the TTL the name's addresses
	// share, and the first keeps its comment
	out = set(map[string]any{"value": "10.9.8.23"})
	after := acctest.Rows(t, out["after"], "after")
	if !slices.Equal(values(t, out["after"], "after"), []string{"10.9.8.22", "10.9.8.23"}) || acctest.Num(t, after[0]["ttl"], "ttl") != 300 || acctest.Num(t, after[1]["ttl"], "ttl") != 300 || after[0]["comment"] != "the emby vm" || len(acctest.Strs(t, out["changes"], "changes")) != 1 {
		t.Errorf("a second address = %v", out)
	}
	// a third with a TTL of its own: the server sets it on all three and
	// drops their comments, and the tool puts the comment back
	out = set(map[string]any{"value": "10.9.8.24", "ttl": 900})
	after = acctest.Rows(t, out["after"], "after")
	if got := acctest.Strs(t, out["changes"], "changes"); len(got) != 2 || !strings.Contains(got[0], "set the TTL of the other 2 A records there from 300 to 900") || !strings.HasPrefix(got[1], "kept the comment and state of A 10.9.8.22") {
		t.Errorf("a third address with its own TTL = %v", got)
	}
	if len(after) != 3 || acctest.Num(t, after[0]["ttl"], "ttl") != 900 || acctest.Num(t, after[1]["ttl"], "ttl") != 900 || after[0]["comment"] != "the emby vm" {
		t.Errorf("after a third address = %v, want all three at 900 and the first's comment kept", after)
	}
	// and one alone again, at another TTL and with no comment
	out = set(map[string]any{"value": "10.9.8.22", "only": true, "ttl": 600, "comment": ""})
	if got := acctest.Strs(t, out["changes"], "changes"); len(got) != 3 || !strings.Contains(got[0], "its TTL from 900 to 600") || !strings.Contains(got[0], `its comment from "the emby vm" to ""`) || got[1] != "removed A 10.9.8.23 at "+host || got[2] != "removed A 10.9.8.24 at "+host {
		t.Errorf("made the only one = %v", got)
	}
	if after = acctest.Rows(t, out["after"], "after"); len(after) != 1 || acctest.Num(t, after[0]["ttl"], "ttl") != 600 || after[0]["comment"] != nil {
		t.Errorf("after making it the only one = %v", out["after"])
	}

	// disabled, and enabled again
	if out = set(map[string]any{"value": "10.9.8.22", "disabled": true}); !acctest.BoolOf(acctest.Rows(t, out["after"], "after")[0]["disabled"]) {
		t.Errorf("disabled = %v", out["after"])
	}
	if out = set(map[string]any{"value": "10.9.8.22", "disabled": false}); acctest.Rows(t, out["after"], "after")[0]["disabled"] != nil || acctest.Num(t, acctest.Rows(t, out["after"], "after")[0]["ttl"], "ttl") != 600 {
		t.Errorf("enabled again = %v, want it enabled with its TTL kept", out["after"])
	}

	// a CNAME to it, changed by setting another; and what a CNAME refuses
	alias := map[string]any{"name": "m." + writeZone, "type": "CNAME", "value": host}
	if out = suite.Call(t, "record_set", on(alias)); !slices.Equal(values(t, out["after"], "after"), []string{host}) {
		t.Errorf("a CNAME = %v", out)
	}
	alias["value"] = "other." + writeZone
	if out = suite.Call(t, "record_set", on(alias)); !slices.Equal(values(t, out["after"], "after"), []string{"other." + writeZone}) || !strings.Contains(acctest.Strs(t, out["changes"], "changes")[0], "its value from "+host) {
		t.Errorf("a CNAME set over the one there = %v", out)
	}
	if msg := suite.CallErr(t, "record_set", on(map[string]any{"name": host, "type": "CNAME", "value": "x." + writeZone})); !strings.Contains(msg, "a CNAME stands alone") {
		t.Errorf("a CNAME beside an address = %q", msg)
	}
	if msg := suite.CallErr(t, "record_set", on(map[string]any{"name": "m." + writeZone, "type": "TXT", "value": "hello"})); !strings.Contains(msg, "is a CNAME to other."+writeZone) {
		t.Errorf("a record beside a CNAME = %q", msg)
	}
	// a PTR with no reverse zone to go in changes nothing
	if msg := suite.CallErr(t, "record_set", on(map[string]any{"name": "far." + writeZone, "type": "A", "value": "192.168.77.1", "ptr": true})); !strings.Contains(msg, "the PTR for 192.168.77.1 belongs at 1.77.168.192.in-addr.arpa") || !strings.Contains(msg, "Nothing was changed") {
		t.Errorf("a PTR with nowhere to go = %q", msg)
	}
	if got := found(t, map[string]any{"name": "far." + writeZone, "server": world.First}); len(got) != 0 {
		t.Errorf("the refused record was made: %v", got)
	}

	// every other type the tool writes, set and read back
	for _, tc := range []struct{ name, recordType, value string }{
		{host, "AAAA", "fd00::22"},
		{writeZone, "MX", "10 mail." + writeZone},
		{writeZone, "TXT", "v=spf1 include:example.com -all"},
		{"_sip._tcp." + writeZone, "SRV", "1 2 5060 " + host},
		{writeZone, "CAA", "0 issue letsencrypt.org"},
		{"sub." + writeZone, "NS", "ns.elsewhere.test"},
		{"an." + writeZone, "ANAME", host},
	} {
		got := suite.Call(t, "record_set", on(map[string]any{"name": tc.name, "type": tc.recordType, "value": tc.value}))
		if !slices.Contains(values(t, got["after"], "after"), tc.value) {
			t.Errorf("the %s set to %q reads back as %v", tc.recordType, tc.value, got["after"])
		}
	}

	// in a cluster the other node takes what was set, and refuses a change
	// of its own, saying where one is made
	if clustered() {
		if !acctest.EventuallyWithin(2*time.Minute, func() bool {
			return slices.Equal(values(t, suite.Call(t, "zone_records", map[string]any{"zone": writeZone, "server": world.Second, "name": host, "types": []string{"A"}})["records"], "records"), []string{"10.9.8.22"})
		}) {
			t.Errorf("%s never took the address set on %s", world.Second, world.First)
		}
		if msg := suite.CallErr(t, "record_set", map[string]any{"server": world.Second, "name": host, "type": "A", "value": "10.9.8.30"}); !strings.Contains(msg, world.Second+" holds "+writeZone+" as a Secondary zone, a copy that takes no changes: make the change on "+world.First) {
			t.Errorf("a change asked of the copy = %q", msg)
		}
		if msg := suite.CallErr(t, "record_delete", map[string]any{"server": world.Second, "name": host, "type": "A"}); !strings.Contains(msg, "make the change on "+world.First) {
			t.Errorf("a delete asked of the copy = %q", msg)
		}
	}
	// with two servers a change says which it is made on
	if !alone() {
		if msg := suite.CallErr(t, "record_set", map[string]any{"name": host, "type": "A", "value": "10.9.8.30"}); !strings.Contains(msg, "which server: a change is made on one server at a time, so name it ("+testenv.NS1+", "+testenv.NS2+")") {
			t.Errorf("a change with no server named = %q", msg)
		}
	}
	// two servers on their own: the second holds no such zone
	if world.Topology == testenv.Pair {
		if msg := suite.CallErr(t, "record_set", map[string]any{"server": world.Second, "name": host, "type": "A", "value": "10.9.8.30"}); !strings.Contains(msg, world.Second+" holds no zone that "+host+" is in") {
			t.Errorf("a change asked of a server without the zone = %q", msg)
		}
	}

	// deleted: first what would go, then gone, with what it was. The server
	// takes the address's PTR away with it, which is said either way
	del := map[string]any{"name": host, "type": "A", "dry_run": true}
	gone := []string{"deleted A 10.9.8.22 at " + host, "removed PTR " + host + " at 22." + writeReverseZone + ", which the server takes away with the address"}
	dry = suite.Call(t, "record_delete", on(del))
	if got := acctest.Strs(t, dry["changes"], "changes"); !slices.Equal(got, []string{"would have " + gone[0], "would have " + gone[1]}) || !slices.Equal(values(t, dry["deleted"], "deleted"), []string{"10.9.8.22"}) || len(ptrs()) != 1 || !slices.Equal(values(t, dry["left"], "left"), []string{"10.9.8.22"}) {
		t.Errorf("a dry run of the delete = %v, with PTRs %v", dry, ptrs())
	}
	del["dry_run"] = false
	out = suite.Call(t, "record_delete", on(del))
	deleted := acctest.Rows(t, out["deleted"], "deleted")
	if len(deleted) != 1 || deleted[0]["value"] != "10.9.8.22" || acctest.Num(t, deleted[0]["ttl"], "ttl") != 600 || len(acctest.Rows(t, out["left"], "left")) != 0 || !slices.Equal(acctest.Strs(t, out["changes"], "changes"), gone) || out["note"] != nil {
		t.Errorf("deleted = %v", out)
	}
	if got := ptrs(); len(got) != 0 {
		t.Errorf("the PTRs after deleting = %v", got)
	}
	if msg := suite.CallErr(t, "record_delete", on(map[string]any{"name": host, "type": "A"})); !strings.Contains(msg, "has no A record") {
		t.Errorf("deleting what is gone = %q", msg)
	}
	// the last record at a name: the name goes with it
	if out = suite.Call(t, "record_delete", on(map[string]any{"name": "m." + writeZone, "type": "CNAME"})); !slices.Equal(values(t, out["deleted"], "deleted"), []string{"other." + writeZone}) || len(acctest.Rows(t, out["left"], "left")) != 0 {
		t.Errorf("the last record at a name = %v", out)
	}
}

// record_repoint moves every record at one address to another, with the PTR:
// here two names at one address, a third reaching it by a CNAME, and a
// neighbour at the address moved to.
func TestRecordRepoint(t *testing.T) {
	t.Parallel()

	names(t)
	const one, two, alias, neighbour = "one.move." + writeZone, "two.move." + writeZone, "alias.move." + writeZone, "near.move." + writeZone
	for _, rec := range []map[string]any{
		{"name": one, "type": "A", "value": "10.9.8.41", "ttl": 300, "comment": "moves", "ptr": true},
		{"name": two, "type": "A", "value": "10.9.8.41"},
		{"name": alias, "type": "CNAME", "value": one},
		{"name": neighbour, "type": "A", "value": "10.9.8.43"},
	} {
		suite.Call(t, "record_set", on(rec))
	}
	held := func(address string) []string {
		t.Helper()

		return found(t, map[string]any{"address": address, "server": world.First, "direct": true})
	}

	// onto a neighbour's address: refused, with nothing changed
	if msg := suite.CallErr(t, "record_repoint", on(map[string]any{"from": "10.9.8.41", "to": "10.9.8.43"})); !strings.Contains(msg, "10.9.8.43 is already held by "+neighbour) || !strings.Contains(msg, "Nothing was changed") {
		t.Errorf("onto a neighbour's address = %q", msg)
	}

	// the dry run lists every change and makes none
	want := []string{
		"moved A " + one + " from 10.9.8.41 to 10.9.8.42",
		"moved A " + two + " from 10.9.8.41 to 10.9.8.42",
		"added PTR " + one + " at 42." + writeReverseZone,
		"removed PTR " + one + " at 41." + writeReverseZone,
	}
	dry := suite.Call(t, "record_repoint", on(map[string]any{"from": "10.9.8.41", "to": "10.9.8.42", "dry_run": true}))
	if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != len(want) || got[0] != "would have "+want[0] || got[3] != "would have "+want[3] {
		t.Errorf("a dry run = %v", got)
	}
	if got := held("10.9.8.41"); len(got) != 3 {
		t.Fatalf("after a dry run, 10.9.8.41 is held by %v, want the two names and the PTR still", got)
	}

	out := suite.Call(t, "record_repoint", on(map[string]any{"from": "10.9.8.41", "to": "10.9.8.42"}))
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, want) || out["server"] != world.First || out["skipped"] != nil || out["already_at"] != nil {
		t.Errorf("moved = %v", out)
	}
	moved := acctest.Rows(t, out["repointed"], "repointed")
	if len(moved) != 2 || moved[0]["name"] != one || moved[0]["comment"] != "moves" || acctest.Num(t, moved[0]["ttl"], "ttl") != 300 || moved[0]["zone"] != writeZone {
		t.Errorf("repointed = %v", moved)
	}
	if got := held("10.9.8.41"); len(got) != 0 {
		t.Errorf("after the move, 10.9.8.41 is still held by %v", got)
	}
	if got := held("10.9.8.42"); len(got) != 3 {
		t.Errorf("after the move, 10.9.8.42 is held by %v, want the two names and the PTR", got)
	}
	// the record kept its comment, and the name that reaches it by a CNAME follows without a change
	kept := acctest.Rows(t, suite.Call(t, "zone_records", map[string]any{"zone": writeZone, "name": one, "server": world.First})["records"], "records")
	if len(kept) != 1 || kept[0]["value"] != "10.9.8.42" || kept[0]["comment"] != "moves" || acctest.Num(t, kept[0]["ttl"], "ttl") != 300 {
		t.Errorf("the moved record = %v", kept)
	}
	if via := found(t, map[string]any{"address": "10.9.8.42", "server": world.First, "types": []string{"CNAME"}}); len(via) != 1 || !strings.Contains(via[0], alias) {
		t.Errorf("what reaches the new address by a CNAME = %v", via)
	}

	// run again there is nothing to move, and it says so
	if again := suite.Call(t, "record_repoint", on(map[string]any{"from": "10.9.8.41", "to": "10.9.8.42"})); len(acctest.Strs(t, again["changes"], "changes")) != 0 || !strings.Contains(acctest.Str(again["note"]), "there was nothing to move") {
		t.Errorf("moved again = %v", again)
	}
	// onto the neighbour's address on purpose
	shared := suite.Call(t, "record_repoint", on(map[string]any{"from": "10.9.8.42", "to": "10.9.8.43", "share": true, "no_ptr": true}))
	if got := acctest.Strs(t, shared["already_at"], "already_at"); !slices.Equal(got, []string{neighbour}) || len(acctest.Rows(t, shared["repointed"], "repointed")) != 2 {
		t.Errorf("shared on purpose = %v", shared)
	}
	// the PTR was left where it was, as asked
	if left := found(t, map[string]any{"types": []string{"PTR"}, "zone": writeReverseZone, "server": world.First, "name": "42."}); len(left) != 1 {
		t.Errorf("the PTR that was to be left alone = %v", left)
	}
}
