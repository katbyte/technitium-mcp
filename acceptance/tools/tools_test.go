//go:build acceptance

package tools_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// names are the servers' names in this arrangement, skipping the test when
// there are none to run against.
func names(t *testing.T) []string {
	t.Helper()

	if !suite.Ready {
		t.Skip(suite.NotReady)
	}

	return world.Names()
}

// recent reports whether a time a tool gave is in UTC, as every time is, and
// within the last while.
func recent(t *testing.T, v any, within time.Duration) bool {
	t.Helper()

	at, err := time.Parse(time.RFC3339, acctest.Str(v))

	return err == nil && at.Location() == time.UTC && strings.HasSuffix(acctest.Str(v), "Z") && time.Since(at) < within
}

// server_info describes every server from what each says of itself: on its
// own, or as a node of the cluster with its role there.
func TestServerInfo(t *testing.T) {
	t.Parallel()

	servers := names(t)
	out := suite.Call(t, "server_info", nil)
	if acctest.Str(out["technitium_mcp_version"]) == "" || out["sdk_api_version"] != technitium.APIVersion {
		t.Errorf("the versions = %v and %v", out["technitium_mcp_version"], out["sdk_api_version"])
	}
	rows := acctest.Rows(t, out["servers"], "servers")
	if len(rows) != len(servers) {
		t.Fatalf("servers = %v, want %v", rows, servers)
	}
	for i, name := range servers {
		row := rows[i]
		// each server calls itself what the script named it, under the
		// cluster's domain once it is a node of one
		if row["server"] != name || row["domain"] != world.Domain(name) || row["account"] != "admin" || acctest.Str(row["version"]) == "" || acctest.Str(row["token_name"]) == "" || !strings.HasPrefix(acctest.Str(row["url"]), "http://127.0.0.1:") {
			t.Errorf("%s = %v", name, row)
		}
		if !recent(t, row["started"], 24*time.Hour) {
			t.Errorf("%s started %q, want a time in UTC in the last day", name, row["started"])
		}
		// an administrator's token, on a server with a password set
		for _, absent := range []string{"error", "cannot_view", "cannot_modify", "cannot_delete", "default_credentials"} {
			if _, there := row[absent]; there {
				t.Errorf("%s has %s = %v", name, absent, row[absent])
			}
		}
		if !acctest.BoolOf(row["dnssec_validation"]) {
			t.Errorf("%s: dnssec_validation = %v, and a new server validates", name, row["dnssec_validation"])
		}

		if !clustered() {
			for _, absent := range []string{"cluster", "cluster_role", "cluster_nodes"} {
				if _, there := row[absent]; there {
					t.Errorf("%s is in no cluster and has %s = %v", name, absent, row[absent])
				}
			}

			continue
		}

		// the first server made the cluster and is its primary; each lists
		// the other
		role, other := "Primary", world.Second
		if name == world.Second {
			role, other = "Secondary", world.First
		}
		nodes := acctest.Rows(t, row["cluster_nodes"], "cluster_nodes")
		if row["cluster"] != testenv.ClusterDomain || row["cluster_role"] != role || len(nodes) != 1 || nodes[0]["name"] != world.Domain(other) || nodes[0]["role"] == role || acctest.Str(nodes[0]["state"]) == "" {
			t.Errorf("%s in the cluster = %v as %v with nodes %v", name, row["cluster"], row["cluster_role"], nodes)
		}
	}

	last := servers[len(servers)-1]
	one := acctest.Rows(t, suite.Call(t, "server_info", map[string]any{"server": last})["servers"], "servers")
	if len(one) != 1 || one[0]["server"] != last {
		t.Errorf("server_info for %s = %v", last, one)
	}
	if msg := suite.CallErr(t, "server_info", map[string]any{"server": "ns3"}); !strings.Contains(msg, strings.Join(servers, ", ")) {
		t.Errorf("a server that is not one = %q, want the ones there are", msg)
	}
}

// zone_list lists the zones of every server side by side: one server's, two
// servers' own copies with what differs between them, or a cluster's zone as
// its primary and its secondary hold it.
func TestZoneList(t *testing.T) {
	t.Parallel()

	servers := names(t)
	out := suite.Call(t, "zone_list", map[string]any{"name": sharedZone, "counts": true})
	if !slices.Equal(acctest.Strs(t, out["asked"], "asked"), servers) || out["failed"] != nil {
		t.Errorf("asked = %v, failed = %v", out["asked"], out["failed"])
	}
	rows := acctest.Rows(t, out["zones"], "zones")
	if len(rows) != 2 || acctest.Num(t, out["total"], "total") != 2 || rows[0]["zone"] != sharedZone || rows[1]["zone"] != firstZone {
		t.Fatalf("zones = %v, want the shared zone then the one under it", rows)
	}

	// the zone every server holds
	shared := rows[0]
	on := acctest.Rows(t, shared["on"], "on")
	if len(on) != len(servers) || shared["missing_on"] != nil {
		t.Fatalf("%s = %v", sharedZone, shared)
	}
	for _, name := range servers {
		held := rowFor(t, on, "server", name)
		if acctest.Num(t, held["serial"], "serial") < 2 || held["disabled"] != nil || held["dnssec"] != nil || held["error"] != nil {
			t.Errorf("%s on %s = %v", sharedZone, name, held)
		}
		if !recent(t, held["modified"], time.Hour) {
			t.Errorf("%s on %s was modified %q, want just now in UTC", sharedZone, name, held["modified"])
		}
	}
	first := rowFor(t, on, "server", world.First)
	switch world.Topology {
	case testenv.Single:
		// the SOA and the NS the server made, and the first server's nine fixtures
		if first["type"] != "Primary" || acctest.Num(t, first["records"], "records") != 11 || shared["differs"] != nil || shared["change_on"] != nil {
			t.Errorf("%s on the one server = %v", sharedZone, shared)
		}
	case testenv.Pair:
		// each its own primary, the first's with one record more
		second := rowFor(t, on, "server", world.Second)
		if first["type"] != "Primary" || second["type"] != "Primary" || acctest.Num(t, first["records"], "records") != 11 || acctest.Num(t, second["records"], "records") != 10 {
			t.Errorf("%s = %v on %s and %v on %s, want primaries of 11 and 10 records", sharedZone, first, world.First, second, world.Second)
		}
		if got := acctest.Strs(t, shared["differs"], "differs"); !slices.Equal(got, []string{"serial", "records"}) || shared["change_on"] != nil {
			t.Errorf("%s differs in %v and can be changed on %v, want its serial and its size, and nothing said of where", sharedZone, got, shared["change_on"])
		}
	case testenv.Cluster:
		// the primary's zone and the copy the cluster gave the other node:
		// the same serial and the same records, an NS for each node among
		// them, and one place to change it
		second := rowFor(t, on, "server", world.Second)
		if first["type"] != "Primary" || second["type"] != "Secondary" || first["catalog"] != testenv.ClusterCatalog || second["catalog"] != testenv.ClusterCatalog {
			t.Errorf("%s = %v on %s and %v on %s", sharedZone, first, world.First, second, world.Second)
		}
		if acctest.Num(t, first["records"], "records") != 12 || acctest.Num(t, second["records"], "records") != 12 || acctest.Num(t, first["serial"], "serial") != acctest.Num(t, second["serial"], "serial") {
			t.Errorf("%s holds %v records at serial %v on %s and %v at %v on %s, want 12 at one serial", sharedZone, first["records"], first["serial"], world.First, second["records"], second["serial"], world.Second)
		}
		if second["sync_failed"] != nil || second["expired"] != nil || !strings.HasSuffix(acctest.Str(second["expiry"]), "Z") || first["expiry"] != nil {
			t.Errorf("the copy's state = %v, and the primary's expiry = %v", second, first["expiry"])
		}
		if got := acctest.Strs(t, shared["differs"], "differs"); !slices.Equal(got, []string{"type"}) {
			t.Errorf("%s differs in %v, want its type alone", sharedZone, got)
		}
		if got := acctest.Strs(t, shared["change_on"], "change_on"); !slices.Equal(got, []string{world.First}) {
			t.Errorf("%s can be changed on %v, want the primary", sharedZone, got)
		}
	}

	// the zone only the first server holds
	own := rows[1]
	if only := acctest.Rows(t, own["on"], "on"); len(only) != 1 || only[0]["server"] != world.First || acctest.Num(t, only[0]["records"], "records") != 2 || own["differs"] != nil || own["change_on"] != nil {
		t.Errorf("%s = %v, want it on %s with its SOA and NS", firstZone, own, world.First)
	}
	if alone() {
		if own["missing_on"] != nil {
			t.Errorf("with one server, %s is missing on %v", firstZone, own["missing_on"])
		}

		return
	}
	if got := acctest.Strs(t, own["missing_on"], "missing_on"); !slices.Equal(got, []string{world.Second}) {
		t.Errorf("%s is missing on %v", firstZone, got)
	}

	// the second server alone lists what it holds and calls nothing missing
	fromSecond := suite.Call(t, "zone_list", map[string]any{"server": world.Second, "name": "*" + sharedZone})
	if got := acctest.Rows(t, fromSecond["zones"], "zones"); len(got) != 1 || got[0]["zone"] != sharedZone || got[0]["missing_on"] != nil {
		t.Errorf("%s's zones = %v", world.Second, got)
	}
	// and what it holds as a copy: nothing when the two are apart, the
	// shared zone in a cluster, which nowhere asked can change
	secondaries := suite.Call(t, "zone_list", map[string]any{"server": world.Second, "name": sharedZone, "type": "Secondary"})
	if !clustered() {
		if acctest.Num(t, secondaries["total"], "total") != 0 {
			t.Errorf("the suite's secondaries = %v, and it made none", secondaries["zones"])
		}

		return
	}
	copies := acctest.Rows(t, secondaries["zones"], "zones")
	if len(copies) != 1 || copies[0]["zone"] != sharedZone {
		t.Fatalf("the suite's secondaries on %s = %v", world.Second, copies)
	}
	if where, said := copies[0]["change_on"]; !said || len(acctest.Strs(t, where, "change_on")) != 0 {
		t.Errorf("a copy asked of its own server alone can be changed on %v (said: %v), want an empty list", where, said)
	}
}

// line is a record row as one line: name, type, value, and who alone holds
// it.
func line(t *testing.T, row map[string]any) string {
	t.Helper()

	out := acctest.Str(row["name"]) + " " + acctest.Str(row["type"]) + " " + acctest.Str(row["value"])
	if row["only_on"] != nil {
		out += " @" + strings.Join(acctest.Strs(t, row["only_on"], "only_on"), ",")
	}

	return out
}

func lines(t *testing.T, out map[string]any) []string {
	t.Helper()

	rows := acctest.Rows(t, out["records"], "records")
	got := make([]string, 0, len(rows))
	for _, row := range rows {
		got = append(got, line(t, row))
	}

	return got
}

// sharedRecords is the shared zone's records as zone_records should give
// them, less the SOA, whose serial depends on the run: one server's own, two
// servers' with who alone holds what, or a cluster's, held alike by both
// nodes with an NS for each.
func sharedRecords() []string {
	switch world.Topology {
	case testenv.Pair:
		return []string{
			"acc.test MX 10 mail.acc.test",
			"acc.test NS ns1 @ns1",
			"acc.test NS ns2 @ns2",
			"extra.acc.test TXT only on ns1 @ns1",
			"gone.acc.test CNAME nothing.acc.test",
			"jf.acc.test CNAME m.acc.test",
			"m.acc.test CNAME emby.van.acc.test",
			"dock.van.acc.test A 10.0.0.2 @ns1",
			"edge.van.acc.test A 10.0.0.252 @ns1",
			"edge.van.acc.test A 10.0.0.252 @ns2",
			"emby.van.acc.test A 10.0.0.4",
			"rpi.van.acc.test A 10.0.0.3 @ns2",
			"*.wild.acc.test A 10.0.0.9",
		}
	case testenv.Cluster:
		return []string{
			"acc.test MX 10 mail.acc.test",
			"acc.test NS ns1.cluster.test",
			"acc.test NS ns2.cluster.test",
			"extra.acc.test TXT only on ns1",
			"gone.acc.test CNAME nothing.acc.test",
			"jf.acc.test CNAME m.acc.test",
			"m.acc.test CNAME emby.van.acc.test",
			"dock.van.acc.test A 10.0.0.2",
			"edge.van.acc.test A 10.0.0.252",
			"emby.van.acc.test A 10.0.0.4",
			"*.wild.acc.test A 10.0.0.9",
		}
	default:
		return []string{
			"acc.test MX 10 mail.acc.test",
			"acc.test NS ns1",
			"extra.acc.test TXT only on ns1",
			"gone.acc.test CNAME nothing.acc.test",
			"jf.acc.test CNAME m.acc.test",
			"m.acc.test CNAME emby.van.acc.test",
			"dock.van.acc.test A 10.0.0.2",
			"edge.van.acc.test A 10.0.0.252",
			"emby.van.acc.test A 10.0.0.4",
			"*.wild.acc.test A 10.0.0.9",
		}
	}
}

// zone_records reads the shared zone from every server holding it as one
// table: what they hold alike once, and what only one holds, or holds
// differently, naming it.
func TestZoneRecords(t *testing.T) {
	t.Parallel()

	servers := names(t)
	out := suite.Call(t, "zone_records", map[string]any{"zone": sharedZone})
	if !slices.Equal(acctest.Strs(t, out["read"], "read"), servers) || out["missing_on"] != nil || out["failed"] != nil {
		t.Errorf("read from %v (missing on %v, failed %v)", out["read"], out["missing_on"], out["failed"])
	}
	got := lines(t, out)
	want := sharedRecords()
	// two servers on their own each have an SOA naming themselves; one
	// server, and a cluster's two nodes, have one between them
	soas := 1
	if world.Topology == testenv.Pair {
		soas = 2
	}
	withoutSOA := slices.DeleteFunc(slices.Clone(got), func(l string) bool { return strings.HasPrefix(l, sharedZone+" SOA ") })
	if !slices.Equal(withoutSOA, want) {
		t.Errorf("records =\n  %s\nwant\n  %s", strings.Join(withoutSOA, "\n  "), strings.Join(want, "\n  "))
	}
	if len(got) != len(want)+soas || acctest.Num(t, out["total"], "total") != len(want)+soas {
		t.Errorf("%d rows and a total of %v, want the %d above and %d SOA", len(got), out["total"], len(want), soas)
	}

	rows := acctest.Rows(t, out["records"], "records")
	dock := rowFor(t, rows, "name", "dock.van."+sharedZone)
	if dock["comment"] != "the docker host" || acctest.Num(t, dock["ttl"], "ttl") != 3600 || dock["disabled"] != nil || dock["on"] != nil {
		t.Errorf("dock = %v", dock)
	}
	// one record held with two TTLs by two servers on their own is a row for
	// each; anywhere else it is the first server's
	ttls := map[string]int{}
	for _, row := range rows {
		if row["name"] == "edge.van."+sharedZone {
			ttls[strings.Join(acctest.Texts(row["only_on"]), ",")] = acctest.Num(t, row["ttl"], "ttl")
		}
	}
	if world.Topology == testenv.Pair {
		if len(ttls) != 2 || ttls[testenv.NS1] != 300 || ttls[testenv.NS2] != 3600 {
			t.Errorf("edge's TTLs by server = %v", ttls)
		}
	} else if len(ttls) != 1 || ttls[""] != 300 {
		t.Errorf("edge's TTLs = %v, want the one record at 300 with no server named", ttls)
	}

	wantA := map[testenv.Topology]int{testenv.Single: 4, testenv.Pair: 6, testenv.Cluster: 4}[world.Topology]
	if byType := acctest.Rows(t, out["by_type"], "by_type"); byType[0]["type"] != "A" || acctest.Num(t, byType[0]["count"], "count") != wantA {
		t.Errorf("by_type = %v, want the %d A rows first", byType, wantA)
	}

	// the filters, which answer the same wherever every server holds the record
	for name, tc := range map[string]struct {
		args map[string]any
		want []string
	}{
		"what points at an address": {map[string]any{"value": "10.0.0.4", "types": []string{"A"}}, []string{"emby.van.acc.test A 10.0.0.4"}},
		"what points at a name":     {map[string]any{"value": "emby.van.acc.test"}, []string{"m.acc.test CNAME emby.van.acc.test"}},
		"a subtree on one server":   {map[string]any{"name": "*.van.acc.test", "server": world.First}, []string{"dock.van.acc.test A 10.0.0.2", "edge.van.acc.test A 10.0.0.252", "emby.van.acc.test A 10.0.0.4"}},
		"disabled":                  {map[string]any{"disabled": true}, []string{}},
		"a page of one server's":    {map[string]any{"types": []string{"A"}, "limit": 2, "offset": 1, "server": world.First}, []string{"edge.van.acc.test A 10.0.0.252", "emby.van.acc.test A 10.0.0.4"}},
	} {
		tc.args["zone"] = sharedZone
		if got := lines(t, suite.Call(t, "zone_records", tc.args)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v\n  = %v\n  want %v", name, tc.args, got, tc.want)
		}
	}
	commented := lines(t, suite.Call(t, "zone_records", map[string]any{"zone": sharedZone, "comment": "*"}))
	if len(commented) != 1 || !strings.HasPrefix(commented[0], "dock.van.acc.test A 10.0.0.2") {
		t.Errorf("the commented records = %v", commented)
	}

	summary := suite.Call(t, "zone_records", map[string]any{"zone": sharedZone, "summary": true})
	if acctest.Num(t, summary["total"], "total") != len(want)+soas || len(acctest.Rows(t, summary["records"], "records")) != 0 {
		t.Errorf("summary = %v", summary)
	}

	// each server's own facts about a record every server holds: when it was
	// changed, which was just now
	details := acctest.Rows(t, suite.Call(t, "zone_records", map[string]any{"zone": sharedZone, "name": "emby", "details": true})["records"], "records")
	seen := acctest.Rows(t, details[0]["on"], "on")
	if len(seen) != len(servers) {
		t.Fatalf("emby's own facts = %v, want one for each of %v", seen, servers)
	}
	for i, s := range seen {
		// a cluster's second node holds a copy, which keeps no record of
		// when a record was changed
		wantModified := !clustered() || servers[i] == world.First
		if s["server"] != servers[i] || recent(t, s["modified"], time.Hour) != wantModified || (!wantModified && s["modified"] != nil) {
			t.Errorf("emby on %v: modified %v", s["server"], s["modified"])
		}
	}
	// and when it last answered a query: never, for a record no test asks a
	// server to resolve
	unused := acctest.Rows(t, suite.Call(t, "zone_records", map[string]any{"zone": sharedZone, "name": "extra", "details": true, "server": world.First})["records"], "records")
	if on := acctest.Rows(t, unused[0]["on"], "on"); len(on) != 1 || on[0]["last_used"] != nil {
		t.Errorf("a record never asked for was last used %v", on)
	}
	// read from a primary and its copy together, the answer says what a copy lacks
	if said := acctest.Str(out["note"]); clustered() != strings.Contains(said, world.Second+" holds a copy of this zone") {
		t.Errorf("the note = %q in the %s topology", said, world.Topology)
	}

	// the zone only the first server holds is read from it, and the other named
	own := suite.Call(t, "zone_records", map[string]any{"zone": firstZone})
	if !slices.Equal(acctest.Strs(t, own["read"], "read"), []string{world.First}) || acctest.Num(t, own["total"], "total") != 2 {
		t.Errorf("%s = %v", firstZone, own)
	}
	if alone() {
		if own["missing_on"] != nil {
			t.Errorf("with one server, %s is missing on %v", firstZone, own["missing_on"])
		}
	} else if got := acctest.Strs(t, own["missing_on"], "missing_on"); !slices.Equal(got, []string{world.Second}) {
		t.Errorf("%s is missing on %v", firstZone, got)
	}

	// a host name given where a zone's belongs says which zone it is in
	if msg := suite.CallErr(t, "zone_records", map[string]any{"zone": "emby.van." + sharedZone}); !strings.Contains(msg, "it is a name inside the zone "+sharedZone) {
		t.Errorf("a host name given for a zone = %q", msg)
	}
	if msg := suite.CallErr(t, "zone_records", map[string]any{"zone": "nope.example"}); !strings.Contains(msg, "no server asked ("+strings.Join(servers, ", ")+") holds a zone named nope.example") {
		t.Errorf("a zone nobody holds = %q", msg)
	}
}

// only is how a row names the first server when it alone of the servers
// asked holds a record: nothing with one server, since it is every server.
func only() string {
	if alone() {
		return ""
	}

	return " @" + world.First
}

// found is every row record_find gave as one line: zone, name, type, value,
// who alone holds it and the chain it was reached by.
func found(t *testing.T, args map[string]any) []string {
	t.Helper()

	out := suite.Call(t, "record_find", args)
	// a zone that could not be read is not in the answer, which would then
	// be short without a failure to show for it
	if out["problems"] != nil || out["failed"] != nil {
		t.Errorf("record_find %v could not read everything: problems %v, failed %v", args, out["problems"], out["failed"])
	}
	rows := acctest.Rows(t, out["records"], "records")
	got := make([]string, 0, len(rows))
	for _, row := range rows {
		l := "[" + acctest.Str(row["zone"]) + "] " + line(t, row)
		if row["via"] != nil {
			l += " via " + strings.Join(acctest.Strs(t, row["via"], "via"), " > ")
		}
		got = append(got, l)
	}

	return got
}

// record_find answers what a change to an address or a name would touch,
// across every zone: here the emby host's address, held by one record, named
// by a PTR in a zone only the first server has, and reached by two CNAMEs,
// one through the other.
func TestRecordFind(t *testing.T) {
	t.Parallel()

	servers := names(t)
	out := suite.Call(t, "record_find", map[string]any{"address": "10.0.0.4"})
	if out["reverse_name"] != "4."+reverseZone || !slices.Equal(acctest.Strs(t, out["asked"], "asked"), servers) || out["failed"] != nil || out["problems"] != nil || acctest.Num(t, out["total"], "total") != 4 {
		t.Errorf("the answer = %v", out)
	}
	// every server follows the names to the address, so those are held
	// alike; the PTR is the first server's alone, as its zone is
	byAddress := []string{
		"[0.0.10.in-addr.arpa] 4.0.0.10.in-addr.arpa PTR emby.van.acc.test" + only(),
		"[acc.test] jf.acc.test CNAME m.acc.test via m.acc.test > emby.van.acc.test > 10.0.0.4",
		"[acc.test] m.acc.test CNAME emby.van.acc.test via emby.van.acc.test > 10.0.0.4",
		"[acc.test] emby.van.acc.test A 10.0.0.4",
	}
	if got := found(t, map[string]any{"address": "10.0.0.4"}); !slices.Equal(got, byAddress) {
		t.Errorf("what ends at 10.0.0.4 =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(byAddress, "\n  "))
	}
	if got := found(t, map[string]any{"address": "10.0.0.4", "direct": true}); !slices.Equal(got, []string{byAddress[0], byAddress[3]}) {
		t.Errorf("what holds 10.0.0.4 = %v", got)
	}

	// an address no record holds is free of records
	free := suite.Call(t, "record_find", map[string]any{"address": "10.0.0.7"})
	if acctest.Num(t, free["total"], "total") != 0 || free["reverse_name"] != "7."+reverseZone {
		t.Errorf("an address nothing holds = %v", free)
	}

	// what points at a name: the PTR and one CNAME straight at it, the other through that one
	byTarget := []string{
		byAddress[0],
		"[acc.test] jf.acc.test CNAME m.acc.test via m.acc.test > emby.van.acc.test",
		"[acc.test] m.acc.test CNAME emby.van.acc.test",
	}
	if got := found(t, map[string]any{"target": "emby.van." + sharedZone}); !slices.Equal(got, byTarget) {
		t.Errorf("what ends at the emby host's name =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(byTarget, "\n  "))
	}

	// a search of every zone at once: by type, and by name in the zones of one kind
	if got := found(t, map[string]any{"types": []string{"PTR", "TXT"}, "server": world.First, "zone": "*0.0.10.in-addr.arpa"}); !slices.Equal(got, []string{"[0.0.10.in-addr.arpa] 4.0.0.10.in-addr.arpa PTR emby.van.acc.test"}) {
		t.Errorf("the PTR and TXT records of %s's reverse zone = %v", world.First, got)
	}
	if got := found(t, map[string]any{"types": []string{"PTR", "TXT"}, "server": world.First, "zone": sharedZone}); !slices.Equal(got, []string{"[acc.test] extra.acc.test TXT only on ns1"}) {
		t.Errorf("the PTR and TXT records of %s's shared zone = %v", world.First, got)
	}
	if got := found(t, map[string]any{"name": "4.0.0.10", "zone": "*.arpa"}); !slices.Equal(got, []string{byAddress[0]}) {
		t.Errorf("a name in the reverse zones = %v", got)
	}

	if msg := suite.CallErr(t, "record_find", map[string]any{}); !strings.Contains(msg, "say what to find") {
		t.Errorf("nothing asked for = %q", msg)
	}
}

// audit_names says of each host name what the servers' own zones give for
// it: here a name every server holds, one reached through two CNAMEs, one a
// wildcard answers, one the zone lacks, one in no zone, and the two that only
// one server of a pair holds.
func TestAuditNames(t *testing.T) {
	t.Parallel()

	servers := names(t)
	asked := []string{"emby.van." + sharedZone, "jf." + sharedZone, "x.wild." + sharedZone, "nope." + sharedZone, "www.elsewhere.test", "dock.van." + sharedZone, "rpi.van." + sharedZone}
	out := suite.Call(t, "audit_names", map[string]any{"names": asked, "expect": map[string]any{"jf." + sharedZone: "10.0.0.4", "nope." + sharedZone: "10.0.0.4"}, "subtree": "van." + sharedZone})
	if !slices.Equal(acctest.Strs(t, out["asked"], "asked"), servers) || out["failed"] != nil || out["problems"] != nil {
		t.Errorf("asked = %v, failed = %v, problems = %v", out["asked"], out["failed"], out["problems"])
	}
	rows := acctest.Rows(t, out["names"], "names")
	if len(rows) != len(asked) {
		t.Fatalf("names = %v", rows)
	}

	if emby := rows[0]; emby["status"] != "exists" || emby["zone"] != sharedZone || !slices.Equal(acctest.Strs(t, emby["ends_at"], "ends_at"), []string{"10.0.0.4"}) || !slices.Equal(acctest.Strs(t, emby["records"], "records"), []string{"A 10.0.0.4"}) {
		t.Errorf("emby = %v", emby)
	}
	if jf := rows[1]; jf["status"] != "exists" || !slices.Equal(acctest.Strs(t, jf["chain"], "chain"), []string{"m." + sharedZone, "emby.van." + sharedZone}) || !slices.Equal(acctest.Strs(t, jf["ends_at"], "ends_at"), []string{"10.0.0.4"}) || jf["expected"] != "10.0.0.4" || jf["unmet"] != nil {
		t.Errorf("jf = %v", jf)
	}
	if wild := rows[2]; wild["status"] != "wildcard" || wild["wildcard"] != "*.wild."+sharedZone || !slices.Equal(acctest.Strs(t, wild["ends_at"], "ends_at"), []string{"10.0.0.9"}) {
		t.Errorf("the name a wildcard answers = %v", wild)
	}
	if nope := rows[3]; nope["status"] != "missing" || nope["zone"] != sharedZone || nope["unmet"] != "it is missing" {
		t.Errorf("the name the zone lacks = %v", nope)
	}
	if elsewhere := rows[4]; elsewhere["status"] != "no_zone" || elsewhere["zone"] != nil {
		t.Errorf("the name in no zone = %v", elsewhere)
	}

	// the two names that two servers on their own each hold one of: with one
	// server, and in a cluster, the first server's is held by all and the
	// second's by none
	dock, rpi := rows[5], rows[6]
	counts := acctest.Object(t, out["counts"], "counts")
	if world.Topology == testenv.Pair {
		for _, row := range []map[string]any{dock, rpi} {
			if perServer := acctest.Rows(t, row["per_server"], "per_server"); row["status"] != "differs" || len(perServer) != 2 || perServer[0]["server"] != testenv.NS1 || perServer[1]["server"] != testenv.NS2 || perServer[0]["status"] == perServer[1]["status"] {
				t.Errorf("a name one of the two holds = %v", row)
			}
		}
		if acctest.NumOr0(counts["exists"]) != 2 || acctest.NumOr0(counts["differs"]) != 2 || acctest.NumOr0(counts["missing"]) != 1 {
			t.Errorf("counts = %v", counts)
		}
	} else {
		if dock["status"] != "exists" || rpi["status"] != "missing" || dock["per_server"] != nil {
			t.Errorf("dock = %v and rpi = %v", dock, rpi)
		}
		if acctest.NumOr0(counts["exists"]) != 3 || acctest.NumOr0(counts["differs"]) != 0 || acctest.NumOr0(counts["missing"]) != 2 {
			t.Errorf("counts = %v", counts)
		}
	}
	if acctest.NumOr0(counts["wildcard"]) != 1 || acctest.NumOr0(counts["no_zone"]) != 1 || acctest.Num(t, out["unmet"], "unmet") != 1 {
		t.Errorf("counts = %v with %v unmet", counts, out["unmet"])
	}

	// the one name under the subtree that was not asked about
	unlisted := acctest.Rows(t, out["unlisted"], "unlisted")
	if len(unlisted) != 1 || unlisted[0]["name"] != "edge.van."+sharedZone {
		t.Fatalf("unlisted = %v, want the edge host alone", unlisted)
	}
	// two servers on their own hold it with different TTLs, which is the
	// same name with the same address
	if unlisted[0]["only_on"] != nil || !slices.Equal(acctest.Strs(t, unlisted[0]["records"], "records"), []string{"A 10.0.0.252"}) {
		t.Errorf("the edge host = %v", unlisted[0])
	}
}

// dns_resolve asks each server what it answers a client: here a name through
// two CNAMEs in the shared zone, one that is not there, one that only one of
// two servers on their own holds, and an address's name.
func TestDNSResolve(t *testing.T) {
	t.Parallel()

	servers := names(t)
	out := suite.Call(t, "dns_resolve", map[string]any{"name": "jf." + sharedZone})
	rows := acctest.Rows(t, out["answers"], "answers")
	if out["type"] != "A" || len(rows) != len(servers) || out["differ"] != nil || out["note"] != nil {
		t.Fatalf("the answer = %v", out)
	}
	for i, name := range servers {
		row := rows[i]
		// each answers from a zone it holds: its own, or in a cluster its copy
		if row["server"] != name || row["asked"] != "itself" || row["result"] != "NoError" || !slices.Equal(acctest.Strs(t, row["answers"], "answers"), []string{"10.0.0.4"}) || !acctest.BoolOf(row["own_zone"]) || acctest.Num(t, row["ttl"], "ttl") != 3600 || acctest.Str(row["took"]) == "" || acctest.Str(row["answered_by"]) == "" {
			t.Errorf("%s = %v", name, row)
		}
		if got, want := acctest.Strs(t, row["chain"], "chain"), []string{"jf.acc.test CNAME m.acc.test", "m.acc.test CNAME emby.van.acc.test", "emby.van.acc.test A 10.0.0.4"}; !slices.Equal(got, want) {
			t.Errorf("%s: chain = %v", name, got)
		}
	}

	for _, row := range acctest.Rows(t, suite.Call(t, "dns_resolve", map[string]any{"name": "nope." + sharedZone})["answers"], "answers") {
		if row["result"] != "NxDomain" || row["answers"] != nil || !acctest.BoolOf(row["own_zone"]) {
			t.Errorf("a name that is not there, on %v = %v", row["server"], row)
		}
	}
	// a name with no record of the type asked for
	for _, row := range acctest.Rows(t, suite.Call(t, "dns_resolve", map[string]any{"name": "emby.van." + sharedZone, "type": "txt"})["answers"], "answers") {
		if row["result"] != "NoError" || row["answers"] != nil {
			t.Errorf("a type the name has none of, on %v = %v", row["server"], row)
		}
	}

	// the name only the first of two servers on their own holds: they differ
	dock := suite.Call(t, "dns_resolve", map[string]any{"name": "dock.van." + sharedZone})
	if acctest.BoolOf(dock["differ"]) != (world.Topology == testenv.Pair) {
		t.Errorf("in the %s topology, differ = %v for a name %s holds: %v", world.Topology, dock["differ"], world.First, dock["answers"])
	}
	if own := acctest.Rows(t, dock["answers"], "answers")[0]; !slices.Equal(acctest.Strs(t, own["answers"], "answers"), []string{"10.0.0.2"}) || own["chain"] != nil {
		t.Errorf("%s's answer for a name it holds = %v", world.First, own)
	}

	// the same question put to a name server by its address, from every
	// server: here the first server's, which every one can reach
	address := world.Address(world.First)
	asked := acctest.Rows(t, suite.Call(t, "dns_resolve", map[string]any{"name": "emby.van." + sharedZone, "resolvers": []string{address}})["answers"], "answers")
	if len(asked) != 2*len(servers) {
		t.Fatalf("answers = %v, want each server's own and each's from %s", asked, address)
	}
	for i, row := range asked[len(servers):] {
		if row["server"] != servers[i] || row["asked"] != address || row["result"] != "NoError" || !slices.Equal(acctest.Strs(t, row["answers"], "answers"), []string{"10.0.0.4"}) {
			t.Errorf("what %s told %s = %v", address, servers[i], row)
		}
	}

	// an address is resolved to its name, on the server that holds its reverse zone
	reverse := suite.Call(t, "dns_resolve", map[string]any{"name": "10.0.0.4", "server": world.First})
	if got := acctest.Rows(t, reverse["answers"], "answers"); reverse["name"] != "4."+reverseZone || reverse["type"] != "PTR" || !slices.Equal(acctest.Strs(t, got[0]["answers"], "answers"), []string{"emby.van." + sharedZone}) {
		t.Errorf("the name of 10.0.0.4 = %v", reverse)
	}

	// a record that has answered a query says when, on the server that answered
	if !acctest.Eventually(func() bool {
		used := acctest.Rows(t, suite.Call(t, "zone_records", map[string]any{"zone": sharedZone, "name": "emby.van", "details": true, "server": world.First})["records"], "records")

		return recent(t, acctest.Rows(t, used[0]["on"], "on")[0]["last_used"], time.Hour)
	}) {
		t.Errorf("the emby record answered a query on %s and does not say when", world.First)
	}

	if msg := suite.CallErr(t, "dns_resolve", map[string]any{"name": ""}); !strings.Contains(msg, "which name") {
		t.Errorf("no name = %q", msg)
	}
}

// cache_get and cache_flush, on a cache filled the one way a test can fill
// one: the first server forwards a zone to the second, so what it resolves
// there it keeps. With one server nothing is ever kept, and both say so.
//
// It does not run beside the other tests: a zone made or deleted can empty a
// server's cache, and some of them make zones.
//
//nolint:paralleltest // it reads the server's cache, which a test making a zone beside it would empty
func TestCache(t *testing.T) {
	servers := names(t)
	flush := func(args map[string]any) []map[string]any {
		t.Helper()
		if !alone() {
			args["server"] = world.First
		}

		return acctest.Rows(t, suite.Call(t, "cache_flush", args)["flushed"], "flushed")
	}
	if alone() {
		empty := suite.Call(t, "cache_get", map[string]any{"name": "a." + cacheZone})
		if len(acctest.Rows(t, empty["cached"], "cached")) != 0 || !slices.Equal(acctest.Strs(t, empty["not_on"], "not_on"), servers) {
			t.Errorf("a name never resolved = %v", empty)
		}
		if rows := flush(map[string]any{"name": cacheZone}); len(rows) != 1 || acctest.Num(t, rows[0]["dropped"], "dropped") != 0 || rows[0]["error"] != nil {
			t.Errorf("a drop of nothing = %v", rows)
		}

		return
	}

	// resolved through the forwarder: an address by way of a CNAME, and a
	// name that is not there. Until it answers: a server that has just joined
	// a cluster does not answer its neighbour for a moment
	for name, want := range map[string]string{"c." + cacheZone: "NoError", "nope." + cacheZone: "NxDomain"} {
		if !acctest.EventuallyWithin(time.Minute, func() bool {
			return acctest.Rows(t, suite.Call(t, "dns_resolve", map[string]any{"name": name, "server": world.First})["answers"], "answers")[0]["result"] == want
		}) {
			t.Fatalf("%s resolved through the forwarder never came to %s", name, want)
		}
	}

	out := suite.Call(t, "cache_get", map[string]any{"name": cacheZone, "subtree": true})
	kept := map[string]map[string]any{}
	for _, row := range acctest.Rows(t, out["cached"], "cached") {
		if row["server"] != world.First {
			t.Errorf("%v keeps %v, and only %s resolved it through a forwarder", row["server"], row, world.First)
		}
		kept[acctest.Str(row["name"])+" "+acctest.Str(row["type"])] = row
	}
	address, alias, negative := kept["a."+cacheZone+" A"], kept["c."+cacheZone+" CNAME"], kept["nope."+cacheZone+" A"]
	if address == nil || address["value"] != "10.5.5.5" || acctest.Num(t, address["ttl"], "ttl") <= 0 || acctest.Num(t, address["ttl"], "ttl") > 600 || address["from"] != world.Address(world.Second) || !recent(t, address["last_used"], time.Hour) {
		t.Errorf("the address kept = %v (of %v)", address, kept)
	}
	if alias == nil || alias["value"] != "a."+cacheZone || alias["negative"] != nil {
		t.Errorf("the CNAME kept = %v", alias)
	}
	if negative == nil || !acctest.BoolOf(negative["negative"]) || negative["value"] != "NxDomain" {
		t.Errorf("the answer that the name is not there = %v", negative)
	}
	// the second server holds the zone itself, and keeps none of it
	if !slices.Contains(acctest.Strs(t, out["not_on"], "not_on"), world.Second) {
		t.Errorf("not_on = %v, want %s, which holds the zone itself", out["not_on"], world.Second)
	}
	// one name, and the names under one
	if one := acctest.Rows(t, suite.Call(t, "cache_get", map[string]any{"name": "a." + cacheZone, "server": world.First})["cached"], "cached"); len(one) != 1 || one[0]["value"] != "10.5.5.5" {
		t.Errorf("one name = %v", one)
	}
	under := acctest.Rows(t, suite.Call(t, "cache_get", map[string]any{"name": cacheZone, "server": world.First})["under"], "under")
	if len(under) != 1 || !slices.Contains(acctest.Strs(t, under[0]["names"], "names"), "nope."+cacheZone) {
		t.Errorf("the names under the zone = %v", under)
	}

	// the negative answer dropped: first what would go, then gone, the rest kept
	if rows := flush(map[string]any{"name": "nope." + cacheZone, "dry_run": true}); acctest.Num(t, rows[0]["dropped"], "dropped") != 1 {
		t.Errorf("a dry run = %v", rows)
	}
	if rows := flush(map[string]any{"name": "nope." + cacheZone}); len(rows) != 1 || rows[0]["server"] != world.First || acctest.Num(t, rows[0]["dropped"], "dropped") != 1 || rows[0]["error"] != nil {
		t.Errorf("dropped = %v", rows)
	}
	left := acctest.Rows(t, suite.Call(t, "cache_get", map[string]any{"name": cacheZone, "subtree": true, "server": world.First})["cached"], "cached")
	if len(left) != 2 {
		t.Errorf("after the drop the server keeps %v, want the address and the CNAME", left)
	}
	// the zone and all under it, on every server at once
	all := acctest.Rows(t, suite.Call(t, "cache_flush", map[string]any{"server": "all", "name": cacheZone})["flushed"], "flushed")
	if len(all) != len(servers) || acctest.Num(t, all[0]["dropped"], "dropped") != 2 || acctest.Num(t, all[1]["dropped"], "dropped") != 0 {
		t.Errorf("dropped on all = %v", all)
	}
	if gone := suite.Call(t, "cache_get", map[string]any{"name": cacheZone, "subtree": true}); acctest.Num(t, gone["total"], "total") != 0 {
		t.Errorf("after the drop on all, kept = %v", gone["cached"])
	}
	if msg := suite.CallErr(t, "cache_flush", map[string]any{"name": cacheZone}); !strings.Contains(msg, "which server") {
		t.Errorf("a drop with no server named = %q", msg)
	}
}

// server_settings sets every server's settings side by side. New servers are
// set up alike, and a cluster's nodes copy the primary's, so nothing differs;
// a cluster's nodes serve their console over HTTPS too.
func TestServerSettings(t *testing.T) {
	t.Parallel()

	servers := names(t)
	out := suite.Call(t, "server_settings", nil)
	rows := acctest.Rows(t, out["servers"], "servers")
	if len(rows) != len(servers) || out["differ"] != nil {
		t.Fatalf("servers = %v, differ = %v", rows, out["differ"])
	}
	for i, name := range servers {
		row := rows[i]
		if row["server"] != name || row["error"] != nil || len(acctest.Strs(t, row["listens"], "listens")) == 0 || acctest.Str(row["recursion"]) == "" || row["blocking"] != "NxDomain" || acctest.Num(t, row["default_ttl"], "default_ttl") != 3600 || acctest.Num(t, row["cache_negative_ttl"], "cache_negative_ttl") == 0 || !acctest.BoolOf(row["dnssec_validation"]) || acctest.Str(row["query_log"]) == "" {
			t.Errorf("%s = %v", name, row)
		}
		// nothing a new server does not have is said
		for _, absent := range []string{"forwarders", "forwarder_protocol", "proxy", "block_lists", "also", "note"} {
			if _, there := row[absent]; there {
				t.Errorf("%s has %s = %v", name, absent, row[absent])
			}
		}
		// the one app the servers are started with, said to be the one that keeps a log to search
		if apps := acctest.Strs(t, row["apps"], "apps"); len(apps) != 1 || !strings.HasPrefix(apps[0], "Query Logs (Sqlite) ") || !strings.HasSuffix(apps[0], "(keeps a searchable log of queries)") {
			t.Errorf("%s: apps = %v, want the log app .scripts/testenv.sh installs", name, apps)
		}
		// a cluster makes itself the key its nodes transfer its catalog with:
		// given by its name, and nothing of its secret
		if !clustered() && row["tsig_keys"] != nil {
			t.Errorf("%s has tsig_keys = %v", name, row["tsig_keys"])
		}
		if clustered() {
			if keys := acctest.Strs(t, row["tsig_keys"], "tsig_keys"); len(keys) != 1 || !strings.HasPrefix(keys[0], testenv.ClusterCatalog+" (hmac-") {
				t.Errorf("%s: tsig_keys = %v, want the cluster's own by its name and algorithm", name, keys)
			}
		}
		console := acctest.Str(row["console"])
		if !strings.HasPrefix(console, "http on 5380") || strings.Contains(console, "https on 53443 with a certificate it signed for itself") != clustered() {
			t.Errorf("%s: console = %q in the %s topology", name, console, world.Topology)
		}
	}
	if one := acctest.Rows(t, suite.Call(t, "server_settings", map[string]any{"server": world.First})["servers"], "servers"); len(one) != 1 || one[0]["server"] != world.First {
		t.Errorf("one server's settings = %v", one)
	}
}

// findings are what an audit found in the suite's own zones: the tests that
// change records work in others, beside this one.
func findings(t *testing.T, tool string, args map[string]any) (found []map[string]any, counts map[string]any) {
	t.Helper()

	if args == nil {
		args = map[string]any{}
	}
	if args["zone"] == nil {
		args["zone"] = sharedZone
	}
	asked := names(t)
	if server, named := args["server"].(string); named {
		asked = []string{server}
	}
	out := suite.Call(t, tool, args)
	if out["failed"] != nil || out["unread"] != nil || !slices.Equal(acctest.Strs(t, out["asked"], "asked"), asked) {
		t.Errorf("%s could not read everything: asked %v, failed %v, unread %v", tool, out["asked"], out["failed"], out["unread"])
	}

	return acctest.Rows(t, out["findings"], "findings"), acctest.Object(t, out["counts"], "counts")
}

// one is the finding of a kind at a zone or a name; it fails the test when
// there is not exactly one.
func one(t *testing.T, found []map[string]any, problem, at string) map[string]any {
	t.Helper()

	var hit []map[string]any
	for _, f := range found {
		if f["problem"] == problem && (f["name"] == at || (f["name"] == nil && f["zone"] == at)) {
			hit = append(hit, f)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("%d findings of %s at %s among %v, want one", len(hit), problem, at, found)
	}

	return hit[0]
}

// audit_servers finds where the servers do not hold the same: nothing with
// one server; with two on their own, the zone only one has, the zone each
// holds as a primary and the records that differ in it; in a cluster, the
// zone the catalog does not carry, and nothing in the one it does.
func TestAuditServers(t *testing.T) {
	t.Parallel()

	names(t)
	found, counts := findings(t, "audit_servers", nil)
	if alone() {
		if len(found) != 0 {
			t.Errorf("with one server, audit_servers found %v", found)
		}

		return
	}

	missing := one(t, found, "zone_missing", firstZone)
	if !slices.Equal(acctest.Strs(t, missing["servers"], "servers"), []string{world.First}) || missing["detail"] != firstZone+" is on "+world.First+" and not on "+world.Second {
		t.Errorf("the zone only one holds = %v", missing)
	}
	if clustered() {
		// the way to give it to the other node is the catalog that node follows
		if !strings.Contains(acctest.Str(missing["fix"]), world.First+" holds the catalog "+testenv.ClusterCatalog+", which "+world.Second+" follows, and this zone is not a member of it") {
			t.Errorf("the fix in a cluster = %q", missing["fix"])
		}
		// the zone the catalog carries is one zone and its copy: nothing differs
		if len(found) != 1 {
			t.Errorf("in a cluster, audit_servers found %v, want the one zone the catalog does not carry", found)
		}

		return
	}

	primaries := one(t, found, "two_primaries", sharedZone)
	if !slices.Equal(acctest.Strs(t, primaries["servers"], "servers"), []string{testenv.NS1, testenv.NS2}) {
		t.Errorf("the zone each holds as its own = %v", primaries)
	}
	// each server's NS for itself, the three records only one holds, and the one held at two TTLs
	differ := one(t, found, "records_differ", sharedZone)
	if !strings.HasPrefix(acctest.Str(differ["detail"]), "7 records of "+sharedZone+" are not the same on ns1 and ns2: ") || !strings.Contains(acctest.Str(differ["detail"]), "acc.test NS ns1 (ttl 14400) on ns1 alone") {
		t.Errorf("the records that differ = %v", differ)
	}
	if len(found) != 3 || acctest.NumOr0(counts["zone_missing"]) != 1 {
		t.Errorf("audit_servers found %v (%v), want the three", found, counts)
	}
}

// The record audits, on the suite's own zones: one CNAME to nothing, two
// addresses with no PTR, and a wildcard; and nothing else, which is as much
// what they are for.
func TestRecordAudits(t *testing.T) {
	t.Parallel()

	names(t)
	found, _ := findings(t, "audit_targets", nil)
	if len(found) != 2 {
		t.Fatalf("audit_targets found %v, want the CNAME to nothing and the MX whose host has no record", found)
	}
	if gone := one(t, found, "dangling", "gone."+sharedZone); gone["servers"] != nil || !strings.Contains(acctest.Str(gone["detail"]), "nothing."+sharedZone+" has no record in "+sharedZone) || gone["zone"] != sharedZone {
		t.Errorf("the CNAME to nothing = %v", gone)
	}
	// the mail host the fixtures name and never made: found by the audit before it was by its author
	if mail := one(t, found, "target_missing", sharedZone); mail["servers"] != nil || !strings.Contains(acctest.Str(mail["detail"]), "the MX at "+sharedZone+" names mail."+sharedZone+", which has no record") {
		t.Errorf("the MX whose host has no record = %v", mail)
	}

	// the reverse zone is the first server's alone, and holds the PTR for one
	// of the three addresses its names have there
	found, counts := findings(t, "audit_reverse", map[string]any{"zone": reverseZone, "server": world.First})
	if len(found) != 2 || acctest.NumOr0(counts["no_ptr"]) != 2 {
		t.Fatalf("audit_reverse found %v, want the two addresses with no PTR", found)
	}
	if dock := one(t, found, "no_ptr", "2."+reverseZone); dock["fix"] != "record_set name=2."+reverseZone+" type=PTR value=dock.van."+sharedZone || !strings.Contains(acctest.Str(dock["detail"]), "10.0.0.2 is held by dock.van."+sharedZone) {
		t.Errorf("the address with no PTR = %v", dock)
	}
	one(t, found, "no_ptr", "252."+reverseZone)
	// a server with no reverse zone for the addresses its names hold says so once, for the network
	if !alone() {
		found, _ = findings(t, "audit_reverse", map[string]any{"zone": reverseZone, "server": world.Second})
		if absent := one(t, found, "no_reverse_zone", reverseZone); !strings.Contains(acctest.Str(absent["detail"]), "addresses in 10.0.0.0/24 are held by records and no reverse zone here holds their PTRs") {
			t.Errorf("the network with no reverse zone on %s = %v", world.Second, absent)
		}
	}

	found, _ = findings(t, "audit_overlaps", nil)
	if len(found) != 1 {
		t.Fatalf("audit_overlaps found %v, want the wildcard", found)
	}
	if wild := one(t, found, "wildcard", "*.wild."+sharedZone); !strings.Contains(acctest.Str(wild["detail"]), "is answered with A 10.0.0.9") || wild["servers"] != nil {
		t.Errorf("the wildcard = %v", wild)
	}

	if found, _ = findings(t, "audit_state", nil); len(found) != 0 {
		t.Errorf("audit_state found %v in zones with nothing of its kind wrong", found)
	}
	// the one record the first server holds at a TTL of its own, where the rest of the zone's have another
	found, _ = findings(t, "audit_naming", nil)
	if len(found) != 1 {
		t.Fatalf("audit_naming found %v, want the one TTL that stands apart", found)
	}
	if apart := one(t, found, "ttl_outlier", "edge.van."+sharedZone); !strings.Contains(acctest.Str(apart["detail"]), "has a TTL of 300 seconds, where 6 of the zone's 7 such records have 3600") || (world.Topology == testenv.Pair) != slices.Equal(acctest.Texts(apart["servers"]), []string{world.First}) {
		t.Errorf("the TTL that stands apart = %v", apart)
	}

	// every audit at once, by how much each found: the same as each finds itself. The audit of the queries reads the last day's, which the tests running beside this one add to between the two calls, so it is held to itself alone
	all := suite.Call(t, "audit_all", map[string]any{"zone": sharedZone})
	total, queries := 0, 0
	for _, row := range acctest.Rows(t, all["audits"], "audits") {
		own, _ := findings(t, acctest.Str(row["audit"]), nil)
		if row["audit"] == "audit_queries" {
			queries = acctest.Num(t, row["total"], "total")

			continue
		}
		if acctest.Num(t, row["total"], "total") != len(own) {
			t.Errorf("audit_all counts %v for %v, which finds %d itself", row["total"], row["audit"], len(own))
		}
		total += len(own)
	}
	if acctest.Num(t, all["total"], "total") != total+queries || total == 0 {
		t.Errorf("audit_all's total = %v, want %d", all["total"], total+queries)
	}
}
