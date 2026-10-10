//go:build integration

package acceptance

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// liveClusterZone is whether a zone is the cluster's own, held with something in it.
func liveClusterZone(z technitium.Zone) bool {
	return z.Name == testenv.ClusterDomain && z.SOASerial > 0 && !z.IsExpired
}

// clusterOf is how a server stands in a cluster, as cluster_get gives it.
func clusterOf(t *testing.T, server string) map[string]any {
	t.Helper()

	return rowOn(t, suite.Call(t, "cluster_get", map[string]any{"server": server}), server)
}

// The cluster tools on servers as they stand: read everywhere; on servers in
// no cluster, making and joining one as dry runs and the rest refused; on a
// cluster, its intervals changed and everything that would end it as a dry
// run. What ends a cluster for real is the test after this one.
func TestCluster(t *testing.T) {
	t.Parallel()

	servers := names(t)
	first := world.First
	if !clustered() {
		got := suite.Call(t, "cluster_get", nil)
		for _, name := range servers {
			if row := rowOn(t, got, name); acctest.BoolOf(row["in_cluster"]) || row["nodes"] != nil || row["role"] != nil {
				t.Errorf("cluster_get for %s = %v", name, row)
			}
		}
		if got["note"] == nil {
			t.Errorf("cluster_get with no cluster anywhere says nothing of it: %v", got)
		}

		// made and joined only as dry runs: the servers are to stay as they are
		address := world.Address(first)
		if address == "" {
			address = "10.250.250.2"
		}
		dry := suite.Call(t, "cluster_create", on(map[string]any{"domain": "Acc-Cluster.test.", "addresses": []string{address}, "dry_run": true}))
		if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have made " + first + " the primary node of a new cluster, acc-cluster.test, reached at " + address}) || dry["after"] != nil || acctest.BoolOf(clusterOf(t, first)["in_cluster"]) {
			t.Errorf("a dry run of making a cluster = %v", dry)
		}
		for what, args := range map[string]map[string]any{"no address": {"domain": "acc-cluster.test", "addresses": []string{" "}}, "a domain of one label": {"domain": "cluster", "addresses": []string{address}}} {
			if msg := suite.CallErr(t, "cluster_create", on(args)); !strings.Contains(msg, "a cluster is made with a domain of its own") {
				t.Errorf("%s: cluster_create = %q", what, msg)
			}
		}
		join := map[string]any{"primary_url": "https://ns9.acc-cluster.test:53443/", "addresses": []string{address}, "primary_username": "admin", "primary_password": "an acceptance passw0rd", "dry_run": true}
		dry = suite.Call(t, "cluster_join", on(join))
		if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != 1 || !strings.HasPrefix(got[0], "would have had "+first+" join the cluster whose primary is at https://ns9.acc-cluster.test:53443/") || strings.Contains(fmt.Sprint(dry), "passw0rd") {
			t.Errorf("a dry run of joining a cluster = %v", dry["changes"])
		}
		join["primary_url"] = "http://ns9.acc-cluster.test:5380/"
		if msg := suite.CallErr(t, "cluster_join", on(join)); !strings.Contains(msg, "the primary's https:// url") {
			t.Errorf("joining over plain http = %q", msg)
		}

		// and the rest have no cluster to work on
		for tool, args := range map[string]map[string]any{"cluster_edit": {"resync": true}, "cluster_leave": {}, "cluster_promote": {}, "cluster_node_delete": {"node": "ns9.acc-cluster.test"}, "cluster_delete": {}} {
			if msg := suite.CallErr(t, tool, on(args)); !strings.Contains(msg, first+" is in no cluster") {
				t.Errorf("%s with no cluster = %q", tool, msg)
			}
		}

		return
	}

	// a cluster of two: each says what it is, and both list both
	second := world.Second
	primary, secondary := clusterOf(t, first), clusterOf(t, second)
	if primary["role"] != "Primary" || secondary["role"] != "Secondary" || primary["domain"] != testenv.ClusterDomain || secondary["domain"] != testenv.ClusterDomain || len(acctest.Rows(t, primary["nodes"], "nodes")) != 2 || len(acctest.Rows(t, secondary["nodes"], "nodes")) != 2 {
		t.Fatalf("cluster_get = %v and %v", primary, secondary)
	}
	nodes := acctest.Rows(t, primary["nodes"], "nodes")
	other := rowFor(t, nodes, "name", world.Domain(second))
	if self := rowFor(t, nodes, "name", world.Domain(first)); self["state"] != "Self" || self["type"] != "Primary" || other["type"] != "Secondary" || acctest.Num(t, other["id"], "id") == 0 || !strings.HasPrefix(acctest.Str(other["url"]), "https://") || len(acctest.Strs(t, other["addresses"], "addresses")) == 0 {
		t.Errorf("the nodes as the primary sees them = %v", nodes)
	}

	// made again under its own domain it is found so; under another it is refused, as is joining what one is in
	if again := suite.Call(t, "cluster_create", map[string]any{"server": first, "domain": testenv.ClusterDomain, "addresses": []string{world.Address(first)}}); acctest.BoolOf(again["changed"]) || again["note"] == nil || acctest.Object(t, again["after"], "after")["role"] != "Primary" {
		t.Errorf("the cluster made again = %v", again)
	}
	if msg := suite.CallErr(t, "cluster_create", map[string]any{"server": first, "domain": "acc-other.test", "addresses": []string{world.Address(first)}}); !strings.Contains(msg, "is already in the cluster "+testenv.ClusterDomain) {
		t.Errorf("a second cluster made of a node = %q", msg)
	}
	if msg := suite.CallErr(t, "cluster_join", map[string]any{"server": second, "primary_url": acctest.Str(rowFor(t, nodes, "name", world.Domain(first))["url"]), "addresses": []string{world.Address(second)}, "primary_username": "admin", "primary_password": "x"}); !strings.Contains(msg, "is already in the cluster") {
		t.Errorf("a node joining again = %q", msg)
	}

	// its intervals are the primary's to set: changed, found so when asked again, and put back
	was := acctest.Num(t, primary["config_retry_seconds"], "config_retry_seconds")
	edited := suite.Call(t, "cluster_edit", map[string]any{"server": first, "config_retry_seconds": was + 7})
	if after := acctest.Object(t, edited["after"], "after"); acctest.Num(t, after["config_retry_seconds"], "config_retry_seconds") != was+7 || !slices.Equal(acctest.Strs(t, edited["changes"], "changes"), []string{fmt.Sprintf("set the cluster's config retry from %ds to %ds", was, was+7)}) {
		t.Errorf("the config retry set = %v", edited)
	}
	if again := suite.Call(t, "cluster_edit", map[string]any{"server": first, "config_retry_seconds": was + 7}); acctest.BoolOf(again["changed"]) {
		t.Errorf("set to what it is = %v", again)
	}
	suite.Call(t, "cluster_edit", map[string]any{"server": first, "config_retry_seconds": was})
	if msg := suite.CallErr(t, "cluster_edit", map[string]any{"server": second, "config_retry_seconds": was + 7}); !strings.Contains(msg, "is asked of its primary") {
		t.Errorf("a secondary setting the intervals = %q", msg)
	}
	if msg := suite.CallErr(t, "cluster_edit", map[string]any{"server": first, "heartbeat_refresh_seconds": 5}); !strings.Contains(msg, "heartbeat_refresh_seconds is 10 to 300") {
		t.Errorf("the nodes set to look at each other every five seconds = %q", msg)
	}
	// a secondary fetches the configuration again when asked, and the primary has none to fetch
	if synced := suite.Call(t, "cluster_edit", map[string]any{"server": second, "resync": true}); len(acctest.Strs(t, synced["changes"], "changes")) != 1 || synced["note"] == nil {
		t.Errorf("a secondary resynced = %v", synced)
	}
	if msg := suite.CallErr(t, "cluster_edit", map[string]any{"server": first, "resync": true}); !strings.Contains(msg, "is asked of its secondary") {
		t.Errorf("the primary resynced = %q", msg)
	}

	// what would end it, as dry runs: each says what it would do and is asked of the node it is for
	dry := suite.Call(t, "cluster_node_delete", map[string]any{"server": first, "node": world.Domain(second), "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have asked the node " + world.Domain(second) + " to leave the cluster " + testenv.ClusterDomain}) {
		t.Errorf("a dry run of taking a node out = %v", dry)
	}
	if forced := suite.Call(t, "cluster_node_delete", map[string]any{"server": first, "node": strconv.Itoa(acctest.Num(t, other["id"], "id")), "force": true, "dry_run": true}); !strings.HasPrefix(acctest.Strs(t, forced["changes"], "changes")[0], "would have dropped the node "+world.Domain(second)) || forced["note"] == nil {
		t.Errorf("a dry run of dropping a node by its id = %v", forced)
	}
	for msg, args := range map[string]map[string]any{"has no node": {"server": first, "node": "ns9." + testenv.ClusterDomain}, "is the cluster's primary": {"server": first, "node": world.Domain(first)}, "is asked of its primary": {"server": second, "node": world.Domain(first)}} {
		if got := suite.CallErr(t, "cluster_node_delete", args); !strings.Contains(got, msg) {
			t.Errorf("cluster_node_delete %v = %q, want %q in it", args, got, msg)
		}
	}
	if dry = suite.Call(t, "cluster_leave", map[string]any{"server": second, "dry_run": true}); !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have removed " + second + " from the cluster " + testenv.ClusterDomain + ", telling the primary"}) {
		t.Errorf("a dry run of leaving = %v", dry)
	}
	if msg := suite.CallErr(t, "cluster_leave", map[string]any{"server": first}); !strings.Contains(msg, "is asked of its secondary") {
		t.Errorf("the primary leaving = %q", msg)
	}
	if dry = suite.Call(t, "cluster_promote", map[string]any{"server": second, "dry_run": true}); !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have made " + second + " the primary of the cluster " + testenv.ClusterDomain + " in place of " + world.Domain(first) + ", which was asked to leave"}) {
		t.Errorf("a dry run of promoting = %v", dry)
	}
	if msg := suite.CallErr(t, "cluster_promote", map[string]any{"server": first}); !strings.Contains(msg, "is asked of its secondary") {
		t.Errorf("the primary promoted = %q", msg)
	}
	if msg := suite.CallErr(t, "cluster_delete", map[string]any{"server": first}); !strings.Contains(msg, "still has 1 secondary nodes") {
		t.Errorf("a cluster with a secondary, deleted = %q", msg)
	}
	if dry = suite.Call(t, "cluster_delete", map[string]any{"server": first, "force": true, "dry_run": true}); !strings.Contains(acctest.Strs(t, dry["changes"], "changes")[0], "leaving its 1 secondary nodes without a primary") || dry["note"] == nil {
		t.Errorf("a dry run of deleting the cluster = %v", dry)
	}
	if now := clusterOf(t, second); now["role"] != "Secondary" || len(acctest.Rows(t, now["nodes"], "nodes")) != 2 {
		t.Errorf("after the dry runs the cluster is %v", now)
	}
}

// The cluster tools for real, which end with there being no cluster: a node
// asked to leave and joined again, a node dropped and left to leave by
// itself, a secondary made the primary, the cluster deleted, and a new one
// made.
//
// Nothing can run after it, so it is skipped by every run but the one that
// ends the suite, which make starts last and alone.
//
//nolint:paralleltest // it takes the cluster apart, which every other test of a cluster needs whole
func TestClusterToolsTakenApart(t *testing.T) {
	names(t)
	if !world.TakingApart() {
		t.Skip("the cluster is taken apart only by the run that ends the suite: make testacc-acceptance")
	}
	first, second := world.First, world.Second
	in := func(server string) bool { return acctest.BoolOf(clusterOf(t, server)["in_cluster"]) }
	nodesOf := func(server string) int { return len(acctest.RowsOf(clusterOf(t, server)["nodes"])) }
	primaryURL := acctest.Str(rowFor(t, acctest.Rows(t, clusterOf(t, first)["nodes"], "nodes"), "name", world.Domain(first))["url"])
	join := func(joiner, to, url string) map[string]any {
		t.Helper()

		return suite.Call(t, "cluster_join", map[string]any{"server": joiner, "primary_url": url, "primary_address": world.Address(to), "addresses": []string{world.Address(joiner)}, "primary_username": "admin", "primary_password": world.Password(), "ignore_certificate_errors": true})
	}

	// where the nodes are reached is each node's to say
	if moved := suite.Call(t, "cluster_edit", map[string]any{"server": first, "addresses": []string{world.Address(first)}}); acctest.BoolOf(moved["changed"]) {
		t.Errorf("a node told the addresses it has = %v", moved)
	}
	if told := suite.Call(t, "cluster_edit", map[string]any{"server": second, "primary_url": primaryURL, "primary_addresses": []string{world.Address(first)}}); len(acctest.Strs(t, told["changes"], "changes")) != 1 {
		t.Errorf("a secondary told where the primary is = %v", told)
	}

	// asked to leave by the primary, the secondary leaves by itself; joined again, it is back
	removed := suite.Call(t, "cluster_node_delete", map[string]any{"server": first, "node": world.Domain(second)})
	if !acctest.BoolOf(removed["changed"]) || !acctest.EventuallyWithin(2*time.Minute, func() bool { return !in(second) && nodesOf(first) == 1 }) {
		t.Fatalf("the node asked to leave = %v, and it says %v", removed, clusterOf(t, second))
	}
	joined := join(second, first, primaryURL)
	if after := acctest.Object(t, joined["after"], "after"); after["role"] != "Secondary" || after["domain"] != testenv.ClusterDomain || strings.Contains(fmt.Sprint(joined), world.Password()) {
		t.Fatalf("joined again = %v", joined["changes"])
	}
	if !acctest.EventuallyWithin(2*time.Minute, func() bool { return nodesOf(first) == 2 }) {
		t.Fatalf("the primary does not list the node that joined: %v", clusterOf(t, first))
	}

	// dropped by the primary without being asked, it still thinks it is in, and leaves without telling anyone
	dropped := suite.Call(t, "cluster_node_delete", map[string]any{"server": first, "node": world.Domain(second), "force": true})
	if len(acctest.Rows(t, acctest.Object(t, dropped["after"], "after")["nodes"], "nodes")) != 1 || !in(second) {
		t.Fatalf("the node dropped = %v, and it says %v", dropped, clusterOf(t, second))
	}
	if left := suite.Call(t, "cluster_leave", map[string]any{"server": second, "force": true}); !acctest.BoolOf(left["changed"]) || !acctest.EventuallyWithin(2*time.Minute, func() bool { return !in(second) }) {
		t.Fatalf("the node left = %v, and it says %v", left, clusterOf(t, second))
	}

	// joined once more and made the primary: the old primary is out, and the cluster is the new one's alone
	join(second, first, primaryURL)
	// a node that has just joined holds no copy of the cluster's zone for a few seconds, and is refused until it does: it is promoted once it has it
	heldBySecond := func() bool {
		zones, err := mustClient(t, second).Zones(context.WithoutCancel(t.Context()), technitium.ZoneFilter{})

		return err == nil && slices.ContainsFunc(zones, liveClusterZone)
	}
	if !acctest.EventuallyWithin(time.Minute, heldBySecond) {
		t.Fatalf("the node that joined never held the cluster's zone: it says %v", clusterOf(t, second))
	}
	promoted := suite.Call(t, "cluster_promote", map[string]any{"server": second})
	if !acctest.BoolOf(promoted["changed"]) || !acctest.EventuallyWithin(3*time.Minute, func() bool { return clusterOf(t, second)["role"] == "Primary" && nodesOf(second) == 1 && !in(first) }) {
		t.Fatalf("promoted = %v: the new primary says %v and the old %v", promoted, clusterOf(t, second), clusterOf(t, first))
	}

	// the cluster deleted on the node that is left, and a new one made of the other
	deleted := suite.Call(t, "cluster_delete", map[string]any{"server": second})
	if !acctest.BoolOf(deleted["changed"]) || !acctest.EventuallyWithin(2*time.Minute, func() bool { return !in(second) }) {
		t.Fatalf("the cluster deleted = %v, and its last node says %v", deleted, clusterOf(t, second))
	}
	made := suite.Call(t, "cluster_create", map[string]any{"server": first, "domain": "acc-again.test", "addresses": []string{world.Address(first)}})
	if after := acctest.Object(t, made["after"], "after"); after["role"] != "Primary" || after["domain"] != "acc-again.test" || len(acctest.Rows(t, after["nodes"], "nodes")) != 1 {
		t.Fatalf("a new cluster made = %v", made)
	}
	if gone := suite.Call(t, "cluster_delete", map[string]any{"server": first}); !acctest.BoolOf(gone["changed"]) || acctest.BoolOf(acctest.Object(t, gone["after"], "after")["in_cluster"]) {
		t.Errorf("the new cluster deleted = %v", gone)
	}
}
