package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// The cluster as each of its two nodes gives it, and a server in none.
const (
	asPrimary   = `{"clusterInitialized":true,"dnsServerDomain":"dock.cluster.example","version":"15.6","clusterDomain":"cluster.example","heartbeatRefreshIntervalSeconds":30,"heartbeatRetryIntervalSeconds":10,"configRefreshIntervalSeconds":900,"configRetryIntervalSeconds":60,"clusterNodes":[{"id":2,"name":"dock.cluster.example","url":"https://dock.cluster.example:53443/","ipAddresses":["10.0.0.2"],"type":"Primary","state":"Self","version":"15.6"},{"id":3,"name":"rpi.cluster.example","url":"https://rpi.cluster.example:53443/","ipAddresses":["10.0.0.3"],"type":"Secondary","state":"Connected","version":"15.6","lastSeen":"2026-10-09T10:00:00Z"}]}`
	asSecondary = `{"clusterInitialized":true,"dnsServerDomain":"rpi.cluster.example","version":"15.6","clusterDomain":"cluster.example","heartbeatRefreshIntervalSeconds":30,"heartbeatRetryIntervalSeconds":10,"configRefreshIntervalSeconds":900,"configRetryIntervalSeconds":60,"configLastSynced":"2026-10-09T10:00:00Z","clusterNodes":[{"id":2,"name":"dock.cluster.example","url":"https://dock.cluster.example:53443/","ipAddresses":["10.0.0.2"],"type":"Primary","state":"Connected","version":"15.6"},{"id":3,"name":"rpi.cluster.example","url":"https://rpi.cluster.example:53443/","ipAddresses":["10.0.0.3"],"type":"Secondary","state":"Self","version":"15.6"}]}`
	inNoCluster = `{"clusterInitialized":false,"dnsServerDomain":"dock","version":"15.6"}`
)

// clusterCalls are the calls that change a cluster.
var clusterCalls = []string{"init", "initJoin", "primary/delete", "primary/removeSecondary", "primary/deleteSecondary", "primary/setOptions", "secondary/leave", "secondary/promote", "secondary/resync", "secondary/updatePrimary", "updateIpAddress"}

// clusterPair is the pair as a cluster of two, dock its primary, with every
// call that changes a cluster answered.
func clusterPair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.Answer("admin/cluster/state", asPrimary)
	p.rpi.Answer("admin/cluster/state", asSecondary)
	for _, call := range clusterCalls {
		p.dock.Answer("admin/cluster/"+call, asPrimary)
		p.rpi.Answer("admin/cluster/"+call, asSecondary)
	}
	p.both("admin/cluster/secondary/resync", `{}`)

	return p
}

// changed is how many calls that change a cluster a server got.
func changed(server *technitiumtest.Server) int {
	n := 0
	for _, call := range clusterCalls {
		n += len(server.Requests("admin/cluster/" + call))
	}

	return n
}

func TestClusterGet(t *testing.T) {
	t.Parallel()

	p := clusterPair(t)
	suite := p.session(t, Options{})

	rows := acctest.Rows(t, suite.Call(t, "cluster_get", nil)["servers"], "servers")
	if len(rows) != 2 {
		t.Fatalf("cluster_get = %v", rows)
	}
	d, r := rows[0], rows[1]
	if d["server"] != "dock" || !acctest.BoolOf(d["in_cluster"]) || d["role"] != "Primary" || d["domain"] != "cluster.example" || acctest.Num(t, d["config_refresh_seconds"], "config_refresh_seconds") != 900 || acctest.Num(t, d["heartbeat_retry_seconds"], "heartbeat_retry_seconds") != 10 || d["config_last_synced"] != nil {
		t.Errorf("the primary = %v", d)
	}
	nodes := acctest.Rows(t, d["nodes"], "nodes")
	if len(nodes) != 2 || acctest.Num(t, nodes[1]["id"], "id") != 3 || nodes[1]["name"] != "rpi.cluster.example" || nodes[1]["type"] != "Secondary" || nodes[1]["state"] != "Connected" || nodes[1]["last_seen"] != "2026-10-09T10:00:00Z" || !slices.Equal(acctest.Strs(t, nodes[1]["addresses"], "addresses"), []string{"10.0.0.3"}) {
		t.Errorf("the nodes as the primary sees them = %v", nodes)
	}
	if r["role"] != "Secondary" || r["config_last_synced"] != "2026-10-09T10:00:00Z" {
		t.Errorf("the secondary = %v", r)
	}

	// servers in no cluster say so, and the answer says what makes one
	p.both("admin/cluster/state", inNoCluster)
	out := suite.Call(t, "cluster_get", nil)
	if rows = acctest.Rows(t, out["servers"], "servers"); acctest.BoolOf(rows[0]["in_cluster"]) || rows[0]["role"] != nil || !strings.Contains(acctest.Str(out["note"]), "no server asked is in a cluster") {
		t.Errorf("servers in no cluster = %v", out)
	}
	// one that will not say is its own row's error, and the other is still given
	p.rpi.Fail("admin/cluster/state", "error", "Access was denied.")
	if rows = acctest.Rows(t, suite.Call(t, "cluster_get", nil)["servers"], "servers"); !strings.Contains(acctest.Str(rows[1]["error"]), "Access was denied") || rows[0]["error"] != nil {
		t.Errorf("a server that will not say = %v", rows)
	}
}

// Each change to a cluster is asked of the node it belongs to, and refused
// before anything is sent when it is asked of the other.
func TestClusterChangesAreAskedOfTheRightNode(t *testing.T) {
	t.Parallel()

	p := clusterPair(t)
	suite := p.session(t, everything)

	for _, c := range []struct {
		tool string
		args map[string]any
		says string
	}{
		{"cluster_edit", map[string]any{"server": "rpi", "config_retry_seconds": 90}, "rpi is the cluster's secondary node, and setting the cluster's intervals is asked of its primary"},
		{"cluster_edit", map[string]any{"server": "dock", "resync": true}, "dock is the cluster's primary node, and naming the primary or fetching its configuration is asked of its secondary"},
		{"cluster_edit", map[string]any{"server": "dock", "heartbeat_refresh_seconds": 5}, "heartbeat_refresh_seconds is 10 to 300"},
		{"cluster_edit", map[string]any{"server": "dock"}, "nothing was given to change"},
		{"cluster_edit", map[string]any{"server": "rpi", "primary_url": "http://dock:5380/"}, "primary_url is the primary's console over HTTPS"},
		{"cluster_node_delete", map[string]any{"server": "rpi", "node": "dock.cluster.example"}, "taking a node out is asked of its primary"},
		{"cluster_node_delete", map[string]any{"server": "dock", "node": "ns9.cluster.example"}, `the cluster has no node "ns9.cluster.example"`},
		{"cluster_node_delete", map[string]any{"server": "dock", "node": "dock.cluster.example"}, "dock.cluster.example is the cluster's primary"},
		{"cluster_leave", map[string]any{"server": "dock"}, "leaving is asked of its secondary"},
		{"cluster_promote", map[string]any{"server": "dock"}, "promoting is asked of its secondary"},
		{"cluster_delete", map[string]any{"server": "rpi"}, "deleting the cluster is asked of its primary"},
		{"cluster_delete", map[string]any{"server": "dock"}, "the cluster cluster.example still has 1 secondary nodes"},
		{"cluster_join", map[string]any{"server": "rpi", "primary_url": "https://dock.cluster.example:53443/", "addresses": []string{"10.0.0.3"}, "primary_username": "admin", "primary_password": "p"}, "rpi is already in the cluster cluster.example, as its secondary node"},
		{"cluster_join", map[string]any{"server": "rpi", "primary_url": "http://dock:5380/", "addresses": []string{"10.0.0.3"}, "primary_username": "admin", "primary_password": "p"}, "joining takes the primary's https:// url"},
		{"cluster_create", map[string]any{"server": "dock", "domain": "other.example", "addresses": []string{"10.0.0.2"}}, "dock is already in the cluster cluster.example, as its primary node"},
		{"cluster_create", map[string]any{"server": "dock", "domain": "cluster", "addresses": []string{"10.0.0.2"}}, "a cluster is made with a domain of its own"},
	} {
		if got := suite.CallErr(t, c.tool, c.args); !strings.Contains(got, c.says) {
			t.Errorf("%s %v = %q, want %q in it", c.tool, c.args, got, c.says)
		}
	}
	if n := changed(p.dock) + changed(p.rpi); n != 0 {
		t.Errorf("%d refused changes reached a server", n)
	}

	// each as a dry run says what it would do and sends nothing
	for _, c := range []struct {
		tool string
		args map[string]any
		says string
	}{
		{"cluster_edit", map[string]any{"server": "dock", "config_retry_seconds": 90, "heartbeat_refresh_seconds": 30}, "would have set the cluster's config retry from 60s to 90s"},
		{"cluster_edit", map[string]any{"server": "rpi", "resync": true, "primary_url": "https://dock.cluster.example:53443/"}, "would have told rpi the primary is at https://dock.cluster.example:53443/"},
		{"cluster_node_delete", map[string]any{"server": "dock", "node": "RPI.cluster.example."}, "would have asked the node rpi.cluster.example to leave the cluster cluster.example"},
		{"cluster_node_delete", map[string]any{"server": "dock", "node": "3", "force": true}, "would have dropped the node rpi.cluster.example from the cluster cluster.example without asking it"},
		{"cluster_leave", map[string]any{"server": "rpi", "force": true}, "would have removed rpi from the cluster cluster.example, without telling the primary"},
		{"cluster_promote", map[string]any{"server": "rpi"}, "would have made rpi the primary of the cluster cluster.example in place of dock.cluster.example, which was asked to leave"},
		{"cluster_delete", map[string]any{"server": "dock", "force": true}, "would have deleted the cluster cluster.example on its primary dock, leaving its 1 secondary nodes without a primary"},
	} {
		c.args["dry_run"] = true
		out := suite.Call(t, c.tool, c.args)
		if got := acctest.Strs(t, out["changes"], "changes"); !slices.Contains(got, c.says) || out["after"] != nil {
			t.Errorf("a dry run of %s = %v, want %q among it", c.tool, got, c.says)
		}
	}
	if n := changed(p.dock) + changed(p.rpi); n != 0 {
		t.Errorf("%d dry runs reached a server", n)
	}
}

func TestClusterChangesMade(t *testing.T) {
	t.Parallel()

	p := clusterPair(t)
	suite := p.session(t, everything)

	// the intervals: only the ones that differ are said and sent, and the same again sends nothing
	edited := suite.Call(t, "cluster_edit", map[string]any{"server": "dock", "config_retry_seconds": 90, "heartbeat_refresh_seconds": 30})
	if asked := p.dock.Last("admin/cluster/primary/setOptions"); !slices.Equal(acctest.Strs(t, edited["changes"], "changes"), []string{"set the cluster's config retry from 60s to 90s"}) || asked.Params.Get("configRetryIntervalSeconds") != "90" || acctest.Object(t, edited["after"], "after")["role"] != "Primary" {
		t.Errorf("the intervals set = %v, with %v", edited, asked.Params)
	}
	if same := suite.Call(t, "cluster_edit", map[string]any{"server": "dock", "heartbeat_refresh_seconds": 30, "addresses": []string{"10.0.0.2"}}); acctest.BoolOf(same["changed"]) || len(p.dock.Requests("admin/cluster/primary/setOptions")) != 1 || len(p.dock.Requests("admin/cluster/updateIpAddress")) != 0 {
		t.Errorf("set to what it is = %v", same)
	}
	if moved := suite.Call(t, "cluster_edit", map[string]any{"server": "dock", "addresses": []string{"10.0.0.2", "10.0.0.12"}}); p.dock.Last("admin/cluster/updateIpAddress").Params.Get("ipAddresses") != "10.0.0.2,10.0.0.12" || len(acctest.Strs(t, moved["changes"], "changes")) != 1 {
		t.Errorf("the node's addresses set = %v", moved)
	}
	told := suite.Call(t, "cluster_edit", map[string]any{"server": "rpi", "primary_url": "https://dock.cluster.example:53443/", "primary_addresses": []string{"10.0.0.2"}, "resync": true})
	if asked := p.rpi.Last("admin/cluster/secondary/updatePrimary"); asked.Params.Get("primaryNodeUrl") != "https://dock.cluster.example:53443/" || asked.Params.Get("primaryNodeIpAddresses") != "10.0.0.2" || len(p.rpi.Requests("admin/cluster/secondary/resync")) != 1 || len(acctest.Strs(t, told["changes"], "changes")) != 2 || !strings.Contains(acctest.Str(told["note"]), "config_last_synced") {
		t.Errorf("the secondary told and resynced = %v, with %v", told, asked.Params)
	}

	// a node taken out by its name or its id, asked or dropped
	suite.Call(t, "cluster_node_delete", map[string]any{"server": "dock", "node": "rpi.cluster.example"})
	if asked := p.dock.Last("admin/cluster/primary/removeSecondary"); asked.Params.Get("secondaryNodeId") != "3" || len(p.dock.Requests("admin/cluster/primary/deleteSecondary")) != 0 {
		t.Errorf("the node was asked to leave with %v", asked.Params)
	}
	if dropped := suite.Call(t, "cluster_node_delete", map[string]any{"server": "dock", "node": "3", "force": true}); p.dock.Last("admin/cluster/primary/deleteSecondary").Params.Get("secondaryNodeId") != "3" || !strings.Contains(acctest.Str(dropped["note"]), "cluster_leave with force") {
		t.Errorf("the node dropped = %v", dropped)
	}
	suite.Call(t, "cluster_leave", map[string]any{"server": "rpi"})
	if asked := p.rpi.Last("admin/cluster/secondary/leave"); len(asked.Params) != 0 {
		t.Errorf("the node left with %v", asked.Params)
	}
	suite.Call(t, "cluster_promote", map[string]any{"server": "rpi", "force": true})
	if asked := p.rpi.Last("admin/cluster/secondary/promote"); asked.Params.Get("forceDeletePrimary") != "true" {
		t.Errorf("the node was promoted with %v", asked.Params)
	}
	// a node that has only just joined is refused in the server's words, which the tool turns into what to do
	p.rpi.Fail("admin/cluster/secondary/promote", "error", "Failed to promote to Primary node: the Cluster Secondary zone does not exist.")
	if msg := suite.CallErr(t, "cluster_promote", map[string]any{"server": "rpi"}); !strings.Contains(msg, "it holds no copy of the cluster's own zone yet") || !strings.Contains(msg, "ask again in a moment") {
		t.Errorf("a node promoted before it has the cluster's zone = %q", msg)
	}
	p.rpi.Fail("admin/cluster/secondary/promote", "error", "HttpClientNetworkHandler could not resolve DANE TLSA record for host: dock.cluster.example (dock.cluster.example:53443)")
	if msg := suite.CallErr(t, "cluster_promote", map[string]any{"server": "rpi"}); !strings.Contains(msg, "it holds no copy of the cluster's own zone yet") {
		t.Errorf("a node promoted before it can read the primary's certificate record = %q", msg)
	}
	suite.Call(t, "cluster_delete", map[string]any{"server": "dock", "force": true})
	if asked := p.dock.Last("admin/cluster/primary/delete"); asked.Params.Get("forceDelete") != "true" {
		t.Errorf("the cluster was deleted with %v", asked.Params)
	}
}

// A cluster is made of a server in none and joined by another, the password
// it is joined with going to the server and nowhere else.
func TestClusterCreateAndJoin(t *testing.T) {
	t.Parallel()

	p := clusterPair(t)
	p.both("admin/cluster/state", inNoCluster)
	suite := p.session(t, everything)

	p.dock.Then("admin/cluster/init", func(technitiumtest.Request) { p.dock.Answer("admin/cluster/state", asPrimary) })
	made := suite.Call(t, "cluster_create", map[string]any{"server": "dock", "domain": "Cluster.example.", "addresses": []string{"10.0.0.2", " "}})
	if asked := p.dock.Last("admin/cluster/init"); asked.Params.Get("clusterDomain") != "cluster.example" || asked.Params.Get("primaryNodeIpAddresses") != "10.0.0.2" || acctest.Object(t, made["after"], "after")["role"] != "Primary" || !slices.Equal(acctest.Strs(t, made["changes"], "changes"), []string{"made dock the primary node of a new cluster, cluster.example, reached at 10.0.0.2"}) {
		t.Errorf("the cluster made = %v, with %v", made, asked.Params)
	}
	// made again under its own domain it is found so, and nothing is sent
	if again := suite.Call(t, "cluster_create", map[string]any{"server": "dock", "domain": "cluster.example", "addresses": []string{"10.0.0.2"}}); acctest.BoolOf(again["changed"]) || len(p.dock.Requests("admin/cluster/init")) != 1 || !strings.Contains(acctest.Str(again["note"]), "in that cluster already") {
		t.Errorf("the cluster made again = %v", again)
	}

	p.rpi.Then("admin/cluster/initJoin", func(technitiumtest.Request) { p.rpi.Answer("admin/cluster/state", asSecondary) })
	joined := suite.Call(t, "cluster_join", map[string]any{"server": "rpi", "primary_url": "https://dock.cluster.example:53443/", "primary_address": "10.0.0.2", "addresses": []string{"10.0.0.3"}, "primary_username": "admin", "primary_password": "5ecre7-join", "primary_totp": "123456", "ignore_certificate_errors": true})
	asked := p.rpi.Last("admin/cluster/initJoin")
	for param, want := range map[string]string{"primaryNodeUrl": "https://dock.cluster.example:53443/", "primaryNodeIpAddress": "10.0.0.2", "secondaryNodeIpAddresses": "10.0.0.3", "primaryNodeUsername": "admin", "primaryNodePassword": "5ecre7-join", "primaryNodeTotp": "123456", "ignoreCertificateErrors": "true"} {
		if asked.Params.Get(param) != want {
			t.Errorf("joined with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if acctest.Object(t, joined["after"], "after")["role"] != "Secondary" || strings.Contains(acctest.Str(joined["note"])+strings.Join(acctest.Strs(t, joined["changes"], "changes"), " "), "5ecre7") {
		t.Errorf("joined = %v", joined)
	}

	// joined, the server's accounts are the primary's, and a token of its own that is no longer taken is said so rather than failing
	p.rpi.Answer("admin/cluster/state", inNoCluster)
	p.rpi.Then("admin/cluster/initJoin", func(technitiumtest.Request) {
		p.rpi.Fail("admin/cluster/state", "invalid-token", "Invalid token or session expired.")
	})
	locked := suite.Call(t, "cluster_join", map[string]any{"server": "rpi", "primary_url": "https://dock.cluster.example:53443/", "addresses": []string{"10.0.0.3"}, "primary_username": "admin", "primary_password": "5ecre7-join"})
	if !acctest.BoolOf(locked["changed"]) || !strings.Contains(acctest.Str(locked["note"]), "the token configured for it here is no longer taken") {
		t.Errorf("joined with a token the primary does not have = %v", locked)
	}
}
