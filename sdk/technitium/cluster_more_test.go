package technitium_test

import (
	"net/http"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// clusterState is a cluster of two as its primary gives it.
const clusterState = `{"clusterInitialized":true,"dnsServerDomain":"ns1.cluster.example","version":"15.6","clusterDomain":"cluster.example","heartbeatRefreshIntervalSeconds":30,"heartbeatRetryIntervalSeconds":10,"configRefreshIntervalSeconds":900,"configRetryIntervalSeconds":60,"configLastSynced":"2025-09-27T13:19:55Z","clusterNodes":[{"id":1164167,"name":"ns1.cluster.example","url":"https://ns1.cluster.example:53443/","ipAddresses":["192.0.2.2"],"type":"Primary","state":"Self"},{"id":811905692,"name":"ns2.cluster.example","url":"https://ns2.cluster.example:53443/","ipAddresses":["192.0.2.3"],"type":"Secondary","state":"Connected"}]}`

// The calls that change a cluster each answer with the cluster as it then
// stands, and send what they take in the body of a POST.
func TestClusterChanges(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	for _, path := range []string{"primary/delete", "secondary/leave", "primary/removeSecondary", "primary/deleteSecondary", "secondary/promote", "primary/setOptions", "secondary/updatePrimary", "updateIpAddress", "primary/join", "primary/updateSecondary"} {
		fake.Answer("admin/cluster/"+path, clusterState)
	}
	fake.AnswerWhole("admin/cluster/secondary/resync", `{"status":"ok"}`)
	fake.AnswerWhole("admin/cluster/secondary/notify", `{"status":"ok"}`)
	fake.AnswerText("admin/cluster/primary/transferConfig", "PK\x03\x04 a zip file")
	c := client(t, fake)

	const primaryURL = "https://ns1.cluster.example:53443/"
	both := []string{"192.0.2.2", "192.0.2.12"}
	options := technitium.ClusterOptions{HeartbeatRefreshIntervalSeconds: 60, ConfigRetryIntervalSeconds: 120}
	node := technitium.SecondaryNode{ID: 811905692, URL: "https://ns2.cluster.example:53443/", Addresses: []string{"192.0.2.3", "2001:db8::3"}, Certificate: "MIIB"}
	calls := map[string]struct {
		do   func() (*technitium.Cluster, error)
		want map[string]string
	}{
		"primary/delete":          {func() (*technitium.Cluster, error) { return c.DeleteCluster(t.Context(), true) }, map[string]string{"forceDelete": "true"}},
		"secondary/leave":         {func() (*technitium.Cluster, error) { return c.LeaveCluster(t.Context(), true) }, map[string]string{"forceLeave": "true"}},
		"primary/removeSecondary": {func() (*technitium.Cluster, error) { return c.RemoveSecondaryNode(t.Context(), 811905692) }, map[string]string{"secondaryNodeId": "811905692"}},
		"primary/deleteSecondary": {func() (*technitium.Cluster, error) { return c.DeleteSecondaryNode(t.Context(), 811905692) }, map[string]string{"secondaryNodeId": "811905692"}},
		"secondary/promote":       {func() (*technitium.Cluster, error) { return c.PromoteToPrimary(t.Context(), true) }, map[string]string{"forceDeletePrimary": "true"}},
		"primary/setOptions":      {func() (*technitium.Cluster, error) { return c.SetClusterOptions(t.Context(), options) }, map[string]string{"heartbeatRefreshIntervalSeconds": "60", "configRetryIntervalSeconds": "120"}},
		"secondary/updatePrimary": {func() (*technitium.Cluster, error) { return c.UpdatePrimaryNode(t.Context(), primaryURL, both[:1]) }, map[string]string{"primaryNodeUrl": "https://ns1.cluster.example:53443/", "primaryNodeIpAddresses": "192.0.2.2"}},
		"updateIpAddress":         {func() (*technitium.Cluster, error) { return c.UpdateNodeAddresses(t.Context(), both) }, map[string]string{"ipAddresses": "192.0.2.2,192.0.2.12"}},
		"primary/join":            {func() (*technitium.Cluster, error) { return c.AdmitSecondaryNode(t.Context(), node) }, map[string]string{"secondaryNodeId": "811905692", "secondaryNodeUrl": "https://ns2.cluster.example:53443/", "secondaryNodeIpAddresses": "192.0.2.3,2001:db8::3", "secondaryNodeCertificate": "MIIB"}},
		"primary/updateSecondary": {func() (*technitium.Cluster, error) { return c.UpdateSecondaryNode(t.Context(), node) }, map[string]string{"secondaryNodeId": "811905692", "secondaryNodeUrl": "https://ns2.cluster.example:53443/", "secondaryNodeIpAddresses": "192.0.2.3,2001:db8::3", "secondaryNodeCertificate": "MIIB"}},
	}
	for path, call := range calls {
		got, err := call.do()
		if err != nil {
			t.Errorf("%s: %v", path, err)

			continue
		}
		if !got.Initialized || got.Domain != "cluster.example" || len(got.Nodes) != 2 || got.HeartbeatRefreshIntervalSeconds != 30 || got.ConfigRefreshIntervalSeconds != 900 || got.ConfigRetryIntervalSeconds != 60 || got.ConfigLastSynced == "" {
			t.Errorf("%s answered %+v", path, got)
		}
		asked := fake.Last("admin/cluster/" + path)
		if asked.Method != http.MethodPost || len(asked.Params) != len(call.want) {
			t.Errorf("%s was sent %s %v", path, asked.Method, asked.Params)
		}
		for param, want := range call.want {
			if asked.Params.Get(param) != want {
				t.Errorf("%s was sent %s=%q, want %q", path, param, asked.Params.Get(param), want)
			}
		}
	}

	// unforced, nothing is sent but the call
	if _, err := c.DeleteCluster(t.Context(), false); err != nil || len(fake.Last("admin/cluster/primary/delete").Params) != 0 {
		t.Errorf("the cluster was deleted with %v, %v", fake.Last("admin/cluster/primary/delete").Params, err)
	}
	if _, err := c.LeaveCluster(t.Context(), false); err != nil || len(fake.Last("admin/cluster/secondary/leave").Params) != 0 {
		t.Errorf("the cluster was left with %v, %v", fake.Last("admin/cluster/secondary/leave").Params, err)
	}
	if _, err := c.PromoteToPrimary(t.Context(), false); err != nil || len(fake.Last("admin/cluster/secondary/promote").Params) != 0 {
		t.Errorf("the node was promoted with %v, %v", fake.Last("admin/cluster/secondary/promote").Params, err)
	}
	if _, err := c.UpdatePrimaryNode(t.Context(), "https://ns1.cluster.example:53443/", nil); err != nil || len(fake.Last("admin/cluster/secondary/updatePrimary").Params) != 1 {
		t.Errorf("the primary was named with %v, %v", fake.Last("admin/cluster/secondary/updatePrimary").Params, err)
	}

	if err := c.ResyncCluster(t.Context()); err != nil || fake.Last("admin/cluster/secondary/resync").Method != http.MethodPost {
		t.Errorf("ResyncCluster = %v", err)
	}
	if err := c.NotifySecondary(t.Context(), 1164167, "https://ns1.cluster.example:53443/", []string{"192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("admin/cluster/secondary/notify"); asked.Method != http.MethodPost || len(asked.Params) != 3 || asked.Params.Get("primaryNodeId") != "1164167" || asked.Params.Get("primaryNodeUrl") != "https://ns1.cluster.example:53443/" || asked.Params.Get("primaryNodeIpAddresses") != "192.0.2.2" {
		t.Errorf("the secondary was notified with %v", asked.Params)
	}
	zip, err := c.TransferConfig(t.Context(), []string{"example.com", "example.net"})
	if err != nil || string(zip[:2]) != "PK" || fake.Last("admin/cluster/primary/transferConfig").Params.Get("includeZones") != "example.com,example.net" || fake.Last("admin/cluster/primary/transferConfig").Method != http.MethodGet {
		t.Errorf("TransferConfig = %q, %v, asked with %v", zip, err, fake.Last("admin/cluster/primary/transferConfig").Params)
	}
	if _, err := c.TransferConfig(t.Context(), nil); err != nil || len(fake.Last("admin/cluster/primary/transferConfig").Params) != 0 {
		t.Errorf("the configuration alone was asked for with %v, %v", fake.Last("admin/cluster/primary/transferConfig").Params, err)
	}

	// what names no node, or sets nothing, is not sent
	sent := 0
	for path := range calls {
		sent += len(fake.Requests("admin/cluster/" + path))
	}
	refused := map[string]error{}
	_, refused["no node removed"] = c.RemoveSecondaryNode(t.Context(), 0)
	_, refused["no node deleted"] = c.DeleteSecondaryNode(t.Context(), 0)
	_, refused["no option set"] = c.SetClusterOptions(t.Context(), technitium.ClusterOptions{})
	_, refused["no primary named"] = c.UpdatePrimaryNode(t.Context(), "", []string{"192.0.2.2"})
	_, refused["no address given"] = c.UpdateNodeAddresses(t.Context(), nil)
	_, refused["a node with no certificate"] = c.AdmitSecondaryNode(t.Context(), technitium.SecondaryNode{ID: 1, URL: "https://ns2.cluster.example:53443/", Addresses: []string{"192.0.2.3"}})
	_, refused["a node with no id"] = c.UpdateSecondaryNode(t.Context(), technitium.SecondaryNode{URL: "https://ns2.cluster.example:53443/", Addresses: []string{"192.0.2.3"}, Certificate: "MIIB"})
	refused["a notify from nobody"] = c.NotifySecondary(t.Context(), 0, "https://ns1.cluster.example:53443/", []string{"192.0.2.2"})
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	now := 0
	for path := range calls {
		now += len(fake.Requests("admin/cluster/" + path))
	}
	if now != sent || len(fake.Requests("admin/cluster/secondary/notify")) != 1 {
		t.Errorf("%d refused calls reached the server", now-sent)
	}
}

// Joining as an account with a second factor sends its one-time code beside
// its password, and without one sends none.
func TestJoinClusterWithASecondFactor(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("admin/cluster/initJoin", clusterState)
	c := client(t, fake)

	join := technitium.ClusterJoin{Addresses: []string{"192.0.2.3"}, PrimaryURL: "https://ns1.cluster.example:53443/", Username: "admin", Password: "a password", TOTP: "123456"}
	if _, err := c.JoinCluster(t.Context(), join); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("admin/cluster/initJoin"); asked.Method != http.MethodPost || asked.Params.Get("primaryNodeTotp") != "123456" || asked.Params.Get("primaryNodePassword") != "a password" || asked.Params.Has("primaryNodeIpAddress") {
		t.Errorf("joined with %v", asked.Params)
	}
	join.TOTP = ""
	if _, err := c.JoinCluster(t.Context(), join); err != nil || fake.Last("admin/cluster/initJoin").Params.Has("primaryNodeTotp") {
		t.Errorf("joined without a code with %v, %v", fake.Last("admin/cluster/initJoin").Params, err)
	}
}
