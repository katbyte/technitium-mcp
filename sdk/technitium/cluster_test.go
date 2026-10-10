package technitium_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// The answers a 15.6 server gave while a cluster of two was made through its
// API: a server on its own, and the secondary once it had joined.
const (
	aloneAnswer   = `{"version":"15.6","dnsServerDomain":"ns1","clusterInitialized":false,"serverIpAddresses":["172.18.0.2"]}`
	clusterAnswer = `{"version":"15.6","dnsServerDomain":"ns2.cluster.test","clusterInitialized":true,"clusterDomain":"cluster.test","heartbeatRefreshIntervalSeconds":30,"clusterNodes":[
		{"id":26417483,"name":"ns1.cluster.test","url":"https://ns1.cluster.test:53443/","ipAddresses":["172.18.0.2"],"type":"Primary","state":"Connected","lastSeen":"2026-10-10T00:28:04.3172639Z"},
		{"id":2005089605,"name":"ns2.cluster.test","url":"https://ns2.cluster.test:53443/","ipAddresses":["172.18.0.3"],"type":"Secondary","state":"Self","version":"15.6","upSince":"2026-10-10T00:27:30.9241377Z","configLastSynced":"2026-10-10T00:28:04Z"}
	]}`
)

func TestClusterState(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	c := client(t, fake)

	fake.Answer("admin/cluster/state", aloneAnswer)
	alone, err := c.ClusterState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if alone.Initialized || alone.ServerDomain != "ns1" || alone.Self() != nil || alone.Primary() != nil || !slices.Equal(alone.ServerIPAddresses, []string{"172.18.0.2"}) {
		t.Errorf("a server on its own = %+v", alone)
	}
	if asked := fake.Last("admin/cluster/state"); asked.Method != http.MethodGet || asked.Params.Get("includeServerIpAddresses") != "true" {
		t.Errorf("the state was asked for with %s %v", asked.Method, asked.Params)
	}

	fake.Answer("admin/cluster/state", clusterAnswer)
	joined, err := c.ClusterState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !joined.Initialized || joined.Domain != "cluster.test" || joined.ServerDomain != "ns2.cluster.test" || len(joined.Nodes) != 2 {
		t.Fatalf("a node of a cluster = %+v", joined)
	}
	self, primary := joined.Self(), joined.Primary()
	if self == nil || self.Name != "ns2.cluster.test" || self.Type != technitium.NodeSecondary || self.ConfigLastSynced == "" || !slices.Equal(self.IPAddresses, []string{"172.18.0.3"}) {
		t.Errorf("the node asked = %+v", self)
	}
	if primary == nil || primary.Name != "ns1.cluster.test" || primary.State != technitium.NodeConnected || primary.URL != "https://ns1.cluster.test:53443/" || primary.ID != 26417483 {
		t.Errorf("the primary as the secondary sees it = %+v", primary)
	}
}

// A cluster is made on one server and joined from the other, which is asked
// of the primary as an administrator: the password goes in the body of a
// POST with everything else, and into no address or error.
func TestInitAndJoinCluster(t *testing.T) {
	t.Parallel()

	const password = "hunter2-hunter2"
	fake := technitiumtest.New(t)
	fake.Answer("admin/cluster/init", clusterAnswer)
	fake.Answer("admin/cluster/initJoin", clusterAnswer)
	fake.Answer("zones/create", `{"domain":"shared.test"}`)
	c := client(t, fake)

	made, err := c.InitCluster(t.Context(), "cluster.test", []string{"172.18.0.2", "fd00::2"})
	if err != nil || !made.Initialized {
		t.Fatalf("InitCluster = %+v, %v", made, err)
	}
	if asked := fake.Last("admin/cluster/init"); asked.Method != http.MethodPost || asked.Params.Get("clusterDomain") != "cluster.test" || asked.Params.Get("primaryNodeIpAddresses") != "172.18.0.2,fd00::2" {
		t.Errorf("the cluster was made with %s %v", asked.Method, asked.Params)
	}

	join := technitium.ClusterJoin{Addresses: []string{"172.18.0.3"}, PrimaryURL: "https://ns1.cluster.test:53443/", PrimaryAddress: "172.18.0.2", IgnoreCertificateErrors: true, Username: "admin", Password: password}
	joined, err := c.JoinCluster(t.Context(), join)
	if err != nil || joined.Self() == nil || joined.Self().Type != technitium.NodeSecondary {
		t.Fatalf("JoinCluster = %+v, %v", joined, err)
	}
	asked := fake.Last("admin/cluster/initJoin")
	for param, want := range map[string]string{"secondaryNodeIpAddresses": "172.18.0.3", "primaryNodeUrl": "https://ns1.cluster.test:53443/", "primaryNodeIpAddress": "172.18.0.2", "ignoreCertificateErrors": "true", "primaryNodeUsername": "admin", "primaryNodePassword": password} {
		if asked.Params.Get(param) != want {
			t.Errorf("the cluster was joined with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if asked.Method != http.MethodPost {
		t.Errorf("the cluster was joined with a %s, which puts the password in the address", asked.Method)
	}

	// what the primary is left to work out is not sent
	join.PrimaryAddress, join.IgnoreCertificateErrors = "", false
	if _, err := c.JoinCluster(t.Context(), join); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("admin/cluster/initJoin"); asked.Params.Has("primaryNodeIpAddress") || asked.Params.Has("ignoreCertificateErrors") {
		t.Errorf("a join that left the primary's address out sent %v", asked.Params)
	}

	// a refusal says nothing of the password
	fake.Fail("admin/cluster/initJoin", "error", "Connection refused (ns1.cluster.test:53443)")
	if _, err := c.JoinCluster(t.Context(), join); err == nil || strings.Contains(err.Error(), password) || !strings.Contains(err.Error(), "Connection refused") {
		t.Errorf("a refused join = %v", err)
	}

	// what cannot work is not sent
	sent := len(fake.Requests("admin/cluster/init")) + len(fake.Requests("admin/cluster/initJoin"))
	if _, err := c.InitCluster(t.Context(), "cluster.test", nil); err == nil {
		t.Error("a cluster with no address for its primary was made")
	}
	if _, err := c.InitCluster(t.Context(), "", []string{"172.18.0.2"}); err == nil {
		t.Error("a cluster with no domain was made")
	}
	join.Password = ""
	if _, err := c.JoinCluster(t.Context(), join); err == nil {
		t.Error("a cluster was joined with no password")
	}
	if now := len(fake.Requests("admin/cluster/init")) + len(fake.Requests("admin/cluster/initJoin")); now != sent {
		t.Errorf("%d refused calls reached the server", now-sent)
	}

	// a zone made a member of the cluster's catalog is what its nodes share
	if _, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "shared.test", Type: technitium.ZonePrimary, Catalog: "cluster-catalog.cluster.test"}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/create"); asked.Params.Get("catalog") != "cluster-catalog.cluster.test" {
		t.Errorf("a zone for the cluster's catalog was made with %v", asked.Params)
	}
}
