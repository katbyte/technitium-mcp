//go:build acceptance

package technitium_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// A cluster's own calls, which end with there being no cluster: its options
// set, a node asked to leave, a node dropped and left to leave by itself, a
// secondary made the primary, and the cluster deleted.
//
// Nothing can run after it, so it is skipped by every run but the one that
// ends the suite, which make starts last and alone.
//
//nolint:paralleltest // it takes the cluster apart, which every other test of a cluster needs whole
func TestClusterTakenApart(t *testing.T) {
	ready(t)
	if !world.TakingApart() {
		t.Skip("the cluster is taken apart only by the run that ends the suite: make testacc-sdk")
	}
	ctx := t.Context()
	ns1, ns2 := server(t, world.First), server(t, world.Second)
	state := func(c *technitium.Client) *technitium.Cluster {
		t.Helper()
		got, err := c.ClusterState(ctx)
		if err != nil {
			t.Fatal(err)
		}

		return got
	}
	node := func(of *technitium.Cluster, name string) *technitium.Node {
		t.Helper()
		i := slices.IndexFunc(of.Nodes, func(n technitium.Node) bool { return n.Name == world.Domain(name) })
		if i < 0 {
			t.Fatalf("the cluster has no node %s among %+v", world.Domain(name), of.Nodes)
		}

		return &of.Nodes[i]
	}
	left := func(name string) bool {
		now, answered := world.Settled(ctx, name)

		return answered && !now.Initialized
	}

	// its options are the primary's to set: a secondary is refused, and so are times the server will not keep. The primary sets them further down, once the secondary has left: told of new times while it is in, a 15.6 secondary has been seen to stop answering cluster calls (api-defs/README.md)
	options := technitium.ClusterOptions{HeartbeatRefreshIntervalSeconds: 45, HeartbeatRetryIntervalSeconds: 15, ConfigRefreshIntervalSeconds: 600, ConfigRetryIntervalSeconds: 90}
	if _, err := ns2.SetClusterOptions(ctx, options); err == nil {
		t.Error("a secondary set the cluster's options")
	}
	if _, err := ns1.SetClusterOptions(ctx, technitium.ClusterOptions{HeartbeatRefreshIntervalSeconds: 1}); err == nil {
		t.Error("the nodes were set to look at each other every second")
	}

	// where the nodes are reached: each says of itself, and a secondary is told where the primary is
	before := state(ns1)
	primaryID, primaryURL := node(before, world.First).ID, node(before, world.First).URL
	if moved, err := ns1.UpdateNodeAddresses(ctx, []string{world.Address(world.First)}); err != nil || !slices.Equal(node(moved, world.First).IPAddresses, []string{world.Address(world.First)}) {
		t.Errorf("UpdateNodeAddresses = %+v, %v", moved, err)
	}
	if moved, err := ns2.UpdatePrimaryNode(ctx, primaryURL, []string{world.Address(world.First)}); err != nil || node(moved, world.First).URL != primaryURL {
		t.Errorf("UpdatePrimaryNode = %+v, %v", moved, err)
	}
	if _, err := ns1.UpdatePrimaryNode(ctx, primaryURL, nil); err == nil {
		t.Error("the primary was told where the primary is")
	}

	// a secondary fetches the configuration again when asked, and the primary has none to fetch
	if err := ns2.ResyncCluster(ctx); err != nil {
		t.Errorf("ResyncCluster = %v", err)
	}
	if err := ns1.ResyncCluster(ctx); err == nil {
		t.Error("the primary was resynced")
	}

	// the calls the nodes make of each other are taken from an administrator too: the primary hands over the whole configuration as a zip file, and a secondary takes a notify
	config, err := ns1.TransferConfig(ctx, nil)
	if err != nil || !bytes.HasPrefix(config, []byte("PK")) || len(config) < 1000 {
		t.Errorf("TransferConfig = %d bytes, %v", len(config), err)
	}
	if _, err := ns2.TransferConfig(ctx, nil); err == nil {
		t.Error("a secondary handed over the cluster's configuration")
	}
	if err := ns2.NotifySecondary(ctx, primaryID, primaryURL, []string{world.Address(world.First)}); err != nil {
		t.Errorf("NotifySecondary = %v", err)
	}
	// a node is let in, or tells of itself, with the certificate its console answers with: one that is no certificate is refused, and the cluster is as it was
	stranger := technitium.SecondaryNode{ID: 4242, URL: "https://ns9." + before.Domain + ":53443/", Addresses: []string{"10.250.250.9"}, Certificate: "bm90LWEtY2VydGlmaWNhdGU"}
	if _, err := ns1.AdmitSecondaryNode(ctx, stranger); err == nil || !strings.Contains(err.Error(), "ASN1") {
		t.Errorf("AdmitSecondaryNode with what is no certificate = %v", err)
	}
	if _, err := ns1.UpdateSecondaryNode(ctx, stranger); err == nil || !strings.Contains(err.Error(), "ASN1") {
		t.Errorf("UpdateSecondaryNode with what is no certificate = %v", err)
	}
	if now := state(ns1); len(now.Nodes) != 2 {
		t.Fatalf("after two calls that were refused the cluster's nodes = %+v", now.Nodes)
	}

	// asked to leave by the primary, the secondary leaves as if it had been asked itself
	if _, err := ns2.RemoveSecondaryNode(ctx, node(before, world.Second).ID); err == nil {
		t.Error("a secondary removed a node")
	}
	removed, err := ns1.RemoveSecondaryNode(ctx, node(before, world.Second).ID)
	if err != nil || len(removed.Nodes) != 1 || removed.Nodes[0].Type != technitium.NodePrimary {
		t.Fatalf("RemoveSecondaryNode = %+v, %v", removed, err)
	}
	if !acctest.EventuallyWithin(2*time.Minute, func() bool { return left(world.Second) && len(state(ns1).Nodes) == 1 }) {
		t.Fatalf("the secondary was asked to leave and is still in: it says %+v and the primary %+v", state(ns2), state(ns1).Nodes)
	}

	// the cluster's times, set on the primary while it is the only node, and held by a node that joins afterwards
	set, err := ns1.SetClusterOptions(ctx, options)
	if err != nil || set.HeartbeatRefreshIntervalSeconds != 45 || set.HeartbeatRetryIntervalSeconds != 15 || set.ConfigRefreshIntervalSeconds != 600 || set.ConfigRetryIntervalSeconds != 90 || len(set.Nodes) != 1 {
		t.Fatalf("SetClusterOptions = %+v, %v", set, err)
	}

	// dropped by the primary without being asked, it still thinks it is in, and leaves by itself without telling anyone
	if err := world.Join(ctx, world.Second, world.First); err != nil {
		t.Fatal(err)
	}
	if joined := state(ns2); joined.HeartbeatRefreshIntervalSeconds != 45 || joined.ConfigRefreshIntervalSeconds != 600 {
		t.Errorf("a node that joined after the cluster's times were set has them as %d and %d seconds", joined.HeartbeatRefreshIntervalSeconds, joined.ConfigRefreshIntervalSeconds)
	}
	if _, err := ns1.LeaveCluster(ctx, false); err == nil {
		t.Fatal("the primary left its own cluster")
	}
	dropped, err := ns1.DeleteSecondaryNode(ctx, node(state(ns1), world.Second).ID)
	if err != nil || len(dropped.Nodes) != 1 {
		t.Fatalf("DeleteSecondaryNode = %+v, %v", dropped, err)
	}
	if orphan := state(ns2); !orphan.Initialized {
		t.Errorf("a node the primary dropped knows it at once: %+v", orphan)
	}
	// out of the cluster, a server goes back to the name it had before it joined
	gone, err := ns2.LeaveCluster(ctx, true)
	if err != nil || gone.Initialized || len(gone.Nodes) != 0 || strings.HasSuffix(gone.ServerDomain, before.Domain) {
		t.Errorf("LeaveCluster = %+v, %v", gone, err)
	}
	if !acctest.EventuallyWithin(2*time.Minute, func() bool { return left(world.Second) }) {
		t.Fatalf("the node left and still says it is in a cluster: %+v", state(ns2))
	}

	// a secondary made the primary: the old primary is out, and the cluster is the new one's alone
	if err := world.Join(ctx, world.Second, world.First); err != nil {
		t.Fatal(err)
	}
	if _, err := ns1.PromoteToPrimary(ctx, false); err == nil {
		t.Fatal("the primary was promoted to primary")
	}
	promoted, err := ns2.PromoteToPrimary(ctx, false)
	if err != nil || !promoted.Initialized || len(promoted.Nodes) != 1 || promoted.Self() == nil || promoted.Self().Type != technitium.NodePrimary || promoted.Domain != before.Domain {
		t.Errorf("PromoteToPrimary = %+v, %v", promoted, err)
	}
	if !acctest.EventuallyWithin(3*time.Minute, func() bool {
		now, answered := world.Settled(ctx, world.Second)

		return answered && now.Initialized && now.Self() != nil && now.Self().Type == technitium.NodePrimary && len(now.Nodes) == 1 && left(world.First)
	}) {
		t.Fatalf("the secondary was promoted: it says %+v and the old primary %+v", state(ns2), state(ns1))
	}

	// and the cluster deleted on the node that is left
	if _, err := ns1.DeleteCluster(ctx, false); err == nil {
		t.Error("a server in no cluster deleted one")
	}
	deleted, err := ns2.DeleteCluster(ctx, false)
	if err != nil || deleted.Initialized || len(deleted.Nodes) != 0 {
		t.Errorf("DeleteCluster = %+v, %v", deleted, err)
	}
	if !acctest.EventuallyWithin(2*time.Minute, func() bool { return left(world.Second) }) {
		t.Fatalf("the cluster was deleted and its last node still says it is in one: %+v", state(ns2))
	}
	if now := state(ns2); now.Domain != "" || len(now.Nodes) != 0 || strings.HasSuffix(now.ServerDomain, before.Domain) {
		t.Errorf("after the cluster was deleted the server says %+v", now)
	}
}
