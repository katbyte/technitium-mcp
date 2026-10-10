package technitium

import (
	"context"
	"errors"
	"net/url"
	"strings"
)

// The roles a node has in a cluster, and the states one node sees another in.
const (
	NodePrimary   = "Primary"
	NodeSecondary = "Secondary"

	// NodeSelf is the node that was asked
	NodeSelf        = "Self"
	NodeConnected   = "Connected"
	NodeUnreachable = "Unreachable"
)

// Cluster is how a server stands in a cluster, or that it is in none.
type Cluster struct {
	Initialized bool `json:"clusterInitialized"`
	// Domain is the cluster's own domain name, under which each node's is:
	// ns1.example.com in the cluster example.com
	Domain string `json:"clusterDomain"`
	// ServerDomain is the name of the server that was asked
	ServerDomain string `json:"dnsServerDomain"`
	Version      string `json:"version"`
	Nodes        []Node `json:"clusterNodes"`
	// ServerIPAddresses are the addresses the server that was asked has
	ServerIPAddresses []string `json:"serverIpAddresses"`
}

// Node is one server of a cluster, as the server that was asked sees it.
type Node struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// URL is where the node's console answers the other nodes, over HTTPS
	URL         string   `json:"url"`
	IPAddresses []string `json:"ipAddresses"`
	// Type is the node's role: the one Primary, whose settings the others
	// copy, or a Secondary
	Type string `json:"type"`
	// State is Self for the server asked, and for another node whether it
	// is reached: Connected, Unreachable, or not yet known
	State   string `json:"state"`
	Version string `json:"version"`
	UpSince string `json:"upSince"`
	// LastSeen is when the server asked last heard from the node
	LastSeen string `json:"lastSeen"`
	// ConfigLastSynced is when a secondary last copied the primary's settings
	ConfigLastSynced string `json:"configLastSynced"`
}

// Self is the node that was asked, nil for a server in no cluster.
func (c *Cluster) Self() *Node {
	for i := range c.Nodes {
		if c.Nodes[i].State == NodeSelf {
			return &c.Nodes[i]
		}
	}

	return nil
}

// Primary is the cluster's primary node, nil for a server in no cluster.
func (c *Cluster) Primary() *Node {
	for i := range c.Nodes {
		if c.Nodes[i].Type == NodePrimary {
			return &c.Nodes[i]
		}
	}

	return nil
}

// ClusterState reads how the server stands in a cluster: whether it is in
// one, and every node as this one sees it.
func (c *Client) ClusterState(ctx context.Context) (*Cluster, error) {
	var out Cluster
	if err := c.read(ctx, "admin/cluster/state", url.Values{"includeServerIpAddresses": {yes}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// InitCluster makes the server the primary node of a new cluster under the
// domain given, reached by the other nodes at the addresses given. The
// server renames itself under the cluster's domain, turns HTTPS on for its
// console if it was off - which takes it a moment, during which no node can
// join - and makes the cluster's two zones. The cluster's domain cannot be
// changed afterwards.
func (c *Client) InitCluster(ctx context.Context, domain string, addresses []string) (*Cluster, error) {
	if domain == "" || len(addresses) == 0 {
		return nil, errors.New("admin/cluster/init: a cluster needs a domain and an address the other nodes reach this one at")
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/init", url.Values{"clusterDomain": {domain}, "primaryNodeIpAddresses": {strings.Join(addresses, ",")}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ClusterJoin is what a server needs to join a cluster as a secondary node.
type ClusterJoin struct {
	// Addresses are where the other nodes reach this server
	Addresses []string
	// PrimaryURL is the primary node's console over HTTPS, as its own
	// cluster state gives it: https://ns1.example.com:53443/
	PrimaryURL string
	// PrimaryAddress is the primary's address, for when its name does not
	// resolve from this server yet
	PrimaryAddress string
	// IgnoreCertificateErrors accepts the certificate the primary signed
	// for itself, which is what it has unless it was given a real one
	IgnoreCertificateErrors bool
	// Username and Password are an administrator's on the primary: joining
	// is asked of it as that account, and an API token will not do
	Username, Password string
}

// JoinCluster makes the server a secondary node of the cluster whose primary
// is named. Its settings, apps, allowed and blocked lists, and its accounts
// and their tokens are written over with the primary's: the token this
// client holds stops working, and one of the primary's works here instead.
func (c *Client) JoinCluster(ctx context.Context, join ClusterJoin) (*Cluster, error) {
	if len(join.Addresses) == 0 || join.PrimaryURL == "" || join.Username == "" || join.Password == "" {
		return nil, errors.New("admin/cluster/initJoin: joining needs this server's address, the primary's url, and an administrator's name and password on the primary")
	}
	params := url.Values{"secondaryNodeIpAddresses": {strings.Join(join.Addresses, ",")}, "primaryNodeUrl": {join.PrimaryURL}, "primaryNodeUsername": {join.Username}, "primaryNodePassword": {join.Password}}
	if join.PrimaryAddress != "" {
		params.Set("primaryNodeIpAddress", join.PrimaryAddress)
	}
	if join.IgnoreCertificateErrors {
		params.Set("ignoreCertificateErrors", yes)
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/initJoin", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}
