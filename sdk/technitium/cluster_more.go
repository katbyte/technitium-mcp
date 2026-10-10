package technitium

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// DeleteCluster takes the cluster off its primary node, which is asked of
// the primary. Nothing but the cluster's own configuration is lost. The
// server allows it only when no secondary node is left, unless forced: then
// the secondaries are orphaned, and one of them has to be promoted by hand.
func (c *Client) DeleteCluster(ctx context.Context, force bool) (*Cluster, error) {
	params := url.Values{}
	if force {
		params.Set("forceDelete", yes)
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/primary/delete", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// LeaveCluster takes a secondary node out of its cluster, which is asked of
// the secondary. Nothing but the cluster's own configuration is lost.
// Forced, it leaves without telling the primary, which is for a primary
// that is gone.
func (c *Client) LeaveCluster(ctx context.Context, force bool) (*Cluster, error) {
	params := url.Values{}
	if force {
		params.Set("forceLeave", yes)
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/secondary/leave", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// RemoveSecondaryNode has the primary ask a secondary node to leave the
// cluster, as if LeaveCluster had been asked of that node.
func (c *Client) RemoveSecondaryNode(ctx context.Context, id int64) (*Cluster, error) {
	if id == 0 {
		return nil, errors.New("admin/cluster/primary/removeSecondary: which node, by its id")
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/primary/removeSecondary", url.Values{"secondaryNodeId": {strconv.FormatInt(id, 10)}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// DeleteSecondaryNode has the primary drop a secondary node from the
// cluster at once, without asking it to leave: for a node that is gone.
func (c *Client) DeleteSecondaryNode(ctx context.Context, id int64) (*Cluster, error) {
	if id == 0 {
		return nil, errors.New("admin/cluster/primary/deleteSecondary: which node, by its id")
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/primary/deleteSecondary", url.Values{"secondaryNodeId": {strconv.FormatInt(id, 10)}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// PromoteToPrimary makes a secondary node the cluster's primary, which is
// asked of the secondary: it fetches the whole configuration from the
// primary there is, has it leave the cluster, and takes its place. Forced,
// the old primary is dropped without being asked, which is for one that is
// gone. It can take a while.
func (c *Client) PromoteToPrimary(ctx context.Context, forceDeletePrimary bool) (*Cluster, error) {
	params := url.Values{}
	if forceDeletePrimary {
		params.Set("forceDeletePrimary", yes)
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/secondary/promote", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ResyncCluster has a secondary node fetch the whole configuration from the
// primary again, which is asked of the secondary.
func (c *Client) ResyncCluster(ctx context.Context) error {
	return c.write(ctx, "admin/cluster/secondary/resync", nil, nil)
}

// ClusterOptions is how often the nodes of a cluster look at each other and
// fetch the primary's configuration, in seconds: 0 leaves one as it is.
type ClusterOptions struct {
	// HeartbeatRefresh and HeartbeatRetry are 10 to 300
	HeartbeatRefreshIntervalSeconds, HeartbeatRetryIntervalSeconds int
	// ConfigRefresh and ConfigRetry are 30 to 3600
	ConfigRefreshIntervalSeconds, ConfigRetryIntervalSeconds int
}

// SetClusterOptions sets a cluster's options, which is asked of its primary
// and holds for every node.
func (c *Client) SetClusterOptions(ctx context.Context, options ClusterOptions) (*Cluster, error) {
	params := url.Values{}
	for name, seconds := range map[string]int{"heartbeatRefreshIntervalSeconds": options.HeartbeatRefreshIntervalSeconds, "heartbeatRetryIntervalSeconds": options.HeartbeatRetryIntervalSeconds, "configRefreshIntervalSeconds": options.ConfigRefreshIntervalSeconds, "configRetryIntervalSeconds": options.ConfigRetryIntervalSeconds} {
		if seconds != 0 {
			params.Set(name, strconv.Itoa(seconds))
		}
	}
	if len(params) == 0 {
		return nil, errors.New("admin/cluster/primary/setOptions: which option: nothing was given to set")
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/primary/setOptions", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// UpdatePrimaryNode tells a secondary node where the cluster's primary is
// now, which is asked of the secondary: for a primary whose address changed
// while the secondary was away. With no addresses the name in the url is
// resolved.
func (c *Client) UpdatePrimaryNode(ctx context.Context, primaryURL string, addresses []string) (*Cluster, error) {
	if primaryURL == "" {
		return nil, errors.New("admin/cluster/secondary/updatePrimary: the primary's url, over HTTPS")
	}
	params := url.Values{"primaryNodeUrl": {primaryURL}}
	set(params, map[string]string{"primaryNodeIpAddresses": strings.Join(addresses, ",")})

	var out Cluster
	if err := c.write(ctx, "admin/cluster/secondary/updatePrimary", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// UpdateNodeAddresses sets the addresses the other nodes of the cluster
// reach this node at.
func (c *Client) UpdateNodeAddresses(ctx context.Context, addresses []string) (*Cluster, error) {
	if len(addresses) == 0 {
		return nil, errors.New("admin/cluster/updateIpAddress: an address the other nodes reach this one at")
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/updateIpAddress", url.Values{"ipAddresses": {strings.Join(addresses, ",")}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// The four calls below are the ones the nodes of a cluster make of each
// other. They are here because the API has them; a person joins a server to
// a cluster with JoinCluster, which makes them itself.

// SecondaryNode is a secondary node as it tells the primary of itself.
type SecondaryNode struct {
	// ID is the id the node made up for itself when it began to join
	ID int64
	// URL is the node's console over HTTPS
	URL       string
	Addresses []string
	// Certificate is the certificate the node's console answers with,
	// base64url encoded
	Certificate string
}

func (n SecondaryNode) params(path string) (url.Values, error) {
	if n.ID == 0 || n.URL == "" || len(n.Addresses) == 0 || n.Certificate == "" {
		return nil, errors.New(path + ": a secondary node is told of by its id, its url, its addresses and its certificate")
	}

	return url.Values{"secondaryNodeId": {strconv.FormatInt(n.ID, 10)}, "secondaryNodeUrl": {n.URL}, "secondaryNodeIpAddresses": {strings.Join(n.Addresses, ",")}, "secondaryNodeCertificate": {n.Certificate}}, nil
}

// AdmitSecondaryNode is a server asking the primary to let it into the
// cluster as a secondary node.
func (c *Client) AdmitSecondaryNode(ctx context.Context, node SecondaryNode) (*Cluster, error) {
	params, err := node.params("admin/cluster/primary/join")
	if err != nil {
		return nil, err
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/primary/join", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// UpdateSecondaryNode is a secondary node telling the primary its url, its
// addresses or its certificate have changed.
func (c *Client) UpdateSecondaryNode(ctx context.Context, node SecondaryNode) (*Cluster, error) {
	params, err := node.params("admin/cluster/primary/updateSecondary")
	if err != nil {
		return nil, err
	}

	var out Cluster
	if err := c.write(ctx, "admin/cluster/primary/updateSecondary", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// TransferConfig is a secondary node fetching the cluster's configuration
// from the primary: a zip file of it, with the DNSSEC private keys of the
// zones named.
func (c *Client) TransferConfig(ctx context.Context, includeZones []string) ([]byte, error) {
	params := url.Values{}
	set(params, map[string]string{"includeZones": strings.Join(includeZones, ",")})

	return c.readFile(ctx, "admin/cluster/primary/transferConfig", params)
}

// NotifySecondary is the primary telling a secondary node that the
// configuration has changed, and where the primary is.
func (c *Client) NotifySecondary(ctx context.Context, primaryID int64, primaryURL string, addresses []string) error {
	if primaryID == 0 || primaryURL == "" || len(addresses) == 0 {
		return errors.New("admin/cluster/secondary/notify: a notify says which primary it is from: its id, its url and its addresses")
	}

	return c.write(ctx, "admin/cluster/secondary/notify", url.Values{"primaryNodeId": {strconv.FormatInt(primaryID, 10)}, "primaryNodeUrl": {primaryURL}, "primaryNodeIpAddresses": {strings.Join(addresses, ",")}}, nil)
}
