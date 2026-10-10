package tools

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// clusterMember is one node of a cluster as a server sees it, whole.
type clusterMember struct {
	ID           int64    `json:"id"                           jsonschema:"the node's id, which cluster_node_delete names it by"`
	Name         string   `json:"name"`
	Type         string   `json:"type"                         jsonschema:"Primary, where the cluster's settings are changed, or Secondary"`
	State        string   `json:"state"                        jsonschema:"Self for the server asked, Connected for a node it reaches, Unreachable for one it does not, Unknown before it has looked"`
	URL          string   `json:"url"                          jsonschema:"the node's console over HTTPS, which the nodes reach each other on"`
	Addresses    []string `json:"addresses"`
	Version      string   `json:"version,omitempty"`
	UpSince      string   `json:"up_since,omitempty"           jsonschema:"when the node started, UTC"`
	LastSeen     string   `json:"last_seen,omitempty"          jsonschema:"when the server asked last heard from the node, UTC"`
	ConfigSynced string   `json:"config_last_synced,omitempty" jsonschema:"when the node last fetched the primary's configuration, UTC"`
}

// clusterRow is how one server stands in a cluster.
type clusterRow struct {
	Server           string          `json:"server"`
	InCluster        bool            `json:"in_cluster"`
	Domain           string          `json:"domain,omitempty"                    jsonschema:"the cluster's domain, which every node's name is under"`
	Role             string          `json:"role,omitempty"                      jsonschema:"what this server is in it: Primary or Secondary"`
	Nodes            []clusterMember `json:"nodes,omitempty"                     jsonschema:"every node as this server sees it"`
	HeartbeatRefresh int             `json:"heartbeat_refresh_seconds,omitempty" jsonschema:"how often the nodes look at each other"`
	HeartbeatRetry   int             `json:"heartbeat_retry_seconds,omitempty"   jsonschema:"how soon a node looks again after it could not"`
	ConfigRefresh    int             `json:"config_refresh_seconds,omitempty"    jsonschema:"how often a secondary fetches the primary's configuration, beside being told of every change"`
	ConfigRetry      int             `json:"config_retry_seconds,omitempty"      jsonschema:"how soon a secondary fetches again after it could not"`
	ConfigSynced     string          `json:"config_last_synced,omitempty"        jsonschema:"when this server, a secondary, last fetched the primary's configuration, UTC"`
	Error            string          `json:"error,omitempty"`
}

// clusterRowOf is a server's own account of the cluster it is in.
func clusterRowOf(server string, state *technitium.Cluster) clusterRow {
	row := clusterRow{Server: server, InCluster: state.Initialized, Domain: state.Domain, HeartbeatRefresh: state.HeartbeatRefreshIntervalSeconds, HeartbeatRetry: state.HeartbeatRetryIntervalSeconds, ConfigRefresh: state.ConfigRefreshIntervalSeconds, ConfigRetry: state.ConfigRetryIntervalSeconds, ConfigSynced: utc(state.ConfigLastSynced)}
	if self := state.Self(); self != nil {
		row.Role = self.Type
	}
	for _, n := range state.Nodes {
		row.Nodes = append(row.Nodes, clusterMember{ID: n.ID, Name: n.Name, Type: n.Type, State: n.State, URL: n.URL, Addresses: n.IPAddresses, Version: n.Version, UpSince: utc(n.UpSince), LastSeen: utc(n.LastSeen), ConfigSynced: utc(n.ConfigLastSynced)})
	}

	return row
}

// How long a server is waited for after a change that restarts its console,
// and how often it is asked meanwhile.
const (
	restartPatience = 90 * time.Second
	restartStep     = time.Second
)

// settledCluster asks a server how it stands in a cluster once it answers
// again: joining or making a cluster has a server restart its console to
// serve HTTPS, and for that moment nothing is listening.
func settledCluster(ctx context.Context, srv *servers.Server) (*technitium.Cluster, error) {
	deadline := time.Now().Add(restartPatience)
	for {
		state, err := srv.Client.ClusterState(ctx)
		if err == nil {
			return state, nil
		}
		if technitium.IsInvalidToken(err) || time.Now().After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), err)
		case <-time.After(restartStep):
		}
	}
}

// clusterOn is the one server a change to a cluster is made on, with how it
// stands in one.
func (r *registry) clusterOn(ctx context.Context, server string) (*servers.Server, *technitium.Cluster, error) {
	srv, err := r.servers.One(server)
	if err != nil {
		return nil, nil, err
	}
	state, err := srv.Client.ClusterState(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", srv.Name, err)
	}

	return srv, state, nil
}

// roleOf is what a server is in its cluster, "" for a server in none.
func roleOf(state *technitium.Cluster) string {
	if self := state.Self(); state.Initialized && self != nil {
		return self.Type
	}

	return ""
}

// needRole refuses a call made of a server that is not what the call is
// asked of.
func needRole(srv *servers.Server, state *technitium.Cluster, role, what string) error {
	switch got := roleOf(state); {
	case got == "":
		return fmt.Errorf("%s is in no cluster: cluster_get shows how each server stands", srv.Name)
	case got != role:
		return fmt.Errorf("%s is the cluster's %s node, and %s is asked of its %s: cluster_get names the nodes", srv.Name, strings.ToLower(got), what, strings.ToLower(role))
	default:
		return nil
	}
}

// clusterChangeOut is what the tools that change a cluster answer with.
type clusterChangeOut struct {
	Server  string      `json:"server"`
	Changed bool        `json:"changed"         jsonschema:"something was changed; with a dry run, something would be"`
	Changes []string    `json:"changes"         jsonschema:"each change made; with a dry run, each that would be"`
	After   *clusterRow `json:"after,omitempty" jsonschema:"how the server stands in a cluster now, read back; absent from a dry run"`
	Note    string      `json:"note,omitempty"`
}

// finish reads a server's cluster back into an answer once a change is made.
func (out *clusterChangeOut) finish(ctx context.Context, srv *servers.Server, done *changes) error {
	out.Changes, out.Changed = done.said, len(done.said) > 0
	if out.Changes == nil {
		out.Changes = []string{}
	}
	if done.dry {
		return nil
	}
	state, err := settledCluster(ctx, srv)
	if err != nil {
		return fmt.Errorf("the change was made and %s did not answer again: %w", srv.Name, err)
	}
	row := clusterRowOf(srv.Name, state)
	out.After = &row

	return nil
}

func registerClusterTools(r *registry) {
	type clusterGetOut struct {
		Servers []clusterRow `json:"servers"        jsonschema:"each server asked, with the cluster it is in as it sees it"`
		Note    string       `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "cluster_get",
		Description: "How each server stands in a cluster: whether it is in one, the cluster's domain, whether it is the primary or a secondary, every node as it sees it - with the node's id, address, state and when it last fetched the configuration - and how often the nodes look at each other and fetch. A cluster shares settings, apps, accounts, the allowed and blocked lists, and the zones in its catalog; it is changed on its primary. Two servers of one cluster that list different nodes have lost touch.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverArg) (*mcp.CallToolResult, clusterGetOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, clusterGetOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (*technitium.Cluster, error) {
			return srv.Client.ClusterState(ctx)
		})
		if _, err := failures(answers); err != nil {
			return nil, clusterGetOut{}, err
		}

		out := clusterGetOut{Servers: []clusterRow{}}
		clustered := 0
		for _, a := range answers {
			if a.Err != nil {
				out.Servers = append(out.Servers, clusterRow{Server: a.Server.Name, Error: a.Err.Error()})

				continue
			}
			row := clusterRowOf(a.Server.Name, a.Value)
			if row.InCluster {
				clustered++
			}
			out.Servers = append(out.Servers, row)
		}
		if clustered == 0 {
			out.Note = "no server asked is in a cluster: cluster_create makes one of a server, and cluster_join has another join it"
		}

		return nil, out, nil
	})

	type clusterCreateIn struct {
		writeServerArg

		Domain    string   `json:"domain"            jsonschema:"the cluster's domain, as cluster.example.com: every node is renamed under it, and it cannot be changed afterwards"`
		Addresses []string `json:"addresses"         jsonschema:"the addresses of this server that the other nodes will reach it at"`
		DryRun    bool     `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "cluster_create",
		Description: "Make a server the primary node of a new cluster. Nothing it holds is lost. It is renamed under the cluster's domain, its console starts serving HTTPS (on 53443, with a certificate it signs itself, unless it has one) and restarts to do so, and two zones are made: one for the cluster's domain and a catalog under it, which is how the nodes come to share zones. The domain cannot be changed later. cluster_join then has other servers join.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterCreateIn) (*mcp.CallToolResult, clusterChangeOut, error) {
		domain, addresses := cleanName(in.Domain), given(&in.Addresses)
		if domain == "" || !strings.Contains(domain, ".") || len(addresses) == 0 {
			return nil, clusterChangeOut{}, errors.New("a cluster is made with a domain of its own, as cluster.example.com, and an address of this server the other nodes will reach it at")
		}
		srv, state, err := r.clusterOn(ctx, in.Server)
		if err != nil {
			return nil, clusterChangeOut{}, err
		}
		out := clusterChangeOut{Server: srv.Name}
		if state.Initialized {
			if !sameName(state.Domain, domain) {
				return nil, clusterChangeOut{}, fmt.Errorf("%s is already in the cluster %s, as its %s node: a server is in one cluster at a time", srv.Name, state.Domain, strings.ToLower(roleOf(state)))
			}
			out.Note = "the server is in that cluster already"
			done := &changes{dry: in.DryRun}

			err = out.finish(ctx, srv, done)

			return nil, out, err
		}

		out.Note = "the server's console restarts to serve HTTPS as the cluster is made, and it is renamed under the cluster's domain: server_info gives its new name"
		done := &changes{dry: in.DryRun}
		if done.did("made %s the primary node of a new cluster, %s, reached at %s", srv.Name, domain, strings.Join(addresses, ", ")) {
			if _, err := srv.Client.InitCluster(ctx, domain, addresses); err != nil {
				// the console restarting can cut the very connection the answer was coming on
				if now, settleErr := settledCluster(ctx, srv); settleErr != nil || !now.Initialized {
					return nil, clusterChangeOut{}, fmt.Errorf("making the cluster: %w", err)
				}
			}
		}

		err = out.finish(ctx, srv, done)

		return nil, out, err
	})

	type clusterJoinIn struct {
		writeServerArg

		PrimaryURL              string   `json:"primary_url"                         jsonschema:"the primary node's console over HTTPS, as cluster_get gives it for the primary: https://ns1.cluster.example.com:53443/"`
		PrimaryAddress          string   `json:"primary_address,omitempty"           jsonschema:"the primary's address, for when its name does not resolve from this server yet"`
		Addresses               []string `json:"addresses"                           jsonschema:"the addresses of this server that the other nodes will reach it at"`
		PrimaryUsername         string   `json:"primary_username"                    jsonschema:"an administrator's name on the primary: joining is asked of the primary as that account, and an API token will not do"`
		PrimaryPassword         string   `json:"primary_password"                    jsonschema:"that administrator's password. It is sent to this server, which signs in to the primary with it, and is not kept or repeated"`
		PrimaryTOTP             string   `json:"primary_totp,omitempty"              jsonschema:"that administrator's one-time code, when the account has a second factor"`
		IgnoreCertificateErrors bool     `json:"ignore_certificate_errors,omitempty" jsonschema:"accept the certificate the primary signed for itself, which is what it has unless it was given a real one. Only on a network that is trusted"`
		DryRun                  bool     `json:"dry_run,omitempty"                   jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "cluster_join",
		Description: "Have a server join a cluster as a secondary node. Its settings, apps, accounts and tokens, and its allowed and blocked lists are written over with the primary's, for good; its zones and DHCP scopes are kept. Because its accounts are replaced, the API token this server is configured with here stops working unless the primary has the same one: afterwards it is reached with a token of the primary's. Its console restarts to serve HTTPS. Joining can take a while when the primary has much to hand over.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterJoinIn) (*mcp.CallToolResult, clusterChangeOut, error) {
		addresses := given(&in.Addresses)
		if !strings.HasPrefix(in.PrimaryURL, "https://") || len(addresses) == 0 || in.PrimaryUsername == "" || in.PrimaryPassword == "" {
			return nil, clusterChangeOut{}, errors.New("joining takes the primary's https:// url, an address of this server the other nodes will reach it at, and an administrator's name and password on the primary")
		}
		srv, state, err := r.clusterOn(ctx, in.Server)
		if err != nil {
			return nil, clusterChangeOut{}, err
		}
		if state.Initialized {
			return nil, clusterChangeOut{}, fmt.Errorf("%s is already in the cluster %s, as its %s node: cluster_leave takes a secondary out of one first", srv.Name, state.Domain, strings.ToLower(roleOf(state)))
		}

		out := clusterChangeOut{Server: srv.Name, Note: "the server's settings, apps, accounts and lists are now the primary's, and the token configured for it here works only if the primary has it too"}
		done := &changes{dry: in.DryRun}
		if done.did("had %s join the cluster whose primary is at %s, writing the primary's settings, apps, accounts and lists over its own", srv.Name, in.PrimaryURL) {
			if _, err := srv.Client.JoinCluster(ctx, technitium.ClusterJoin{Addresses: addresses, PrimaryURL: in.PrimaryURL, PrimaryAddress: strings.TrimSpace(in.PrimaryAddress), IgnoreCertificateErrors: in.IgnoreCertificateErrors, Username: in.PrimaryUsername, Password: in.PrimaryPassword, TOTP: strings.TrimSpace(in.PrimaryTOTP)}); err != nil {
				// the console restarting can cut the very connection the answer was coming on
				if now, settleErr := settledCluster(ctx, srv); settleErr != nil || !now.Initialized {
					return nil, clusterChangeOut{}, fmt.Errorf("joining the cluster: %w", err)
				}
			}
		}
		if err := out.finish(ctx, srv, done); err != nil {
			if technitium.IsInvalidToken(err) {
				out.Changes, out.Changed = done.said, true
				out.Note = "the server joined, and its accounts are the primary's now: the token configured for it here is no longer taken. Configure it with a token of the primary's to reach it again"

				return nil, out, nil
			}

			return nil, clusterChangeOut{}, err
		}

		return nil, out, nil
	})

	type clusterEditIn struct {
		writeServerArg

		HeartbeatRefresh int      `json:"heartbeat_refresh_seconds,omitempty" jsonschema:"asked of the primary: how often the nodes look at each other, 10 to 300"`
		HeartbeatRetry   int      `json:"heartbeat_retry_seconds,omitempty"   jsonschema:"asked of the primary: how soon a node looks again after it could not, 10 to 300"`
		ConfigRefresh    int      `json:"config_refresh_seconds,omitempty"    jsonschema:"asked of the primary: how often a secondary fetches the configuration, 30 to 3600"`
		ConfigRetry      int      `json:"config_retry_seconds,omitempty"      jsonschema:"asked of the primary: how soon a secondary fetches again after it could not, 30 to 3600"`
		Addresses        []string `json:"addresses,omitempty"                 jsonschema:"asked of any node: the addresses the other nodes reach this one at, when they have changed"`
		PrimaryURL       string   `json:"primary_url,omitempty"               jsonschema:"asked of a secondary: where the primary's console is now, over HTTPS, when it has moved while this node was away"`
		PrimaryAddresses []string `json:"primary_addresses,omitempty"         jsonschema:"asked of a secondary, with primary_url: the primary's addresses, for when its name does not resolve"`
		Resync           bool     `json:"resync,omitempty"                    jsonschema:"asked of a secondary: fetch the whole configuration from the primary again now"`
		DryRun           bool     `json:"dry_run,omitempty"                   jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "cluster_edit",
		Description: "Change how a cluster runs, on the node each change is asked of. On the primary: how often the nodes look at each other and how often a secondary fetches the configuration, which holds for every node. On any node: the addresses the others reach it at. On a secondary: where the primary is now, and a fetch of the whole configuration at once, for a node that has fallen behind. Only what is given is changed. A secondary told of new times has been seen to stop answering the cluster's own calls until its server is restarted, while it goes on answering everything else: after changing the times, see with cluster_get that every node still gives its place in the cluster.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterEditIn) (*mcp.CallToolResult, clusterChangeOut, error) {
		options := technitium.ClusterOptions{HeartbeatRefreshIntervalSeconds: in.HeartbeatRefresh, HeartbeatRetryIntervalSeconds: in.HeartbeatRetry, ConfigRefreshIntervalSeconds: in.ConfigRefresh, ConfigRetryIntervalSeconds: in.ConfigRetry}
		addresses, primaryAddresses := given(&in.Addresses), given(&in.PrimaryAddresses)
		if options == (technitium.ClusterOptions{}) && len(addresses) == 0 && in.PrimaryURL == "" && !in.Resync {
			return nil, clusterChangeOut{}, errors.New("nothing was given to change: an interval, addresses, primary_url or resync")
		}
		for name, seconds := range map[string][3]int{"heartbeat_refresh_seconds": {in.HeartbeatRefresh, 10, 300}, "heartbeat_retry_seconds": {in.HeartbeatRetry, 10, 300}, "config_refresh_seconds": {in.ConfigRefresh, 30, 3600}, "config_retry_seconds": {in.ConfigRetry, 30, 3600}} {
			if seconds[0] != 0 && (seconds[0] < seconds[1] || seconds[0] > seconds[2]) {
				return nil, clusterChangeOut{}, fmt.Errorf("%s is %d to %d", name, seconds[1], seconds[2])
			}
		}
		srv, state, err := r.clusterOn(ctx, in.Server)
		if err != nil {
			return nil, clusterChangeOut{}, err
		}
		if options != (technitium.ClusterOptions{}) {
			if err := needRole(srv, state, technitium.NodePrimary, "setting the cluster's intervals"); err != nil {
				return nil, clusterChangeOut{}, err
			}
		}
		if in.PrimaryURL != "" || in.Resync {
			if err := needRole(srv, state, technitium.NodeSecondary, "naming the primary or fetching its configuration"); err != nil {
				return nil, clusterChangeOut{}, err
			}
		}
		if !state.Initialized {
			return nil, clusterChangeOut{}, fmt.Errorf("%s is in no cluster: cluster_get shows how each server stands", srv.Name)
		}
		if in.PrimaryURL != "" && !strings.HasPrefix(in.PrimaryURL, "https://") {
			return nil, clusterChangeOut{}, errors.New("primary_url is the primary's console over HTTPS, as https://ns1.cluster.example.com:53443/")
		}

		out := clusterChangeOut{Server: srv.Name}
		done := &changes{dry: in.DryRun}
		if options != (technitium.ClusterOptions{}) {
			var set []string
			for _, o := range []struct {
				name    string
				seconds int
				now     int
			}{{"heartbeat refresh", in.HeartbeatRefresh, state.HeartbeatRefreshIntervalSeconds}, {"heartbeat retry", in.HeartbeatRetry, state.HeartbeatRetryIntervalSeconds}, {"config refresh", in.ConfigRefresh, state.ConfigRefreshIntervalSeconds}, {"config retry", in.ConfigRetry, state.ConfigRetryIntervalSeconds}} {
				if o.seconds != 0 && o.seconds != o.now {
					set = append(set, fmt.Sprintf("%s from %ds to %ds", o.name, o.now, o.seconds))
				}
			}
			if len(set) > 0 && done.did("set the cluster's %s", strings.Join(set, ", ")) {
				if _, err := srv.Client.SetClusterOptions(ctx, options); err != nil {
					return nil, clusterChangeOut{}, fmt.Errorf("setting the cluster's intervals: %w", err)
				}
			}
		}
		if self := state.Self(); len(addresses) > 0 && (self == nil || !slices.Equal(self.IPAddresses, addresses)) {
			if done.did("set the addresses the other nodes reach %s at to %s", srv.Name, strings.Join(addresses, ", ")) {
				if _, err := srv.Client.UpdateNodeAddresses(ctx, addresses); err != nil {
					return nil, clusterChangeOut{}, fmt.Errorf("setting the node's addresses: %w", err)
				}
			}
		}
		if in.PrimaryURL != "" {
			if done.did("told %s the primary is at %s", srv.Name, in.PrimaryURL) {
				if _, err := srv.Client.UpdatePrimaryNode(ctx, in.PrimaryURL, primaryAddresses); err != nil {
					return nil, clusterChangeOut{}, fmt.Errorf("naming the primary: %w", err)
				}
			}
		}
		if in.Resync && done.did("had %s fetch the whole configuration from the primary again", srv.Name) {
			if err := srv.Client.ResyncCluster(ctx); err != nil {
				return nil, clusterChangeOut{}, fmt.Errorf("fetching the configuration: %w", err)
			}
			out.Note = "the node fetches after it answers: cluster_get shows when it last did, under config_last_synced"
		}

		err = out.finish(ctx, srv, done)

		return nil, out, err
	})

	type clusterNodeDeleteIn struct {
		writeServerArg

		Node   string `json:"node"              jsonschema:"the secondary node to take out, by the name or the id cluster_get gives it"`
		Force  bool   `json:"force,omitempty"   jsonschema:"drop the node from the cluster at once without asking it to leave: for a node that is gone for good. A node dropped this way that is still running goes on thinking it is in the cluster until cluster_leave with force is asked of it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "cluster_node_delete",
		Description: "Take a secondary node out of a cluster, asked of the primary. By default the node is asked to leave and does so itself, keeping its zones and scopes and what it had of the cluster's settings at the time. With force the primary drops it without asking, which is for a node that no longer exists. The node's own data is not touched either way.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterNodeDeleteIn) (*mcp.CallToolResult, clusterChangeOut, error) {
		srv, state, err := r.clusterOn(ctx, in.Server)
		if err != nil {
			return nil, clusterChangeOut{}, err
		}
		if err := needRole(srv, state, technitium.NodePrimary, "taking a node out"); err != nil {
			return nil, clusterChangeOut{}, err
		}
		want := strings.TrimSpace(in.Node)
		i := slices.IndexFunc(state.Nodes, func(n technitium.Node) bool { return sameName(n.Name, want) || strconv.FormatInt(n.ID, 10) == want })
		if want == "" || i < 0 {
			return nil, clusterChangeOut{}, fmt.Errorf("the cluster has no node %q: cluster_get lists its nodes by name and id", in.Node)
		}
		node := state.Nodes[i]
		if node.Type != technitium.NodeSecondary {
			return nil, clusterChangeOut{}, fmt.Errorf("%s is the cluster's primary: a primary is replaced by promoting a secondary (cluster_promote), or the whole cluster is deleted (cluster_delete)", node.Name)
		}

		out := clusterChangeOut{Server: srv.Name}
		done := &changes{dry: in.DryRun}
		if in.Force {
			out.Note = "the node was not told: if it is still running it thinks it is in the cluster until cluster_leave with force is asked of it"
			if done.did("dropped the node %s from the cluster %s without asking it", node.Name, state.Domain) {
				if _, err := srv.Client.DeleteSecondaryNode(ctx, node.ID); err != nil {
					return nil, clusterChangeOut{}, fmt.Errorf("dropping %s: %w", node.Name, err)
				}
			}
		} else if done.did("asked the node %s to leave the cluster %s", node.Name, state.Domain) {
			if _, err := srv.Client.RemoveSecondaryNode(ctx, node.ID); err != nil {
				return nil, clusterChangeOut{}, fmt.Errorf("asking %s to leave: %w", node.Name, err)
			}
		}

		err = out.finish(ctx, srv, done)

		return nil, out, err
	})

	type clusterLeaveIn struct {
		writeServerArg

		Force  bool `json:"force,omitempty"   jsonschema:"leave without telling the primary: for a primary that is gone, or a node the primary has already dropped"`
		DryRun bool `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "cluster_leave",
		Description: "Take a secondary node out of its cluster, asked of that node. It keeps its zones, its scopes and the settings, apps and accounts it had of the cluster's at the time, goes back to its own name, and no longer follows the primary. The copies it holds of the cluster's zones stay as copies and go stale. To be in the cluster again it joins again (cluster_join).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterLeaveIn) (*mcp.CallToolResult, clusterChangeOut, error) {
		srv, state, err := r.clusterOn(ctx, in.Server)
		if err != nil {
			return nil, clusterChangeOut{}, err
		}
		if err := needRole(srv, state, technitium.NodeSecondary, "leaving"); err != nil {
			return nil, clusterChangeOut{}, err
		}

		out := clusterChangeOut{Server: srv.Name}
		done := &changes{dry: in.DryRun}
		how := "telling the primary"
		if in.Force {
			how = "without telling the primary"
		}
		if done.did("removed %s from the cluster %s, %s", srv.Name, state.Domain, how) {
			if _, err := srv.Client.LeaveCluster(ctx, in.Force); err != nil {
				return nil, clusterChangeOut{}, fmt.Errorf("leaving the cluster: %w", err)
			}
		}

		err = out.finish(ctx, srv, done)

		return nil, out, err
	})

	type clusterPromoteIn struct {
		writeServerArg

		Force  bool `json:"force,omitempty"   jsonschema:"drop the primary there is without fetching its configuration a last time and without telling it: for a primary that is gone. What it had changed since this node last fetched is lost"`
		DryRun bool `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "cluster_promote",
		Description: "Make a secondary node the cluster's primary, asked of that secondary. It fetches the whole configuration from the primary there is, has that server leave the cluster, and takes its place: the zones it held as copies of the cluster's become its own, and the other secondaries follow it from then on. The old primary keeps its data and is in no cluster afterwards; it can join again as a secondary. It is how a primary is moved or retired, and with force how a cluster is saved when its primary is lost.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterPromoteIn) (*mcp.CallToolResult, clusterChangeOut, error) {
		srv, state, err := r.clusterOn(ctx, in.Server)
		if err != nil {
			return nil, clusterChangeOut{}, err
		}
		if err := needRole(srv, state, technitium.NodeSecondary, "promoting"); err != nil {
			return nil, clusterChangeOut{}, err
		}
		old := "the primary"
		if primary := state.Primary(); primary != nil {
			old = primary.Name
		}

		out := clusterChangeOut{Server: srv.Name, Note: "the old primary is in no cluster now and keeps its data: cluster_join has it join again as a secondary"}
		done := &changes{dry: in.DryRun}
		how := "which was asked to leave"
		if in.Force {
			how = "which was dropped without being asked"
		}
		if done.did("made %s the primary of the cluster %s in place of %s, %s", srv.Name, state.Domain, old, how) {
			if _, err := srv.Client.PromoteToPrimary(ctx, in.Force); err != nil {
				// the server's own words for a node that has only just joined: it has no copy of the cluster's zone yet, or cannot yet read the primary's certificate record out of it
				if strings.Contains(err.Error(), "Cluster Secondary zone does not exist") || strings.Contains(err.Error(), "could not resolve DANE TLSA record") {
					return nil, clusterChangeOut{}, fmt.Errorf("promoting %s: it holds no copy of the cluster's own zone yet, which a node that has just joined takes a few seconds to transfer: ask again in a moment, and zone_list shows when it has it (%w)", srv.Name, err)
				}

				return nil, clusterChangeOut{}, fmt.Errorf("promoting %s: %w", srv.Name, err)
			}
		}

		err = out.finish(ctx, srv, done)

		return nil, out, err
	})

	type clusterDeleteIn struct {
		writeServerArg

		Force  bool `json:"force,omitempty"   jsonschema:"delete the cluster on its primary though it still has secondary nodes, which are left thinking they are in a cluster with no primary: each then needs cluster_leave with force, or one of them cluster_promote with force"`
		DryRun bool `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "cluster_delete",
		Description: "Delete a cluster, asked of its primary. The server keeps everything it holds but its place in a cluster and goes back to its own name. The server allows it only once no secondary node is left - take each out first with cluster_node_delete - unless forced. The cluster's two zones stay on the server as ordinary zones.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterDeleteIn) (*mcp.CallToolResult, clusterChangeOut, error) {
		srv, state, err := r.clusterOn(ctx, in.Server)
		if err != nil {
			return nil, clusterChangeOut{}, err
		}
		if err := needRole(srv, state, technitium.NodePrimary, "deleting the cluster"); err != nil {
			return nil, clusterChangeOut{}, err
		}
		secondaries := len(state.Nodes) - 1
		if secondaries > 0 && !in.Force {
			return nil, clusterChangeOut{}, fmt.Errorf("the cluster %s still has %d secondary nodes: take each out with cluster_node_delete first, or give force to leave them without a primary", state.Domain, secondaries)
		}

		out := clusterChangeOut{Server: srv.Name}
		done := &changes{dry: in.DryRun}
		left := ""
		if secondaries > 0 {
			left = fmt.Sprintf(", leaving its %d secondary nodes without a primary", secondaries)
			out.Note = "each node left behind still thinks it is in the cluster: cluster_leave with force takes one out, or cluster_promote with force makes one the primary"
		}
		if done.did("deleted the cluster %s on its primary %s%s", state.Domain, srv.Name, left) {
			if _, err := srv.Client.DeleteCluster(ctx, in.Force); err != nil {
				return nil, clusterChangeOut{}, fmt.Errorf("deleting the cluster: %w", err)
			}
		}

		err = out.finish(ctx, srv, done)

		return nil, out, err
	})
}
