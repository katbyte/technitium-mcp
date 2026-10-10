package tools

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/katbyte/go-kt/version"
	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// utc is a time as the server wrote it, as every tool gives one: UTC, to the
// second, with the Z that says so. "" is a time the server did not give or
// its "never".
func utc(serverTime string) string {
	t, ok := technitium.ParseTime(serverTime)
	if !ok {
		return ""
	}

	return t.UTC().Format(time.RFC3339)
}

// note adds a sentence to a note that may already hold one.
func note(have, more string) string {
	if have == "" {
		return more
	}

	return have + "; " + more
}

// serverRow is one configured server as server_info answers with it.
type serverRow struct {
	Server string `json:"server"          jsonschema:"the name this server is configured under, which every tool's server argument takes"`
	URL    string `json:"url"`
	Error  string `json:"error,omitempty" jsonschema:"why this server could not be asked; the rest of its row is then empty"`

	Domain          string `json:"domain,omitempty"           jsonschema:"the server's own domain name, which the zones it is primary for name as their name server"`
	Version         string `json:"version,omitempty"`
	UpdateAvailable bool   `json:"update_available,omitempty" jsonschema:"the server says a newer version of itself is out"`
	UpdateVersion   string `json:"update_version,omitempty"`
	Started         string `json:"started,omitempty"          jsonschema:"when the server last started, in UTC"`
	Uptime          string `json:"uptime,omitempty"`
	Cluster         string `json:"cluster,omitempty"          jsonschema:"the cluster this server is a node of; absent for a server on its own"`
	ClusterRole     string `json:"cluster_role,omitempty"     jsonschema:"this node's role in its cluster: Primary, whose settings, accounts and lists the others copy, or Secondary. A zone the cluster shares is changed on the node that holds it as a primary, which zone_list names"`

	ClusterNodes []clusterNode `json:"cluster_nodes,omitempty" jsonschema:"the cluster's other nodes as this one sees them"`

	Account            string   `json:"account,omitempty"             jsonschema:"the user the API token acts as"`
	TokenName          string   `json:"token_name,omitempty"`
	CannotView         []string `json:"cannot_view,omitempty"         jsonschema:"the sections of the server the token's account may not read (Zones, Cache, Settings, Logs, ...); absent when it may read all of them"`
	CannotModify       []string `json:"cannot_modify,omitempty"       jsonschema:"the sections the token's account may not change; absent when it may change all of them"`
	CannotDelete       []string `json:"cannot_delete,omitempty"       jsonschema:"the sections the token's account may not delete from; absent when it may delete from all of them"`
	DefaultCredentials bool     `json:"default_credentials,omitempty" jsonschema:"the admin account still has the password the server ships with"`
	DNSSECValidation   bool     `json:"dnssec_validation"             jsonschema:"the server validates DNSSEC on what it resolves"`
	Note               string   `json:"note,omitempty"`
}

// clusterNode is another node of a server's cluster, as that server sees it.
type clusterNode struct {
	Name     string `json:"name"                jsonschema:"the node's own domain name"`
	Role     string `json:"role"                jsonschema:"Primary or Secondary"`
	State    string `json:"state"               jsonschema:"Connected, Unreachable, or Unknown when this server has not heard from it yet"`
	LastSeen string `json:"last_seen,omitempty" jsonschema:"when this server last heard from it, in UTC"`
}

// serverRowOf reads one server for server_info. A server that answers and
// refuses the token is an error that says both.
func serverRowOf(ctx context.Context, srv *servers.Server) (serverRow, error) {
	row := serverRow{Server: srv.Name, URL: srv.Client.BaseURL()}

	status, err := srv.Client.Status(ctx)
	if err != nil {
		return row, err
	}
	row.Domain, row.DefaultCredentials = status.Server, status.HasDefaultCredentials

	session, err := srv.Client.Session(ctx)
	if err != nil {
		return row, fmt.Errorf("the server answers, calling itself %s, and its session could not be read: %w", status.Server, err)
	}
	info := session.Info
	row.Version, row.Account, row.TokenName, row.DNSSECValidation = info.Version, session.Username, session.TokenName, info.DNSSECValidation
	if info.Domain != "" {
		row.Domain = info.Domain
	}
	if info.ClusterInitialized {
		row.Cluster = info.ClusterDomain
		// the nodes are the Administration section's to show, which a token
		// may not read: the server is still described without them
		if state, err := srv.Client.ClusterState(ctx); err != nil {
			row.Note = "the cluster's nodes could not be read: " + err.Error()
		} else {
			for i := range state.Nodes {
				node := &state.Nodes[i]
				if node.State == technitium.NodeSelf {
					row.ClusterRole = node.Type

					continue
				}
				row.ClusterNodes = append(row.ClusterNodes, clusterNode{Name: node.Name, Role: node.Type, State: node.State, LastSeen: utc(node.LastSeen)})
			}
		}
	}
	if started, ok := info.Started(); ok {
		row.Started, row.Uptime = started.UTC().Format(time.RFC3339), time.Since(started).Round(time.Second).String()
	}
	for section, may := range info.Permissions {
		if !may.CanView {
			row.CannotView = append(row.CannotView, section)
		}
		if !may.CanModify {
			row.CannotModify = append(row.CannotModify, section)
		}
		if !may.CanDelete {
			row.CannotDelete = append(row.CannotDelete, section)
		}
	}
	slices.Sort(row.CannotView)
	slices.Sort(row.CannotModify)
	slices.Sort(row.CannotDelete)

	// whether an update is out is asked of the maker's site by the server,
	// and a server that cannot reach it is still described
	update, err := srv.Client.CheckForUpdate(ctx)
	switch {
	case err != nil:
		row.Note = note(row.Note, "whether an update is out could not be asked: "+err.Error())
	case update.Available:
		row.UpdateAvailable, row.UpdateVersion = true, update.UpdateVersion
	case !update.CheckEnabled:
		row.Note = note(row.Note, "the server is set not to look for updates, so update_available says nothing")
	default:
	}

	return row, nil
}

func registerServerTools(r *registry) {
	// serverInfoOut names this binary's version beside each server's,
	// because both change what a caller can rely on: the server's decides
	// what the API answers, and this binary's decides which tools and fixes
	// are in play. The second is the one that goes stale unnoticed - an MCP
	// client keeps the binary it started with.
	type serverInfoOut struct {
		TechnitiumMCPVersion string      `json:"technitium_mcp_version" jsonschema:"the build of this MCP server answering, e.g. v0.1.1+4@g8909c7c: the tag, the commits since it, and the commit"`
		SDKAPIVersion        string      `json:"sdk_api_version"        jsonschema:"the Technitium version whose API this MCP server's client was written against; a server ahead of it may answer with fields the client does not read"`
		Servers              []serverRow `json:"servers"                jsonschema:"every configured server, in the order configured, one that could not be asked included with its error"`
		Note                 string      `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "server_info",
		Description: "Check connectivity to the configured Technitium DNS servers and describe each one. A row gives the name the server is configured under (what every tool's server argument takes), its own domain name, version, whether an update is out, when it started, the cluster it is part of with its role there and the other nodes as it sees them, and the account the API token acts as with the sections of the server that account may not read, change or delete from. A server that cannot be reached, or refuses the token, is listed with the reason beside the ones that answer. Start here.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverArg) (*mcp.CallToolResult, serverInfoOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, serverInfoOut{}, err
		}

		out := serverInfoOut{TechnitiumMCPVersion: version.Version, SDKAPIVersion: technitium.APIVersion, Servers: make([]serverRow, 0, len(picked))}
		reached := 0
		for _, a := range ask(ctx, picked, serverRowOf) {
			row := a.Value
			if a.Err != nil {
				row = serverRow{Server: a.Server.Name, URL: a.Server.Client.BaseURL(), Error: a.Err.Error()}
			} else {
				reached++
			}
			out.Servers = append(out.Servers, row)
		}
		if reached == 0 {
			out.Note = "no server could be asked: each row says why"
		}

		return nil, out, nil
	})
}
