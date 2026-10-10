package tools

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// listOf reads which of a server's two lists a tool was asked about.
func listOf(text string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "", "blocked":
		return "blocked", nil
	case "allowed":
		return "allowed", nil
	default:
		return "", fmt.Errorf("list %q: it is blocked or allowed", text)
	}
}

// namesOn are the names on one of a server's two lists.
func namesOn(ctx context.Context, srv *servers.Server, list string) ([]string, error) {
	if list == "allowed" {
		return srv.Client.AllowedNames(ctx)
	}

	return srv.Client.BlockedNames(ctx)
}

func registerMoreListTools(r *registry) {
	type blockImportIn struct {
		writeServerArg

		List   string   `json:"list,omitempty"    jsonschema:"blocked (the default), the server's own list of names it refuses, or allowed, its list of names nothing blocks"`
		Names  []string `json:"names"             jsonschema:"the names to add, each standing for itself and every name under it"`
		DryRun bool     `json:"dry_run,omitempty" jsonschema:"add nothing, and answer with what would be"`
	}
	type blockImportOut struct {
		Server  string   `json:"server"`
		List    string   `json:"list"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		Added   []string `json:"added"             jsonschema:"the names that were not on the list before"`
		Already []string `json:"already,omitempty" jsonschema:"the names that were on it already"`
		Total   int      `json:"total"             jsonschema:"how many names the list holds now; with a dry run, how many it would"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "block_import",
		Description: "Add many names at once to a server's own list of blocked names, or to its list of allowed names: a list moved in from somewhere else, where block_set adds one name with a check of what it would do. Names already on the list are left as they are. Nothing is taken off: block_delete removes one name and block_flush empties a list. On a cluster a change made on a secondary is passed to the primary and comes back a few seconds later.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blockImportIn) (*mcp.CallToolResult, blockImportOut, error) {
		list, err := listOf(in.List)
		if err != nil {
			return nil, blockImportOut{}, err
		}
		var names []string
		for _, name := range in.Names {
			if name = cleanName(name); name == "" {
				continue
			}
			if strings.ContainsAny(name, " \t/,|") {
				return nil, blockImportOut{}, fmt.Errorf("%q is no domain name: each name is one, as ads.example.com", name)
			}
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			return nil, blockImportOut{}, errors.New("which names: give the domain names to add")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, blockImportOut{}, err
		}
		before, err := namesOn(ctx, srv, list)
		if err != nil {
			return nil, blockImportOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}

		out := blockImportOut{Server: srv.Name, List: list, Changes: []string{}, Added: []string{}, Total: len(before)}
		for _, name := range names {
			if slices.ContainsFunc(before, func(held string) bool { return sameName(held, name) }) {
				out.Already = append(out.Already, name)
			} else {
				out.Added = append(out.Added, name)
			}
		}
		if len(out.Added) == 0 {
			out.Note = "every name was on the list already"

			return nil, out, nil
		}

		out.Changed, out.Total = true, len(before)+len(out.Added)
		done := &changes{dry: in.DryRun}
		if done.did("added %d names to the %s names of %s", len(out.Added), list, srv.Name) {
			if list == "allowed" {
				err = srv.Client.ImportAllowed(ctx, out.Added)
			} else {
				err = srv.Client.ImportBlocked(ctx, out.Added)
			}
			if err != nil {
				return nil, blockImportOut{}, fmt.Errorf("adding the names: %w", err)
			}
			after, err := namesOn(ctx, srv, list)
			if err != nil {
				return nil, blockImportOut{}, fmt.Errorf("the names were added and the list could not be read back: %w", err)
			}
			out.Total = len(after)
			if secondaryNode(ctx, srv) {
				out.Note = "this server is a secondary node of a cluster: the change is the primary's to make, and reaches this list from there a few seconds later"
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type blockFlushIn struct {
		writeServerArg

		List   string `json:"list"              jsonschema:"which list to empty: blocked, the server's own list of names it refuses, or allowed, its list of names nothing blocks"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"empty nothing, and answer with what would be"`
	}
	type blockFlushOut struct {
		Server  string   `json:"server"`
		List    string   `json:"list"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		Removed int      `json:"removed"        jsonschema:"how many names were on the list"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "block_flush",
		Description: "Empty a server's own list of blocked names, or its list of allowed names: every name on it, at once. block_list reads the list first, and is the only record of what was on it. The block lists a server fetches are another thing (block_lists_set) and are not touched: emptying the allowed names lets those lists block what the allowed names were sparing.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blockFlushIn) (*mcp.CallToolResult, blockFlushOut, error) {
		if strings.TrimSpace(in.List) == "" {
			return nil, blockFlushOut{}, errors.New("which list: blocked or allowed")
		}
		list, err := listOf(in.List)
		if err != nil {
			return nil, blockFlushOut{}, err
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, blockFlushOut{}, err
		}
		before, err := namesOn(ctx, srv, list)
		if err != nil {
			return nil, blockFlushOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		out := blockFlushOut{Server: srv.Name, List: list, Changes: []string{}, Removed: len(before)}
		if len(before) == 0 {
			out.Note = "the list is empty already"

			return nil, out, nil
		}

		out.Changed = true
		done := &changes{dry: in.DryRun}
		if done.did("emptied the %s names of %s, which held %d", list, srv.Name, len(before)) {
			if list == "allowed" {
				err = srv.Client.FlushAllowed(ctx)
			} else {
				err = srv.Client.FlushBlocked(ctx)
			}
			if err != nil {
				return nil, blockFlushOut{}, fmt.Errorf("emptying the list: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type blockTreeIn struct {
		serverArg

		List  string `json:"list,omitempty"  jsonschema:"blocked (the default) or allowed"`
		Under string `json:"under,omitempty" jsonschema:"the name to look under, as example.com; left out, the top of the list"`
		Above bool   `json:"above,omitempty" jsonschema:"for a name that only leads on, with nothing listed at it and one name under it: answer for the nearest name above that is listed or branches, where the default answers for the first below. It is the way back up a list. Any other name is answered for itself either way"`
	}
	type blockTreeOn struct {
		Server string   `json:"server"`
		At     string   `json:"at"              jsonschema:"the name the answer is for: asked for a name that only leads on to one other, the server answers for the first name below it where the list branches or a listed name is"`
		Listed bool     `json:"listed"          jsonschema:"that name is on the list itself"`
		Below  []string `json:"below"           jsonschema:"the names under it that are on the list or lead to names that are"`
		Error  string   `json:"error,omitempty"`
	}
	type blockTreeOut struct {
		List    string        `json:"list"`
		Servers []blockTreeOn `json:"servers"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "block_tree",
		Description: "Walk a server's own list of blocked names, or of allowed names, as the tree it is kept as: whether a name is on the list, and the names under it that are or that lead to ones that are. It is for a list too long to read whole - block_list gives every name at once - and for seeing what is listed under one domain.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blockTreeIn) (*mcp.CallToolResult, blockTreeOut, error) {
		list, err := listOf(in.List)
		if err != nil {
			return nil, blockTreeOut{}, err
		}
		under := cleanName(in.Under)
		if in.Above && under == "" {
			return nil, blockTreeOut{}, errors.New("above looks upward from a name: give the name in under")
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, blockTreeOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (*technitium.Listed, error) {
			switch {
			case in.Above && list == "allowed":
				return srv.Client.AllowedAbove(ctx, under)
			case in.Above:
				return srv.Client.BlockedAbove(ctx, under)
			case list == "allowed":
				return srv.Client.AllowedUnder(ctx, under)
			default:
				return srv.Client.BlockedUnder(ctx, under)
			}
		})
		if _, err := failures(answers); err != nil {
			return nil, blockTreeOut{}, err
		}

		out := blockTreeOut{List: list, Servers: []blockTreeOn{}}
		for _, a := range answers {
			row := blockTreeOn{Server: a.Server.Name, Below: []string{}}
			if a.Err != nil {
				row.Error = a.Err.Error()
			} else {
				row.At, row.Listed = a.Value.Domain, len(a.Value.Records) > 0
				row.Below = append(row.Below, a.Value.Zones...)
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})

	type dhcpScopeDeleteIn struct {
		writeServerArg

		Scope  string `json:"scope"             jsonschema:"the scope's name, as dhcp_scopes gives it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"delete nothing, and answer with what would be"`
	}
	type dhcpScopeDeleteOut struct {
		Server       string   `json:"server"`
		Scope        string   `json:"scope"`
		Changed      bool     `json:"changed"`
		Changes      []string `json:"changes"`
		Leases       int      `json:"leases"         jsonschema:"how many leases the scope had given out, which the server forgets with it"`
		Reservations int      `json:"reservations"   jsonschema:"how many addresses it kept for particular machines"`
		Note         string   `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "dhcp_scope_delete",
		Description: "Delete a DHCP scope from a server, with its reservations and the leases it has given out. The machines keep the addresses they hold until their leases run out, and then get none from this server: delete a scope only once another serves that network, or the network is gone. To stop a scope leasing and keep it, switch it off (dhcp_scope_set with enabled false). The records the scope wrote into the zones for its reservations are left behind, each with a comment naming the scope.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dhcpScopeDeleteIn) (*mcp.CallToolResult, dhcpScopeDeleteOut, error) {
		name := strings.TrimSpace(in.Scope)
		if name == "" {
			return nil, dhcpScopeDeleteOut{}, errors.New("which scope: give its name, as dhcp_scopes gives it")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, dhcpScopeDeleteOut{}, err
		}
		scopes, err := srv.Client.Scopes(ctx)
		if err != nil {
			return nil, dhcpScopeDeleteOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		i := slices.IndexFunc(scopes, func(s technitium.Scope) bool { return strings.EqualFold(s.Name, name) })
		if i < 0 {
			return nil, dhcpScopeDeleteOut{}, fmt.Errorf("%s has no scope named %s: dhcp_scopes names its scopes", srv.Name, name)
		}
		detail, err := srv.Client.Scope(ctx, scopes[i].Name)
		if err != nil {
			return nil, dhcpScopeDeleteOut{}, fmt.Errorf("reading the scope: %w", err)
		}
		leases, err := srv.Client.Leases(ctx)
		if err != nil {
			return nil, dhcpScopeDeleteOut{}, fmt.Errorf("reading the leases: %w", err)
		}

		out := dhcpScopeDeleteOut{Server: srv.Name, Scope: scopes[i].Name, Changed: true, Reservations: len(detail.ReservedLeases)}
		for _, l := range leases {
			if strings.EqualFold(l.Scope, scopes[i].Name) {
				out.Leases++
			}
		}
		if scopes[i].Enabled {
			out.Note = "the scope was leasing addresses when it was deleted: the machines it served keep theirs until their leases run out, and then get none from this server"
		}
		done := &changes{dry: in.DryRun}
		if done.did("deleted the scope %s on %s with its %d reservations and %d leases", scopes[i].Name, srv.Name, out.Reservations, out.Leases) {
			if err := srv.Client.DeleteScope(ctx, scopes[i].Name); err != nil {
				return nil, dhcpScopeDeleteOut{}, fmt.Errorf("deleting the scope: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type dhcpLeaseReserveIn struct {
		writeServerArg

		Scope    string `json:"scope,omitempty"    jsonschema:"the scope the lease is in, as dhcp_scopes gives it; it can be left out when the machine holds a lease in only one"`
		Machine  string `json:"machine"            jsonschema:"the machine, by its hardware address as dhcp_leases gives it, its address, or its host name"`
		Reserved *bool  `json:"reserved,omitempty" jsonschema:"true (the default) makes the lease a reservation: the address the machine has now is the one it keeps. false makes a reserved lease an ordinary one again, which runs out like any other, and removes the reservation"`
		DryRun   bool   `json:"dry_run,omitempty"  jsonschema:"change nothing, and answer with what would be"`
	}
	type dhcpLeaseReserveOut struct {
		Server   string   `json:"server"`
		Scope    string   `json:"scope"`
		Changed  bool     `json:"changed"`
		Changes  []string `json:"changes"`
		Machine  string   `json:"machine"             jsonschema:"the machine's hardware address"`
		Address  string   `json:"address"`
		HostName string   `json:"host_name,omitempty"`
		Type     string   `json:"type"                jsonschema:"what the lease is now: Reserved or Dynamic; with a dry run, what it is"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "dhcp_lease_reserve",
		Description: "Turn the lease a machine holds into a reservation, so that the address it has now is the one it always gets; or turn a reserved lease back into an ordinary one. It is the quick way to pin a machine where it already is: dhcp_reservation_set is for choosing the address, or reserving for a machine that holds no lease yet. The machine is found by its hardware address, its address or its host name among the leases.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dhcpLeaseReserveIn) (*mcp.CallToolResult, dhcpLeaseReserveOut, error) {
		want := strings.TrimSpace(in.Machine)
		if want == "" {
			return nil, dhcpLeaseReserveOut{}, errors.New("which machine: give its hardware address, its address or its host name, as dhcp_leases gives them")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, dhcpLeaseReserveOut{}, err
		}
		leases, err := srv.Client.Leases(ctx)
		if err != nil {
			return nil, dhcpLeaseReserveOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		scope, key := strings.TrimSpace(in.Scope), macKey(want)
		var found []technitium.Lease
		for _, l := range leases {
			if scope != "" && !strings.EqualFold(l.Scope, scope) {
				continue
			}
			host, _, _ := strings.Cut(l.HostName, ".")
			if (key != "" && macKey(l.HardwareAddress) == key) || l.Address == want || strings.EqualFold(l.HostName, want) || strings.EqualFold(host, want) {
				found = append(found, l)
			}
		}
		switch len(found) {
		case 0:
			return nil, dhcpLeaseReserveOut{}, fmt.Errorf("%s has given no lease to %s: dhcp_leases lists the leases, and dhcp_reservation_set reserves an address for a machine that holds none", srv.Name, want)
		case 1:
		default:
			return nil, dhcpLeaseReserveOut{}, fmt.Errorf("%d leases on %s match %s: give the scope, or the machine's hardware address", len(found), srv.Name, want)
		}
		lease := found[0]
		reserve := in.Reserved == nil || *in.Reserved

		out := dhcpLeaseReserveOut{Server: srv.Name, Scope: lease.Scope, Changes: []string{}, Machine: lease.HardwareAddress, Address: lease.Address, HostName: lease.HostName, Type: lease.Type}
		done := &changes{dry: in.DryRun}
		switch {
		case reserve && lease.Type == "Reserved", !reserve && lease.Type != "Reserved":
			return nil, out, nil
		case reserve:
			if done.did("made the lease of %s to %s in scope %s a reservation", lease.Address, machine(lease.HardwareAddress, lease.HostName), lease.Scope) {
				if err := srv.Client.ReserveLease(ctx, lease.Scope, lease.HardwareAddress); err != nil {
					return nil, dhcpLeaseReserveOut{}, fmt.Errorf("reserving the lease: %w", err)
				}
				out.Type = "Reserved"
			}
		default:
			if done.did("made the reserved lease of %s to %s in scope %s an ordinary one, removing the reservation", lease.Address, machine(lease.HardwareAddress, lease.HostName), lease.Scope) {
				if err := srv.Client.UnreserveLease(ctx, lease.Scope, lease.HardwareAddress); err != nil {
					return nil, dhcpLeaseReserveOut{}, fmt.Errorf("making the lease ordinary: %w", err)
				}
				out.Type = "Dynamic"
			}
		}
		out.Changed, out.Changes = true, done.said

		return nil, out, nil
	})
}
