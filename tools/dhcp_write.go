package tools

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// dhcpServerArg is the argument every change to a server's DHCP takes to say
// which server it is made on.
type dhcpServerArg struct {
	Server string `json:"server,omitempty" jsonschema:"the configured server whose DHCP to change: a name server_info lists. It can be left out only when one server is configured: DHCP is each server's own, and a change is made on one"`
}

// reservationRow is an address a scope keeps for a machine, as the tools
// that change one give it.
type reservationRow struct {
	Scope           string `json:"scope"`
	HardwareAddress string `json:"hardware_address"`
	Address         string `json:"address"`
	HostName        string `json:"host_name,omitempty"`
	Comment         string `json:"comment,omitempty"`
}

func reservationRowOf(scope string, r *technitium.Reservation) *reservationRow {
	return &reservationRow{Scope: scope, HardwareAddress: r.HardwareAddress, Address: r.Address, HostName: r.HostName, Comment: r.Comments}
}

// machine is a machine as a refusal or a change names one: its hardware
// address, and its name when it has one.
func machine(hardwareAddress, hostName string) string {
	if hostName == "" {
		return hardwareAddress
	}

	return hardwareAddress + " (" + hostName + ")"
}

// dhcpOn reads the DHCP of the one server a change is made on.
func (r *registry) dhcpOn(ctx context.Context, server string) (*servers.Server, *dhcpHeld, error) {
	srv, err := r.servers.One(server)
	if err != nil {
		return nil, nil, err
	}
	held, err := readDHCP(ctx, srv)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", srv.Name, err)
	}

	return srv, &held, nil
}

// scopeNames are a server's scopes as a refusal lists them, each with its
// network.
func (h *dhcpHeld) scopeNames() string {
	names := make([]string, 0, len(h.scopes))
	for i := range h.scopes {
		name := h.scopes[i].listed.Name
		if network, ok := h.scopes[i].network(); ok {
			name += " (" + network.String() + ")"
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return "no scopes"
	}

	return strings.Join(names, ", ")
}

// scopeFor finds the scope a reservation belongs in: the one named; or with
// none named, the one whose network holds the address; or with no address
// either, the one the machine has a reservation in.
func (h *dhcpHeld) scopeFor(server, name, key string, addr netip.Addr, hasAddr bool) (*dhcpScope, error) {
	if strings.TrimSpace(name) != "" {
		if s := h.scope(name); s != nil {
			return s, nil
		}

		return nil, fmt.Errorf("%s has no scope named %s: it has %s", server, name, h.scopeNames())
	}

	var in []string
	var found *dhcpScope
	for i := range h.scopes {
		s := &h.scopes[i]
		network, ok := s.network()
		if (hasAddr && ok && network.Contains(addr)) || (!hasAddr && s.reservation(key) != nil) {
			in, found = append(in, s.listed.Name), s
		}
	}
	switch {
	case len(in) == 1:
		return found, nil
	case len(in) > 1 && hasAddr:
		return nil, fmt.Errorf("%s is in the network of %d scopes on %s (%s): say which with scope", addr, len(in), server, strings.Join(in, ", "))
	case len(in) > 1:
		return nil, fmt.Errorf("%s has a reservation in %d scopes on %s (%s): say which with scope", macText(key), len(in), server, strings.Join(in, ", "))
	case hasAddr:
		return nil, fmt.Errorf("%s is in the network of no scope on %s, which has %s: reserve an address in one of those networks", addr, server, h.scopeNames())
	default:
		return nil, fmt.Errorf("%s has no reservation on %s to change: give the address to keep for it", macText(key), server)
	}
}

// mayReserve refuses an address a scope cannot keep for a machine, which the
// server itself would take without a word: one outside the scope's network,
// one that is the network's own or the server's or the gateway's, one kept
// for another machine, and one another machine holds now.
func (h *dhcpHeld) mayReserve(server string, s *dhcpScope, key string, addr netip.Addr) error {
	scope := s.listed.Name
	if network, ok := s.network(); ok {
		broadcast, _ := ipv4(s.listed.BroadcastAddress)
		switch {
		case !network.Contains(addr):
			return fmt.Errorf("%s is outside %s, the network of scope %s on %s: the server would take the reservation and the machine could not use the address. Nothing was changed", addr, network, scope, server)
		case addr == network.Addr() || addr == broadcast:
			return fmt.Errorf("%s is the network's own address or its broadcast address in %s, which no machine can have. Nothing was changed", addr, network)
		default:
		}
	}
	if own, ok := ipv4(s.listed.InterfaceAddress); ok && own == addr {
		return fmt.Errorf("%s is %s's own address on the network. Nothing was changed", addr, server)
	}
	if router, ok := ipv4(s.details.RouterAddress); ok && router == addr {
		return fmt.Errorf("%s is the gateway scope %s gives every machine. Nothing was changed", addr, scope)
	}

	for i := range h.scopes {
		for _, other := range h.scopes[i].details.ReservedLeases {
			if kept, ok := ipv4(other.Address); ok && kept == addr && macKey(other.HardwareAddress) != key {
				return fmt.Errorf("%s is kept for %s in scope %s already, and two machines cannot be given one address: remove that reservation with dhcp_reservation_delete, or choose another address. Nothing was changed", addr, machine(other.HardwareAddress, other.HostName), h.scopes[i].listed.Name)
			}
		}
	}
	for i := range h.leases {
		l := &h.leases[i]
		if leased, ok := ipv4(l.Address); ok && leased == addr && macKey(l.HardwareAddress) != key {
			return fmt.Errorf("%s is held by %s until %s: choose another address, or once that machine is off it have the server forget the lease with dhcp_lease_delete. Nothing was changed", addr, machine(l.HardwareAddress, l.HostName), utc(l.LeaseExpires))
		}
	}

	return nil
}

// dhcpRecords are the records a server holds at a host name and at the name
// of an address's PTR: what the server keeps in its zones for a lease or a
// reservation, when the scope has it do so. A name the server holds no zone
// for has none.
func dhcpRecords(ctx context.Context, srv *servers.Server, host string, addr netip.Addr) ([]technitium.Record, error) {
	zones, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
	if err != nil {
		return nil, err
	}

	var out []technitium.Record
	for _, at := range []struct{ name, recordType string }{{host, "A"}, {reverseName(addr), "PTR"}} {
		var closest string
		for i := range zones {
			zone := cleanName(zones[i].Name)
			if served(&zones[i]) && (at.name == zone || strings.HasSuffix(at.name, "."+zone)) && len(zone) > len(closest) {
				closest = zone
			}
		}
		if at.name == "" || closest == "" {
			continue
		}
		read, err := srv.Client.RecordsAt(ctx, at.name, closest)
		if err != nil {
			return nil, err
		}
		for i := range read.Records {
			if read.Records[i].Type == at.recordType {
				out = append(out, read.Records[i])
			}
		}
	}

	return out, nil
}

// among reports whether a record is one of a list: the same name, type and
// value.
func among(records []technitium.Record, want *technitium.Record) bool {
	for i := range records {
		if rec := &records[i]; rec.Type == want.Type && sameName(rec.Name, want.Name) && rec.Value() == want.Value() {
			return true
		}
	}

	return false
}

// rowsOfRecords are records as a tool gives them.
func rowsOfRecords(records []technitium.Record) []recordRow {
	rows := make([]recordRow, 0, len(records))
	for i := range records {
		rows = append(rows, rowOf(&records[i]))
	}

	return rows
}

// leaseOf is the lease a machine holds in a scope, nil when it holds none.
func (h *dhcpHeld) leaseOf(scope, key string) *technitium.Lease {
	for i := range h.leases {
		if strings.EqualFold(h.leases[i].Scope, scope) && macKey(h.leases[i].HardwareAddress) == key {
			return &h.leases[i]
		}
	}

	return nil
}

func registerDHCPWriteTools(r *registry) {
	type dhcpReservationSetIn struct {
		dhcpServerArg

		HardwareAddress string  `json:"hardware_address"    jsonschema:"the machine's hardware (MAC) address, however written: 00:11:22:aa:bb:cc, 00-11-22-AA-BB-CC or 001122aabbcc"`
		Address         string  `json:"address,omitempty"   jsonschema:"the address to keep for it. It can be left out only to change the name or comment of a reservation that is there"`
		Scope           string  `json:"scope,omitempty"     jsonschema:"the scope to reserve in; left out, the one whose network holds the address"`
		HostName        *string `json:"host_name,omitempty" jsonschema:"the machine's host name, which a scope with dns_updates on records under its domain with the address; left out, a reservation that is there keeps its own; an empty one clears it"`
		Comment         *string `json:"comment,omitempty"   jsonschema:"a comment on the reservation; left out, a reservation that is there keeps its own; an empty one clears it"`
		DryRun          bool    `json:"dry_run,omitempty"   jsonschema:"change nothing, and answer with what would be done"`
	}
	type dhcpReservationSetOut struct {
		Server  string          `json:"server"`
		Scope   string          `json:"scope"`
		Changed bool            `json:"changed"           jsonschema:"something was changed; with a dry run, something would be"`
		Changes []string        `json:"changes"           jsonschema:"each change made, in order; with a dry run, each that would be. Empty when the reservation was already as asked"`
		Before  *reservationRow `json:"before,omitempty"  jsonschema:"the machine's reservation in the scope before; absent when it had none"`
		After   *reservationRow `json:"after,omitempty"   jsonschema:"its reservation now, read back from the server; absent from a dry run"`
		Records []recordRow     `json:"records,omitempty" jsonschema:"the records the server holds at the reservation's name and for its address's PTR, read back; with a dry run, the ones there now"`
		Note    string          `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "dhcp_reservation_set",
		Description: "Have a scope keep an address for one machine, on one server: pin this host. The reservation is added when the machine has none in the scope, replaced when its address, name or comment differ, and left alone when it is already so. The server itself takes nearly any reservation, so the ones that could not work are refused here: an address outside the scope's network, the server's own or the gateway's, one kept for another machine, and one another machine holds a lease on (dhcp_leases says who has what). In a scope with dns_updates on the server records the host name with the address and its PTR itself, writing over a record already at that name, which the answer says before it is done with dry_run. The answer is the reservation before and after, read back, and the records the server holds for it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dhcpReservationSetIn) (*mcp.CallToolResult, dhcpReservationSetOut, error) {
		key := macKey(in.HardwareAddress)
		if key == "" {
			return nil, dhcpReservationSetOut{}, fmt.Errorf("%q is no hardware address: give the machine's six bytes as 00:11:22:aa:bb:cc, 00-11-22-AA-BB-CC or 001122aabbcc", in.HardwareAddress)
		}
		addr, hasAddr := ipv4(in.Address)
		if strings.TrimSpace(in.Address) != "" && !hasAddr {
			return nil, dhcpReservationSetOut{}, fmt.Errorf("%q is not an IPv4 address, which is what a scope keeps for a machine", in.Address)
		}
		if in.HostName != nil && strings.ContainsAny(strings.TrimSpace(*in.HostName), " \t\r\n") {
			return nil, dhcpReservationSetOut{}, fmt.Errorf("%q is no host name: it has a space in it", *in.HostName)
		}
		srv, held, err := r.dhcpOn(ctx, in.Server)
		if err != nil {
			return nil, dhcpReservationSetOut{}, err
		}
		s, err := held.scopeFor(srv.Name, in.Scope, key, addr, hasAddr)
		if err != nil {
			return nil, dhcpReservationSetOut{}, err
		}
		scope, mac := s.listed.Name, macText(key)

		// what is asked for, over what is there
		existing := s.reservation(key)
		want := technitium.Reservation{HardwareAddress: mac}
		if existing != nil {
			want = *existing
		}
		if hasAddr {
			want.Address = addr.String()
		}
		if in.HostName != nil {
			want.HostName = strings.TrimSpace(*in.HostName)
		}
		if in.Comment != nil {
			want.Comments = *in.Comment
		}
		if addr, hasAddr = ipv4(want.Address); !hasAddr {
			return nil, dhcpReservationSetOut{}, fmt.Errorf("%s has no reservation in scope %s on %s to change: give the address to keep for it", mac, scope, srv.Name)
		}
		if err := held.mayReserve(srv.Name, s, key, addr); err != nil {
			return nil, dhcpReservationSetOut{}, err
		}

		out := dhcpReservationSetOut{Server: srv.Name, Scope: scope, Changes: []string{}}
		if existing != nil {
			out.Before = reservationRowOf(scope, existing)
		}
		if !s.listed.Enabled {
			out.Note = note(out.Note, "scope "+scope+" is switched off: it leases nothing, this address included, until it is enabled")
		}
		if l := held.leaseOf(scope, key); l != nil && l.Address != want.Address {
			out.Note = note(out.Note, fmt.Sprintf("the machine holds %s now, until %s: the reservation is what it is given when it next asks for a lease", l.Address, utc(l.LeaseExpires)))
		}

		// the name the server records for it, in a scope that has it do so
		var host string
		if s.details.DNSUpdates && s.details.DomainName != "" && want.HostName != "" {
			host = hostIn(want.HostName, s.details.DomainName)
		}
		if want.HostName != "" && host == "" {
			out.Note = note(out.Note, "scope "+scope+" does not record names in DNS (its dns_updates is off, or it has no domain): the name is the reservation's alone")
		}
		before, err := dhcpRecords(ctx, srv, host, addr)
		if err != nil {
			return nil, dhcpReservationSetOut{}, err
		}
		out.Records = rowsOfRecords(before)

		if existing != nil && *existing == want {
			out.After = out.Before

			return nil, out, nil
		}

		done := &changes{dry: in.DryRun}
		out.Changed = true
		if existing != nil && done.did("removed the reservation of %s for %s in scope %s, to set it again as asked: the server changes none in place", existing.Address, machine(mac, existing.HostName), scope) {
			if err := srv.Client.RemoveReservation(ctx, scope, mac); err != nil {
				return nil, dhcpReservationSetOut{}, fmt.Errorf("removing the reservation there to set it again: %w. Nothing was changed", err)
			}
		}
		if done.did("reserved %s for %s in scope %s", want.Address, machine(mac, want.HostName), scope) {
			if err := srv.Client.AddReservation(ctx, scope, want); err != nil {
				if existing == nil {
					return nil, dhcpReservationSetOut{}, fmt.Errorf("reserving %s for %s: %w. Nothing was changed", want.Address, mac, err)
				}
				// the old one is gone by now: put it back rather than leave the machine with none
				if backErr := srv.Client.AddReservation(ctx, scope, *existing); backErr != nil {
					return nil, dhcpReservationSetOut{}, fmt.Errorf("reserving %s for %s: %w; and the reservation of %s it had, removed to make way, could not be put back: %w. The machine has no reservation now", want.Address, mac, err, existing.Address, backErr)
				}

				return nil, dhcpReservationSetOut{}, fmt.Errorf("reserving %s for %s: %w. The reservation of %s it had was put back as it was", want.Address, mac, err, existing.Address)
			}
		}
		if host != "" {
			for i := range before {
				if rec := &before[i]; rec.Type == "A" && rec.Value() != want.Address {
					done.did("had the server write over %s, as it does for a reservation's name", recordAt(rec))
				}
			}
			done.did("had the server record %s at %s with its PTR, as a scope with dns_updates on does itself", want.Address, host)
		}
		out.Changes = done.said
		if in.DryRun {
			return nil, out, nil
		}

		after, err := srv.Client.Scope(ctx, scope)
		if err != nil {
			return nil, dhcpReservationSetOut{}, fmt.Errorf("the change was made, and the scope could not be read back: %w", err)
		}
		got := (&dhcpScope{details: after}).reservation(key)
		if got == nil || got.Address != want.Address || got.HostName != want.HostName || got.Comments != want.Comments {
			return nil, dhcpReservationSetOut{}, fmt.Errorf("the server took the change and scope %s does not hold the reservation as asked: it holds %+v for %s", scope, got, mac)
		}
		out.After = reservationRowOf(scope, got)
		records, err := dhcpRecords(ctx, srv, host, addr)
		if err != nil {
			return nil, dhcpReservationSetOut{}, fmt.Errorf("the change was made, and the records for it could not be read back: %w", err)
		}
		out.Records = rowsOfRecords(records)

		return nil, out, nil
	})

	type dhcpReservationDeleteIn struct {
		dhcpServerArg

		HardwareAddress string `json:"hardware_address,omitempty" jsonschema:"the machine whose reservation to remove, by its hardware (MAC) address, however written"`
		Address         string `json:"address,omitempty"          jsonschema:"or the address reserved. One of the two is needed; both say exactly which when an address is reserved twice"`
		Scope           string `json:"scope,omitempty"            jsonschema:"the scope the reservation is in; left out, every scope on the server is looked in"`
		DryRun          bool   `json:"dry_run,omitempty"          jsonschema:"remove nothing, and answer with what would be removed"`
	}
	type dhcpReservationDeleteOut struct {
		Server  string         `json:"server"`
		Scope   string         `json:"scope"`
		Removed reservationRow `json:"removed"           jsonschema:"the reservation removed, as it was: what dhcp_reservation_set needs to put it back. With a dry run, the one that would be"`
		Changes []string       `json:"changes"           jsonschema:"each change made, in order; with a dry run, each that would be"`
		Records []recordRow    `json:"records,omitempty" jsonschema:"the records still at the reservation's name and for its address's PTR, read back; with a dry run, the ones there now"`
		Note    string         `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "dhcp_reservation_delete",
		Description: "Have a scope stop keeping an address for a machine, on one server: the reservation named by the machine's hardware address or by the address. The answer gives the reservation as it was, which is what dhcp_reservation_set needs to put it back. In a scope with dns_updates on the server takes the reservation's name and PTR out of its zones with it, at once, though the machine may hold the address for the rest of its lease, which the answer says. dry_run removes nothing and says what would go.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dhcpReservationDeleteIn) (*mcp.CallToolResult, dhcpReservationDeleteOut, error) {
		key, addr, hasAddr, err := whichMachine(in.HardwareAddress, in.Address)
		if err != nil {
			return nil, dhcpReservationDeleteOut{}, err
		}
		srv, held, err := r.dhcpOn(ctx, in.Server)
		if err != nil {
			return nil, dhcpReservationDeleteOut{}, err
		}
		if strings.TrimSpace(in.Scope) != "" && held.scope(in.Scope) == nil {
			return nil, dhcpReservationDeleteOut{}, fmt.Errorf("%s has no scope named %s: it has %s", srv.Name, in.Scope, held.scopeNames())
		}

		var s *dhcpScope
		var going *technitium.Reservation
		var matched []string
		for i := range held.scopes {
			if strings.TrimSpace(in.Scope) != "" && held.scope(in.Scope) != &held.scopes[i] {
				continue
			}
			for j := range held.scopes[i].details.ReservedLeases {
				res := &held.scopes[i].details.ReservedLeases[j]
				kept, _ := ipv4(res.Address)
				if (key != "" && macKey(res.HardwareAddress) != key) || (hasAddr && kept != addr) {
					continue
				}
				s, going = &held.scopes[i], res
				matched = append(matched, fmt.Sprintf("%s for %s in scope %s", res.Address, machine(res.HardwareAddress, res.HostName), held.scopes[i].listed.Name))
			}
		}
		// the server lists a scope's reservations in no order of its own
		slices.Sort(matched)
		switch len(matched) {
		case 0:
			return nil, dhcpReservationDeleteOut{}, fmt.Errorf("%s keeps no such reservation: dhcp_leases with type reserved lists the ones it has. Nothing was removed", srv.Name)
		case 1:
		default:
			return nil, dhcpReservationDeleteOut{}, fmt.Errorf("%d reservations on %s match (%s): say which with hardware_address and scope. Nothing was removed", len(matched), srv.Name, strings.Join(matched, "; "))
		}
		scope := s.listed.Name
		kept, _ := ipv4(going.Address)
		host := hostIn(going.HostName, s.details.DomainName)

		out := dhcpReservationDeleteOut{Server: srv.Name, Scope: scope, Removed: *reservationRowOf(scope, going)}
		before, err := dhcpRecords(ctx, srv, host, kept)
		if err != nil {
			return nil, dhcpReservationDeleteOut{}, err
		}
		out.Records = rowsOfRecords(before)
		if l := held.leaseOf(scope, macKey(going.HardwareAddress)); l != nil {
			out.Note = note(out.Note, fmt.Sprintf("the machine holds %s until %s and keeps it till then: the server goes on listing that lease as Reserved, and dhcp_lease_delete has it forget the lease", l.Address, utc(l.LeaseExpires)))
		}

		done := &changes{dry: in.DryRun}
		if done.did("removed the reservation of %s for %s in scope %s", going.Address, machine(going.HardwareAddress, going.HostName), scope) {
			if err := srv.Client.RemoveReservation(ctx, scope, going.HardwareAddress); err != nil {
				return nil, dhcpReservationDeleteOut{}, fmt.Errorf("removing the reservation: %w. Nothing was removed", err)
			}
		}
		if in.DryRun {
			for i := range before {
				if by, written := byDHCP(before[i].Comments); written && strings.EqualFold(by, scope) {
					done.did("removed %s, which the server takes away with the reservation", recordAt(&before[i]))
				}
			}
			out.Changes = done.said

			return nil, out, nil
		}

		after, err := srv.Client.Scope(ctx, scope)
		if err != nil {
			return nil, dhcpReservationDeleteOut{}, fmt.Errorf("the reservation was removed, and the scope could not be read back: %w", err)
		}
		if (&dhcpScope{details: after}).reservation(macKey(going.HardwareAddress)) != nil {
			return nil, dhcpReservationDeleteOut{}, fmt.Errorf("the server took the removal and scope %s still keeps %s for %s", scope, going.Address, going.HardwareAddress)
		}
		left, err := dhcpRecords(ctx, srv, host, kept)
		if err != nil {
			return nil, dhcpReservationDeleteOut{}, fmt.Errorf("the reservation was removed, and the records for it could not be read back: %w", err)
		}
		for i := range before {
			if !among(left, &before[i]) {
				done.did("removed %s, which the server took away with the reservation", recordAt(&before[i]))
			}
		}
		out.Changes, out.Records = done.said, rowsOfRecords(left)

		return nil, out, nil
	})

	type dhcpLeaseDeleteIn struct {
		dhcpServerArg

		HardwareAddress string `json:"hardware_address,omitempty" jsonschema:"the machine whose lease to forget, by its hardware (MAC) address, however written"`
		Address         string `json:"address,omitempty"          jsonschema:"or the address leased. One of the two is needed"`
		Scope           string `json:"scope,omitempty"            jsonschema:"the scope the lease is in; left out, every scope on the server is looked in"`
		DryRun          bool   `json:"dry_run,omitempty"          jsonschema:"forget nothing, and answer with what would be"`
	}
	type dhcpLeaseDeleteOut struct {
		Server      string          `json:"server"`
		Scope       string          `json:"scope"`
		Removed     leaseRow        `json:"removed"               jsonschema:"the lease the server was made to forget, as it was; with a dry run, the one it would be"`
		Changes     []string        `json:"changes"               jsonschema:"each change made, in order; with a dry run, each that would be"`
		Reservation *reservationRow `json:"reservation,omitempty" jsonschema:"the reservation the machine has in the scope, which is kept: read back"`
		Records     []recordRow     `json:"records,omitempty"     jsonschema:"the records still at the lease's name and for its address's PTR, read back; with a dry run, the ones there now"`
		Note        string          `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "dhcp_lease_delete",
		Description: "Have a server forget a lease it gave, named by the machine's hardware address or by the address: for a machine that is gone and whose address is wanted, or a lease that is in the way of a reservation. The address is free to give again at once, and in a scope with dns_updates on the lease's name and PTR leave the server's zones. Nothing is said to the machine: one still running keeps using the address until its lease would have ended, so forget only what is off the network. The server drops a reservation along with its lease; this puts the reservation back, so only the lease goes, and dhcp_reservation_delete is what removes one. dry_run forgets nothing and says what would go.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dhcpLeaseDeleteIn) (*mcp.CallToolResult, dhcpLeaseDeleteOut, error) {
		key, addr, hasAddr, err := whichMachine(in.HardwareAddress, in.Address)
		if err != nil {
			return nil, dhcpLeaseDeleteOut{}, err
		}
		srv, held, err := r.dhcpOn(ctx, in.Server)
		if err != nil {
			return nil, dhcpLeaseDeleteOut{}, err
		}
		if strings.TrimSpace(in.Scope) != "" && held.scope(in.Scope) == nil {
			return nil, dhcpLeaseDeleteOut{}, fmt.Errorf("%s has no scope named %s: it has %s", srv.Name, in.Scope, held.scopeNames())
		}

		var going *technitium.Lease
		var matched []string
		for i := range held.leases {
			l := &held.leases[i]
			leased, _ := ipv4(l.Address)
			if (strings.TrimSpace(in.Scope) != "" && !strings.EqualFold(l.Scope, strings.TrimSpace(in.Scope))) || (key != "" && macKey(l.HardwareAddress) != key) || (hasAddr && leased != addr) {
				continue
			}
			going = l
			matched = append(matched, fmt.Sprintf("%s to %s in scope %s", l.Address, machine(l.HardwareAddress, l.HostName), l.Scope))
		}
		switch len(matched) {
		case 0:
			return nil, dhcpLeaseDeleteOut{}, fmt.Errorf("%s holds no such lease: dhcp_leases lists the ones it has. Nothing was changed", srv.Name)
		case 1:
		default:
			return nil, dhcpLeaseDeleteOut{}, fmt.Errorf("%d leases on %s match (%s): say which with hardware_address and scope. Nothing was changed", len(matched), srv.Name, strings.Join(matched, "; "))
		}
		scope, mac := going.Scope, macKey(going.HardwareAddress)
		leased, _ := ipv4(going.Address)

		out := dhcpLeaseDeleteOut{Server: srv.Name, Scope: scope, Removed: leaseRow{Server: srv.Name, Scope: scope, Type: going.Type, Address: going.Address, HardwareAddress: going.HardwareAddress, HostName: going.HostName, Obtained: utc(going.LeaseObtained), Expires: utc(going.LeaseExpires)}}
		var reservation *technitium.Reservation
		if s := held.scope(scope); s != nil {
			reservation = s.reservation(mac)
		}
		before, err := dhcpRecords(ctx, srv, cleanName(going.HostName), leased)
		if err != nil {
			return nil, dhcpLeaseDeleteOut{}, err
		}
		out.Records = rowsOfRecords(before)

		done := &changes{dry: in.DryRun}
		if done.did("had %s forget the lease of %s to %s in scope %s", srv.Name, going.Address, machine(going.HardwareAddress, going.HostName), scope) {
			if err := srv.Client.RemoveLease(ctx, scope, going.HardwareAddress); err != nil {
				return nil, dhcpLeaseDeleteOut{}, fmt.Errorf("forgetting the lease: %w. Nothing was changed", err)
			}
		}
		if in.DryRun {
			if reservation != nil {
				out.Reservation = reservationRowOf(scope, reservation)
				done.did("put back the reservation of %s for the machine, should the server drop it with the lease as it does a reserved one's", reservation.Address)
			} else {
				for i := range before {
					if by, written := byDHCP(before[i].Comments); written && strings.EqualFold(by, scope) {
						done.did("removed %s, which the server takes away with the lease", recordAt(&before[i]))
					}
				}
			}
			out.Changes = done.said

			return nil, out, nil
		}

		now, err := readDHCP(ctx, srv)
		if err != nil {
			return nil, dhcpLeaseDeleteOut{}, fmt.Errorf("the lease was forgotten, and the server's DHCP could not be read back: %w", err)
		}
		if l := now.leaseOf(scope, mac); l != nil {
			return nil, dhcpLeaseDeleteOut{}, fmt.Errorf("the server took the removal and still lists %s as leased to %s in scope %s", l.Address, l.HardwareAddress, scope)
		}
		if s := now.scope(scope); reservation != nil && s != nil {
			if s.reservation(mac) == nil {
				done.did("put back the reservation of %s for the machine, which the server dropped with its lease", reservation.Address)
				if err := srv.Client.AddReservation(ctx, scope, *reservation); err != nil {
					return nil, dhcpLeaseDeleteOut{}, fmt.Errorf("the lease was forgotten and the server dropped the machine's reservation with it, which could not be put back: %w. It was %+v", err, *reservation)
				}
			}
			out.Reservation = reservationRowOf(scope, reservation)
		}
		left, err := dhcpRecords(ctx, srv, cleanName(going.HostName), leased)
		if err != nil {
			return nil, dhcpLeaseDeleteOut{}, fmt.Errorf("the lease was forgotten, and the records for it could not be read back: %w", err)
		}
		for i := range before {
			if !among(left, &before[i]) {
				done.did("removed %s, which the server took away with the lease", recordAt(&before[i]))
			}
		}
		out.Changes, out.Records = done.said, rowsOfRecords(left)

		return nil, out, nil
	})
}

// whichMachine reads how a reservation or a lease is named: by the machine's
// hardware address, by the address, or by both.
func whichMachine(hardwareAddress, address string) (key string, addr netip.Addr, hasAddr bool, err error) {
	key = macKey(hardwareAddress)
	if strings.TrimSpace(hardwareAddress) != "" && key == "" {
		return "", netip.Addr{}, false, fmt.Errorf("%q is no hardware address: give the machine's six bytes as 00:11:22:aa:bb:cc, 00-11-22-AA-BB-CC or 001122aabbcc", hardwareAddress)
	}
	addr, hasAddr = ipv4(address)
	if strings.TrimSpace(address) != "" && !hasAddr {
		return "", netip.Addr{}, false, fmt.Errorf("%q is not an IPv4 address", address)
	}
	if key == "" && !hasAddr {
		return "", netip.Addr{}, false, errors.New("which one: give the machine's hardware_address, or the address")
	}

	return key, addr, hasAddr, nil
}
