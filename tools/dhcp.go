package tools

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// leaseDynamic and leaseReserved are the two kinds of lease, as the
	// server names them
	leaseDynamic  = "Dynamic"
	leaseReserved = "Reserved"
)

// dhcpScope is a scope as a server holds it: how it is listed, and whole.
type dhcpScope struct {
	listed  technitium.Scope
	details *technitium.ScopeDetails
}

// dhcpHeld is one server's DHCP: its scopes and the leases machines hold.
type dhcpHeld struct {
	scopes []dhcpScope
	leases []technitium.Lease
}

// readDHCP reads a server's DHCP whole: every scope with its reservations,
// and every lease.
func readDHCP(ctx context.Context, srv *servers.Server) (dhcpHeld, error) {
	listed, err := srv.Client.Scopes(ctx)
	if err != nil {
		return dhcpHeld{}, err
	}

	out := dhcpHeld{scopes: make([]dhcpScope, 0, len(listed))}
	for i := range listed {
		details, scopeErr := srv.Client.Scope(ctx, listed[i].Name)
		if scopeErr != nil {
			return dhcpHeld{}, scopeErr
		}
		out.scopes = append(out.scopes, dhcpScope{listed: listed[i], details: details})
	}
	if out.leases, err = srv.Client.Leases(ctx); err != nil {
		return dhcpHeld{}, err
	}

	return out, nil
}

// scope is the scope of a name among a server's, nil when it has none.
func (h *dhcpHeld) scope(name string) *dhcpScope {
	for i := range h.scopes {
		if strings.EqualFold(h.scopes[i].listed.Name, strings.TrimSpace(name)) {
			return &h.scopes[i]
		}
	}

	return nil
}

// macKey is a hardware address as two are compared, however each was
// written - 00:11:22:AA:BB:CC, 00-11-22-aa-bb-cc, 0011.22aa.bbcc or
// 001122aabbcc: its twelve hex digits in lower case. "" is text that is no
// hardware address.
func macKey(text string) string {
	key := macDigits(text)
	if len(key) != 12 {
		return ""
	}

	return key
}

// macDigits are the hex digits of text that is written as a hardware
// address or a part of one, "" for text that is anything else.
func macDigits(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(text)) {
		switch {
		case r == ':' || r == '-' || r == '.':
		case (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'):
			b.WriteRune(r)
		default:
			return ""
		}
	}

	return b.String()
}

// macText is a hardware address as the server writes one: 00-11-22-AA-BB-CC.
func macText(key string) string {
	parts := make([]string, 0, 6)
	for i := 0; i+2 <= len(key); i += 2 {
		parts = append(parts, strings.ToUpper(key[i:i+2]))
	}

	return strings.Join(parts, "-")
}

// number is an IPv4 address as a number, which a range is counted in.
func number(addr netip.Addr) uint32 {
	b := addr.As4()

	return binary.BigEndian.Uint32(b[:])
}

// ipv4 reads an IPv4 address.
func ipv4(text string) (netip.Addr, bool) {
	addr, ok := parseAddr(text)

	return addr, ok && addr.Is4()
}

// network is the network a scope is for, from its address and mask.
func (s *dhcpScope) network() (netip.Prefix, bool) {
	addr, ok := ipv4(s.listed.NetworkAddress)
	mask, maskOK := ipv4(s.listed.SubnetMask)
	if !ok || !maskOK {
		return netip.Prefix{}, false
	}
	ones := bits.LeadingZeros32(^number(mask))
	if number(mask) != ^uint32(0)<<(32-ones) {
		return netip.Prefix{}, false
	}

	return netip.PrefixFrom(addr, ones), true
}

// span is one run of addresses, its first and its last.
type span struct{ first, last uint32 }

// span is the range a scope leases from.
func (s *dhcpScope) span() (span, bool) {
	first, ok := ipv4(s.listed.StartingAddress)
	last, lastOK := ipv4(s.listed.EndingAddress)
	if !ok || !lastOK || number(last) < number(first) {
		return span{}, false
	}

	return span{first: number(first), last: number(last)}, true
}

// excluded are the runs of a scope's range it never leases from, cut to the
// range, in order and with none overlapping.
func (s *dhcpScope) excluded() []span {
	whole, ok := s.span()
	if !ok || s.details == nil {
		return nil
	}

	var out []span
	for _, e := range s.details.Exclusions {
		first, firstOK := ipv4(e.StartingAddress)
		last, lastOK := ipv4(e.EndingAddress)
		if !firstOK || !lastOK {
			continue
		}
		cut := span{first: max(number(first), whole.first), last: min(number(last), whole.last)}
		if cut.first <= cut.last {
			out = append(out, cut)
		}
	}
	slices.SortFunc(out, func(a, b span) int { return cmp.Compare(a.first, b.first) })

	merged := out[:0]
	for _, e := range out {
		if n := len(merged); n > 0 && e.first <= merged[n-1].last+1 {
			merged[n-1].last = max(merged[n-1].last, e.last)

			continue
		}
		merged = append(merged, e)
	}

	return merged
}

// leases reports whether an address is one the scope gives out by itself:
// in its range, and in no exclusion.
func (s *dhcpScope) leases(addr netip.Addr) bool {
	whole, ok := s.span()
	if !ok || !addr.Is4() || number(addr) < whole.first || number(addr) > whole.last {
		return false
	}

	return !slices.ContainsFunc(s.excluded(), func(e span) bool { return number(addr) >= e.first && number(addr) <= e.last })
}

// size is how many addresses the scope gives out by itself.
func (s *dhcpScope) size() int {
	whole, ok := s.span()
	if !ok {
		return 0
	}
	n := int(whole.last-whole.first) + 1
	for _, e := range s.excluded() {
		n -= int(e.last-e.first) + 1
	}

	return n
}

// reservation is the address a scope keeps for a machine, nil when it keeps
// none.
func (s *dhcpScope) reservation(key string) *technitium.Reservation {
	if s.details == nil {
		return nil
	}
	for i := range s.details.ReservedLeases {
		if macKey(s.details.ReservedLeases[i].HardwareAddress) == key {
			return &s.details.ReservedLeases[i]
		}
	}

	return nil
}

// hostIn is a host name as the server records one for a scope: under the
// scope's domain, unless it is written under it already.
func hostIn(host, domain string) string {
	host, domain = cleanName(host), cleanName(domain)
	if host == "" || domain == "" || host == domain || strings.HasSuffix(host, "."+domain) {
		return host
	}

	return host + "." + domain
}

// byDHCP reports whether a record's comment is the one the server gives the
// records it writes for a scope's leases, and which scope it names.
func byDHCP(comment string) (string, bool) {
	scope, found := strings.CutPrefix(comment, "Via '")
	if !found {
		return "", false
	}
	scope, found = strings.CutSuffix(scope, "' DHCP scope")

	return scope, found
}

// lasts is how long a scope's leases run, as 1d, 12h or 1d 6h 30m.
func lasts(d *technitium.ScopeDetails) string {
	var parts []string
	for _, part := range []struct {
		n    int
		unit string
	}{{d.LeaseTimeDays, "d"}, {d.LeaseTimeHours, "h"}, {d.LeaseTimeMinutes, "m"}} {
		if part.n > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", part.n, part.unit))
		}
	}

	return strings.Join(parts, " ")
}

// scopeRow is one scope of one server, as dhcp_scopes answers.
type scopeRow struct {
	Server       string   `json:"server"`
	Scope        string   `json:"scope"`
	Enabled      bool     `json:"enabled"                 jsonschema:"the scope is switched on: only an enabled scope leases"`
	Network      string   `json:"network,omitempty"       jsonschema:"the network the scope is for, as its address and the bits of its mask"`
	Range        string   `json:"range"                   jsonschema:"the first and the last address it leases from"`
	Exclusions   []string `json:"exclusions,omitempty"    jsonschema:"the runs of the range it never leases from, each as its first and last address"`
	Interface    string   `json:"interface,omitempty"     jsonschema:"the server's own address on the network, where it hears machines asking; 0.0.0.0 when it has none there and can only be reached through a relay; absent while the scope is off"`
	LeaseTime    string   `json:"lease_time,omitempty"    jsonschema:"how long a lease runs, as 1d, 12h or 1d 6h"`
	Domain       string   `json:"domain,omitempty"        jsonschema:"the domain machines are told they are in, and the one their names are recorded under when dns_updates is on"`
	DNSUpdates   bool     `json:"dns_updates,omitempty"   jsonschema:"the server records each lease's and each reservation's host name under domain itself, with its PTR, and removes them when the lease ends: records in zone_records with the comment Via '<scope>' DHCP scope are its own"`
	Router       string   `json:"router,omitempty"        jsonschema:"the gateway machines are given"`
	DNSServers   []string `json:"dns_servers,omitempty"   jsonschema:"the name servers machines are told to use, in order; this server is the server's own address on the network"`
	OnlyReserved bool     `json:"only_reserved,omitempty" jsonschema:"the scope leases to no machine it has no reservation for"`
	Addresses    int      `json:"addresses"               jsonschema:"how many addresses the range holds, less its exclusions"`
	Free         int      `json:"free"                    jsonschema:"how many of those no machine holds and none is reserved: at 0 a new machine gets nothing"`
	Leased       int      `json:"leased"                  jsonschema:"how many leases machines hold now, of both kinds"`
	Reserved     int      `json:"reserved"                jsonschema:"how many addresses are kept for particular machines"`
}

// scopeRowOf is a scope as dhcp_scopes gives one.
func scopeRowOf(server string, held *dhcpHeld, s *dhcpScope) scopeRow {
	d := s.details
	row := scopeRow{Server: server, Scope: s.listed.Name, Enabled: s.listed.Enabled, Range: s.listed.StartingAddress + "-" + s.listed.EndingAddress, Interface: s.listed.InterfaceAddress, LeaseTime: lasts(d), Domain: d.DomainName, DNSUpdates: d.DNSUpdates, Router: d.RouterAddress, OnlyReserved: d.AllowOnlyReservedLeases, Addresses: s.size(), Reserved: len(d.ReservedLeases)}
	if network, ok := s.network(); ok {
		row.Network = network.String()
	}
	for _, e := range d.Exclusions {
		row.Exclusions = append(row.Exclusions, e.StartingAddress+"-"+e.EndingAddress)
	}
	if d.UseThisDNSServer {
		row.DNSServers = append(row.DNSServers, "this server")
	}
	row.DNSServers = append(row.DNSServers, d.DNSServers...)

	// an address is taken when a machine holds it or it is kept for one
	taken := map[netip.Addr]bool{}
	for i := range held.leases {
		if !strings.EqualFold(held.leases[i].Scope, s.listed.Name) {
			continue
		}
		row.Leased++
		if addr, ok := ipv4(held.leases[i].Address); ok && s.leases(addr) {
			taken[addr] = true
		}
	}
	for i := range d.ReservedLeases {
		if addr, ok := ipv4(d.ReservedLeases[i].Address); ok && s.leases(addr) {
			taken[addr] = true
		}
	}
	row.Free = row.Addresses - len(taken)

	return row
}

// leaseRow is one lease, or one reservation no machine holds, as dhcp_leases
// answers.
type leaseRow struct {
	Server          string `json:"server"`
	Scope           string `json:"scope"`
	Type            string `json:"type"                jsonschema:"Dynamic: an address from the scope's range, the machine's until the lease expires. Reserved: the address the scope keeps for the machine"`
	Address         string `json:"address"`
	HardwareAddress string `json:"hardware_address"    jsonschema:"the machine's hardware (MAC) address, as the server writes one"`
	HostName        string `json:"host_name,omitempty" jsonschema:"the name the machine gave, or the one reserved for it, under the scope's domain; absent when it gave none"`
	Obtained        string `json:"obtained,omitempty"  jsonschema:"when the machine last took or renewed the lease, in UTC"`
	Expires         string `json:"expires,omitempty"   jsonschema:"when the lease ends unless the machine renews it, in UTC"`
	Unclaimed       bool   `json:"unclaimed,omitempty" jsonschema:"a reservation no machine holds a lease on now: the address is kept, and the machine has not asked for it"`
	Comment         string `json:"comment,omitempty"   jsonschema:"the reservation's comment"`
}

// leaseRowsOf are a server's leases and the reservations no machine holds,
// scope by scope in the order of their addresses.
func leaseRowsOf(server string, held *dhcpHeld) []leaseRow {
	rows := make([]leaseRow, 0, len(held.leases))
	claimed := map[string]bool{}
	for i := range held.leases {
		l := &held.leases[i]
		row := leaseRow{Server: server, Scope: l.Scope, Type: l.Type, Address: l.Address, HardwareAddress: l.HardwareAddress, HostName: l.HostName, Obtained: utc(l.LeaseObtained), Expires: utc(l.LeaseExpires)}
		if s := held.scope(l.Scope); s != nil {
			if r := s.reservation(macKey(l.HardwareAddress)); r != nil {
				row.Comment = r.Comments
				claimed[strings.ToLower(l.Scope)+"\x00"+macKey(l.HardwareAddress)] = true
			}
		}
		rows = append(rows, row)
	}
	for i := range held.scopes {
		s := &held.scopes[i]
		for _, r := range s.details.ReservedLeases {
			if claimed[strings.ToLower(s.listed.Name)+"\x00"+macKey(r.HardwareAddress)] {
				continue
			}
			rows = append(rows, leaseRow{Server: server, Scope: s.listed.Name, Type: leaseReserved, Address: r.Address, HardwareAddress: r.HardwareAddress, HostName: hostIn(r.HostName, s.details.DomainName), Unclaimed: true, Comment: r.Comments})
		}
	}
	slices.SortStableFunc(rows, func(a, b leaseRow) int {
		x, _ := parseAddr(a.Address)
		y, _ := parseAddr(b.Address)

		return cmp.Or(cmp.Compare(strings.ToLower(a.Scope), strings.ToLower(b.Scope)), x.Compare(y), cmp.Compare(a.HardwareAddress, b.HardwareAddress))
	})

	return rows
}

func registerDHCPTools(r *registry) {
	type dhcpScopesIn struct {
		serverArg

		Scope string `json:"scope,omitempty" jsonschema:"only the scopes whose name matches: with a * or a ? the whole name must match, without either the text may be anywhere in it"`
	}
	type dhcpScopesOut struct {
		Scopes  []scopeRow      `json:"scopes"           jsonschema:"each server's scopes, server by server"`
		Serving []string        `json:"serving"          jsonschema:"the servers with a scope switched on: the ones machines get their addresses from. With one alone, nothing leases when it is down"`
		Failed  []serverFailure `json:"failed,omitempty" jsonschema:"the servers that could not be asked, and why"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "dhcp_scopes",
		Description: "Each server's DHCP scopes, side by side: the range a scope leases from and what it leaves out, whether it is switched on and on which of the server's addresses, how long a lease runs, the gateway, name servers and domain machines are given, whether the server records leases in DNS itself, and how many of its addresses are free, leased and reserved. DHCP is each server's own - a cluster does not share it - so serving names the servers machines actually get addresses from. dhcp_leases gives the machines.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dhcpScopesIn) (*mcp.CallToolResult, dhcpScopesOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, dhcpScopesOut{}, err
		}
		answers := ask(ctx, picked, readDHCP)
		failed, err := failures(answers)
		if err != nil {
			return nil, dhcpScopesOut{}, err
		}

		names := newPattern(in.Scope)
		out := dhcpScopesOut{Scopes: []scopeRow{}, Serving: []string{}, Failed: failed}
		for _, a := range answers {
			if a.Err != nil {
				continue
			}
			for i := range a.Value.scopes {
				s := &a.Value.scopes[i]
				if s.listed.Enabled && !slices.Contains(out.Serving, a.Server.Name) {
					out.Serving = append(out.Serving, a.Server.Name)
				}
				if names.matches(s.listed.Name) {
					out.Scopes = append(out.Scopes, scopeRowOf(a.Server.Name, &a.Value, s))
				}
			}
		}

		return nil, out, nil
	})

	type dhcpLeasesIn struct {
		serverArg

		Find   string `json:"find,omitempty"   jsonschema:"only the machines whose host name, address or hardware address matches: with a * or a ? the whole of one must match, without either the text may be anywhere in it. A hardware address is found however it is written: 00:11:22:aa:bb:cc, 00-11-22-AA-BB-CC or 001122aabbcc"`
		Scope  string `json:"scope,omitempty"  jsonschema:"only the leases of the scopes whose name matches, as find matches"`
		Type   string `json:"type,omitempty"   jsonschema:"only dynamic leases, only reserved ones (those no machine holds among them), or only unclaimed reservations"`
		Limit  int    `json:"limit,omitempty"  jsonschema:"the most leases to give (default 200)"`
		Offset int    `json:"offset,omitempty" jsonschema:"how many leases to pass over first, to read on from a limit"`
	}
	type dhcpLeasesOut struct {
		Leases []leaseRow      `json:"leases"           jsonschema:"each lease a machine holds and each reservation none does, server by server and scope by scope, in the order of their addresses"`
		Total  int             `json:"total"            jsonschema:"how many matched, before the limit"`
		Counts map[string]int  `json:"counts"           jsonschema:"how many of those are dynamic, reserved, and reserved but unclaimed"`
		Failed []serverFailure `json:"failed,omitempty" jsonschema:"the servers that could not be asked, and why"`
		Note   string          `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "dhcp_leases",
		Description: "The machines each server has given an address: every lease held now, dynamic or reserved, with the machine's hardware address, the name it gave, and when the lease was taken and ends; and every reservation no machine holds, marked unclaimed. find looks a machine up by name, address or hardware address - what has this address, where is this machine - and every lease is read before any is left out. A server only knows the leases it gave itself: an address set by hand on a machine is in no list here.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dhcpLeasesIn) (*mcp.CallToolResult, dhcpLeasesOut, error) {
		kind := strings.ToLower(strings.TrimSpace(in.Type))
		if !slices.Contains([]string{"", "dynamic", "reserved", "unclaimed"}, kind) {
			return nil, dhcpLeasesOut{}, fmt.Errorf("type %q: it takes dynamic, reserved or unclaimed", in.Type)
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, dhcpLeasesOut{}, err
		}
		answers := ask(ctx, picked, readDHCP)
		failed, err := failures(answers)
		if err != nil {
			return nil, dhcpLeasesOut{}, err
		}

		find, scopes, digits := newPattern(in.Find), newPattern(in.Scope), macDigits(in.Find)
		out := dhcpLeasesOut{Leases: []leaseRow{}, Counts: map[string]int{}, Failed: failed}
		for _, a := range answers {
			if a.Err != nil {
				continue
			}
			for _, row := range leaseRowsOf(a.Server.Name, &a.Value) {
				byMAC := len(digits) >= 4 && strings.Contains(macDigits(row.HardwareAddress), digits)
				found := byMAC || find.matches(row.HostName) || find.matches(row.Address) || find.matches(row.HardwareAddress)
				if !found || !scopes.matches(row.Scope) {
					continue
				}
				if (kind == "dynamic" && row.Type != leaseDynamic) || (kind == "reserved" && row.Type != leaseReserved) || (kind == "unclaimed" && !row.Unclaimed) {
					continue
				}
				out.Counts[strings.ToLower(row.Type)]++
				if row.Unclaimed {
					out.Counts["unclaimed"]++
				}
				out.Leases = append(out.Leases, row)
			}
		}
		out.Total = len(out.Leases)
		out.Leases = out.Leases[min(max(in.Offset, 0), len(out.Leases)):]
		if limit := limitOr(in.Limit); len(out.Leases) > limit {
			out.Leases = out.Leases[:limit]
			out.Note = fmt.Sprintf("%d leases matched and %d are given, starting at the %s: read on with offset %d, or narrow it with find, scope or type", out.Total, limit, ordinal(max(in.Offset, 0)+1), max(in.Offset, 0)+limit)
		}

		return nil, out, nil
	})
}
