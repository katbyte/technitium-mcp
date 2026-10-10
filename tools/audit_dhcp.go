package tools

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// poolLow is the part of a scope's addresses left free, one in this many,
// at and under which the scope is said to be running out, and poolLowFrom
// the size under which a scope is too small for that to mean anything.
const (
	poolLow     = 10
	poolLowFrom = 10
)

// readDHCP reads the DHCP of every server asked, and the addresses each
// server has, for the audits that weigh one against the other. A server
// whose DHCP will not be read is said beside the findings: nothing of its
// DHCP was audited.
func (a *audited) readDHCP(ctx context.Context, picked []*servers.Server) {
	type read struct {
		held      dhcpHeld
		addresses []netip.Addr
		known     bool
	}
	a.dhcp, a.addresses = map[string]*dhcpHeld{}, map[string][]netip.Addr{}
	for _, answer := range ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (read, error) {
		held, err := readDHCP(ctx, srv)
		if err != nil {
			return read{}, err
		}
		out := read{held: held}
		// a server says which addresses are its own where it says how it stands in a cluster, in one or not
		if state, err := srv.Client.ClusterState(ctx); err == nil {
			out.known = true
			for _, text := range state.ServerIPAddresses {
				if addr, ok := parseAddr(text); ok {
					out.addresses = append(out.addresses, addr)
				}
			}
		}

		return out, nil
	}) {
		switch {
		case !slices.Contains(a.inv.asked, answer.Server.Name):
		case answer.Err != nil:
			a.dhcpFailed = append(a.dhcpFailed, serverFailure{Server: answer.Server.Name, Error: answer.Err.Error()})
		default:
			a.dhcp[answer.Server.Name] = &answer.Value.held
			if answer.Value.known {
				a.addresses[answer.Server.Name] = answer.Value.addresses
			}
		}
	}
}

// holder is a name that holds an address by a record of its own.
type holder struct {
	name, zone string
	rec        *technitium.Record
}

// holders are the names holding each address in a server's zones, by
// records that are not disabled and not wildcards, in the order of the
// names.
func (v *view) holders() map[netip.Addr][]holder {
	out := map[netip.Addr][]holder{}
	for _, z := range v.zones {
		for name, records := range z.records {
			for _, rec := range enabled(records) {
				if addr, ok := rec.Address(); ok && !strings.HasPrefix(name, "*.") {
					out[addr] = append(out[addr], holder{name: name, zone: z.name, rec: rec})
				}
			}
		}
	}
	for addr := range out {
		slices.SortFunc(out[addr], func(x, y holder) int { return cmp.Compare(x.name, y.name) })
	}

	return out
}

// runs are the runs of addresses a scope gives out by itself: its range
// with its exclusions cut out.
func (s *dhcpScope) runs() []span {
	whole, ok := s.span()
	if !ok {
		return nil
	}

	var out []span
	at := whole.first
	for _, e := range s.excluded() {
		if e.first > at {
			out = append(out, span{first: at, last: e.first - 1})
		}
		if e.last == whole.last {
			return out
		}
		at = e.last + 1
	}

	return append(out, span{first: at, last: whole.last})
}

// leaseAt is the lease a scope has given on an address, nil when it has
// given none.
func (h *dhcpHeld) leaseAt(scope string, addr netip.Addr) *technitium.Lease {
	for i := range h.leases {
		if leased, ok := ipv4(h.leases[i].Address); ok && leased == addr && strings.EqualFold(h.leases[i].Scope, scope) {
			return &h.leases[i]
		}
	}

	return nil
}

// reservedAt reports whether a scope keeps an address for a machine.
func (s *dhcpScope) reservedAt(addr netip.Addr) bool {
	for i := range s.details.ReservedLeases {
		if kept, ok := ipv4(s.details.ReservedLeases[i].Address); ok && kept == addr {
			return true
		}
	}

	return false
}

// address is a number as the IPv4 address it is.
func address(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)

	return netip.AddrFrom4(b)
}

// auditDHCP finds what is wrong with the servers' DHCP, and where it and
// their zones do not agree.
func auditDHCP(a *audited) []finding {
	var found []finding
	// DHCP is each server's own, so each finding names its server when more than one was asked
	say := func(server string, f finding) {
		if len(a.views) > 1 {
			f.Servers = []string{server}
		}
		found = append(found, f)
	}

	type live struct {
		server string
		scope  *dhcpScope
	}
	var leasing []live
	var leasers, idle []string
	for _, v := range a.views {
		held := a.dhcp[v.server]
		if held == nil {
			continue
		}
		before := len(leasing)
		for i := range held.scopes {
			if held.scopes[i].listed.Enabled {
				leasing = append(leasing, live{server: v.server, scope: &held.scopes[i]})
			}
		}
		if len(leasing) > before {
			leasers = append(leasers, v.server)
		} else {
			idle = append(idle, v.server)
		}
	}
	if len(leasers) == 1 && len(idle) > 0 {
		say(leasers[0], finding{Problem: "dhcp_one_server", Detail: fmt.Sprintf("%s alone leases addresses, and %s has no scope switched on: while %s is down no machine is given an address or renews one", leasers[0], strings.Join(idle, ", "), leasers[0]), Fix: "give " + idle[0] + " a scope for the same network over a part of the range " + leasers[0] + " does not lease from - the two do not tell each other what they have given, so their ranges must not meet - or accept it: a machine keeps its address for the rest of its lease"})
	}

	// two servers leasing the same addresses give them out without knowing of each other
	for i, x := range leasing {
		for _, y := range leasing[i+1:] {
			if x.server == y.server {
				continue
			}
			for _, xr := range x.scope.runs() {
				for _, yr := range y.scope.runs() {
					if first, last := max(xr.first, yr.first), min(xr.last, yr.last); first <= last {
						found = append(found, finding{Problem: "ranges_overlap", Zone: cleanName(x.scope.details.DomainName), Name: x.scope.listed.Name, Servers: []string{x.server, y.server}, Detail: fmt.Sprintf("%s (scope %s) and %s (scope %s) both lease %s-%s, and neither knows what the other has given: two machines can be given one address", x.server, x.scope.listed.Name, y.server, y.scope.listed.Name, address(first), address(last)), Fix: "exclude the addresses from one of the two scopes, so each server leases a part of the network the other does not"})
					}
				}
			}
		}
	}

	// the addresses every server asked is known by: what a scope may tell machines to resolve through
	var known []netip.Addr
	everyKnown := true
	for _, v := range a.views {
		addrs, ok := a.addresses[v.server]
		known, everyKnown = append(known, addrs...), everyKnown && ok && len(addrs) > 0
	}

	for _, l := range leasing {
		v := a.views[slices.IndexFunc(a.views, func(v *view) bool { return v.server == l.server })]
		held, s, d := a.dhcp[l.server], l.scope, l.scope.details
		scope, domain := s.listed.Name, cleanName(d.DomainName)
		network, hasNetwork := s.network()
		holders := v.holders()

		if row := scopeRowOf(l.server, held, s); row.Addresses >= poolLowFrom && row.Free*poolLow <= row.Addresses {
			say(l.server, finding{Problem: "pool_low", Zone: domain, Name: scope, Detail: fmt.Sprintf("scope %s on %s has %d of its %d addresses free: %d leases are held and %d addresses reserved", scope, l.server, row.Free, row.Addresses, row.Leased, row.Reserved), Fix: "widen the range, shorten the lease time so addresses of machines that left come back sooner, or have the server forget leases of machines that are gone"})
		}
		if domain != "" && !slices.ContainsFunc(a.views, func(o *view) bool { return o.zoneFor(domain) != nil }) {
			say(l.server, finding{Problem: "scope_domain_unknown", Zone: domain, Name: scope, Detail: fmt.Sprintf("scope %s on %s tells machines they are in %s, and no server asked holds a zone for it: a host looked up by its short name finds nothing", scope, l.server, domain), Fix: "set the scope's domain to the one the hosts' records are under"})
		}

		// the name servers machines are told to use
		var told []netip.Addr
		if own, ok := ipv4(s.listed.InterfaceAddress); ok && d.UseThisDNSServer && !own.IsUnspecified() {
			told = append(told, own)
		}
		for _, text := range d.DNSServers {
			addr, ok := parseAddr(text)
			if !ok {
				continue
			}
			told = append(told, addr)
			if everyKnown && !slices.Contains(known, addr) {
				say(l.server, finding{Problem: "scope_dns_unknown", Zone: domain, Name: scope, Detail: fmt.Sprintf("scope %s on %s tells machines to resolve through %s, which is no address of a server asked: what they are told there is not what these servers hold", scope, l.server, addr), Fix: "give the scope the addresses of these servers as its name servers, unless the other is meant"})
			}
		}
		for _, o := range a.views {
			if addrs := a.addresses[o.server]; len(told) > 0 && len(addrs) > 0 && !slices.ContainsFunc(addrs, func(addr netip.Addr) bool { return slices.Contains(told, addr) }) {
				say(l.server, finding{Problem: "scope_dns_missing", Zone: domain, Name: scope, Detail: fmt.Sprintf("scope %s on %s tells machines to resolve through %s and not through %s (%s): it is never asked, and takes nothing over when the others are down", scope, l.server, joinAddrs(told), o.server, joinAddrs(addrs)), Fix: "add " + o.server + "'s address to the scope's name servers"})
			}
		}

		// reservations: against the scope, against each other, against the leases and against the zones
		kept := map[netip.Addr][]string{}
		for i := range held.scopes {
			for _, res := range held.scopes[i].details.ReservedLeases {
				if addr, ok := ipv4(res.Address); ok && held.scopes[i].listed.Enabled {
					kept[addr] = append(kept[addr], machine(res.HardwareAddress, res.HostName))
				}
			}
		}
		// the server lists a scope's reservations in no order of its own
		for addr := range kept {
			slices.Sort(kept[addr])
		}
		for _, res := range d.ReservedLeases {
			addr, ok := ipv4(res.Address)
			if !ok {
				continue
			}
			who := machine(res.HardwareAddress, res.HostName)
			if hasNetwork && !network.Contains(addr) {
				say(l.server, finding{Problem: "reservation_outside", Zone: domain, Name: res.Address, Detail: fmt.Sprintf("scope %s on %s keeps %s for %s, which is outside its network %s: the machine could not use it", scope, l.server, addr, who, network), Fix: "remove the reservation, or set it to an address in " + network.String()})
			}
			if others := kept[addr]; len(others) > 1 && others[0] == who {
				say(l.server, finding{Problem: "reservation_shared", Zone: domain, Name: res.Address, Detail: fmt.Sprintf("%s is kept for %d machines on %s: %s. Whichever asks is given it, and both can at once", addr, len(others), l.server, strings.Join(others, ", ")), Fix: "keep the reservation of the machine that is meant to have the address and remove the others"})
			}
			for i := range held.leases {
				if leased, ok := ipv4(held.leases[i].Address); ok && leased == addr && macKey(held.leases[i].HardwareAddress) != macKey(res.HardwareAddress) {
					say(l.server, finding{Problem: "reservation_leased_away", Zone: domain, Name: res.Address, Detail: fmt.Sprintf("scope %s on %s keeps %s for %s, and %s holds a lease on it until %s", scope, l.server, addr, who, machine(held.leases[i].HardwareAddress, held.leases[i].HostName), utc(held.leases[i].LeaseExpires)), Fix: "once the machine holding it is off the address, have the server forget its lease; or reserve another address"})
				}
			}

			if res.HostName == "" || domain == "" {
				if len(holders[addr]) == 0 {
					say(l.server, finding{Problem: "reservation_no_record", Zone: domain, Name: res.Address, Detail: fmt.Sprintf("scope %s on %s keeps %s for %s, and no record on %s names that address: the machine has an address of its own and no name", scope, l.server, addr, who, l.server), Fix: "give the reservation a host name in a scope with dns_updates on and the server records it, or add the record by hand"})
				}

				continue
			}
			host := hostIn(res.HostName, domain)
			at := v.lookup(host)
			var has []string
			for _, rec := range at.records {
				if heldAddr, isAddr := rec.Address(); isAddr && at.status == nameExists {
					has = append(has, heldAddr.String())
				}
			}
			switch {
			case at.status == nameDelegated || slices.Contains(has, addr.String()):
			case len(has) > 0:
				say(l.server, finding{Problem: "reservation_record_elsewhere", Zone: at.zone, Name: host, Detail: fmt.Sprintf("scope %s on %s keeps %s for %s, and %s holds %s: the name does not lead to the machine", scope, l.server, addr, who, host, strings.Join(has, ", ")), Fix: "set the record to " + addr.String() + ", or the reservation to the address the record holds"})
			default:
				say(l.server, finding{Problem: "reservation_no_record", Zone: cmp.Or(at.zone, domain), Name: host, Detail: fmt.Sprintf("scope %s on %s keeps %s for %s, and %s has no address record on %s", scope, l.server, addr, who, host, l.server), Fix: "set the reservation again in a scope with dns_updates on and the server records it, or add the record by hand: " + host + " A " + addr.String()})
			}
		}

		// records made by hand at addresses the scope gives out by itself
		var inPool []netip.Addr
		for addr := range holders {
			if s.leases(addr) && len(kept[addr]) == 0 {
				inPool = append(inPool, addr)
			}
		}
		slices.SortFunc(inPool, func(x, y netip.Addr) int { return x.Compare(y) })
		for _, addr := range inPool {
			for _, h := range holders[addr] {
				if _, written := byDHCP(h.rec.Comments); written {
					continue
				}
				if lease := held.leaseAt(scope, addr); lease != nil && cleanName(lease.HostName) != h.name {
					say(l.server, finding{Problem: "address_leased_elsewhere", Zone: h.zone, Name: h.name, Detail: fmt.Sprintf("%s holds %s by a record made by hand, and scope %s on %s has leased that address to %s until %s", h.name, addr, scope, l.server, machine(lease.HardwareAddress, lease.HostName), utc(lease.LeaseExpires)), Fix: "move the record's host to an address outside the range " + s.listed.StartingAddress + "-" + s.listed.EndingAddress + ", or reserve the address for it once the lease is gone"})

					continue
				}
				say(l.server, finding{Problem: "static_in_pool", Zone: h.zone, Name: h.name, Detail: fmt.Sprintf("%s holds %s by a record made by hand, and scope %s on %s leases from %s-%s: with no reservation, the server can give that address to another machine", h.name, addr, scope, l.server, s.listed.StartingAddress, s.listed.EndingAddress), Fix: "reserve the address for the machine, exclude it from the scope's range, or move the host to an address outside it"})
			}
		}

		// a lease whose name a record made by hand holds, for another address
		for i := range held.leases {
			lease := &held.leases[i]
			leased, ok := ipv4(lease.Address)
			if !ok || lease.HostName == "" || !strings.EqualFold(lease.Scope, scope) {
				continue
			}
			at := v.lookup(lease.HostName)
			var has []string
			for _, rec := range at.records {
				if heldAddr, isAddr := rec.Address(); isAddr && at.status == nameExists && heldAddr != leased {
					if _, written := byDHCP(rec.Comments); !written {
						has = append(has, heldAddr.String())
					}
				}
			}
			if len(has) > 0 {
				say(l.server, finding{Problem: "lease_name_taken", Zone: at.zone, Name: cleanName(lease.HostName), Detail: fmt.Sprintf("%s on %s is leased %s under the name %s, which a record made by hand holds for %s: the server leaves that record alone, so the name does not lead to the machine", lease.HardwareAddress, l.server, leased, cleanName(lease.HostName), strings.Join(has, ", ")), Fix: "remove the record if the name is the machine's, or give the machine another name"})
			}
		}
	}

	// records the server wrote for a lease or a reservation that is no longer there
	for _, v := range a.views {
		held := a.dhcp[v.server]
		if held == nil {
			continue
		}
		for _, z := range v.zones {
			names := make([]string, 0, len(z.records))
			for name := range z.records {
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				for _, rec := range z.records[name] {
					scope, written := byDHCP(rec.Comments)
					addr, isAddr := rec.Address()
					if rec.Type == "PTR" {
						addr, isAddr = reverseAddr(name)
					}
					if !written || !isAddr {
						continue
					}
					s := held.scope(scope)
					if s == nil {
						say(v.server, finding{Problem: "record_left_behind", Zone: z.name, Name: name, Detail: fmt.Sprintf("%s was written by the DHCP scope %s on %s, which is gone: the server removes its records as leases end, and not when a scope is deleted", recordAt(rec), scope, v.server), Fix: "delete the record, unless the host is still at the address: then it is a record of yours now, and worth a comment that says so"})

						continue
					}
					if held.leaseAt(scope, addr) != nil || s.reservedAt(addr) {
						continue
					}
					say(v.server, finding{Problem: "record_left_behind", Zone: z.name, Name: name, Detail: fmt.Sprintf("%s was written by the DHCP scope %s on %s, which has no lease and no reservation for %s now", recordAt(rec), scope, v.server, addr), Fix: "delete the record, unless the host is still at the address: then it is a record of yours now, and worth a comment that says so"})
				}
			}
		}
	}

	return found
}

// joinAddrs is a list of addresses in words.
func joinAddrs(addrs []netip.Addr) string {
	texts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		texts = append(texts, addr.String())
	}

	return strings.Join(texts, ", ")
}
