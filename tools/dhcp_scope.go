package tools

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maskOf reads a subnet mask written as one, 255.255.255.0, or as the number
// of its bits, 24 or /24.
func maskOf(text string) (netip.Addr, bool) {
	text = strings.TrimPrefix(strings.TrimSpace(text), "/")
	if n, err := strconv.Atoi(text); err == nil && n > 0 && n <= 30 {
		return address(^uint32(0) << (32 - n)), true
	}
	mask, ok := ipv4(text)
	if !ok || number(mask) == 0 || number(mask) != ^uint32(0)<<(32-bits.LeadingZeros32(^number(mask))) {
		return netip.Addr{}, false
	}

	return mask, true
}

// rangeOf reads one run of addresses written as its first and its last with
// a dash between.
func rangeOf(text string) (first, last netip.Addr, ok bool) {
	from, to, cut := strings.Cut(strings.TrimSpace(text), "-")
	first, firstOK := ipv4(from)
	last, lastOK := ipv4(to)

	return first, last, cut && firstOK && lastOK && number(first) <= number(last)
}

// spans are runs of addresses in words.
func spans(runs []span) string {
	parts := make([]string, 0, len(runs))
	for _, run := range runs {
		parts = append(parts, address(run.first).String()+"-"+address(run.last).String())
	}

	return strings.Join(parts, ", ")
}

// shared are the runs of addresses two scopes both give out.
func shared(a, b *dhcpScope) []span {
	var out []span
	for _, x := range a.runs() {
		for _, y := range b.runs() {
			if first, last := max(x.first, y.first), min(x.last, y.last); first <= last {
				out = append(out, span{first: first, last: last})
			}
		}
	}

	return out
}

func registerDHCPScopeTools(r *registry) {
	type dhcpScopeSetIn struct {
		dhcpServerArg

		Scope            string    `json:"scope"                         jsonschema:"the scope's name: one that is there is changed, and any other is made"`
		First            string    `json:"first,omitempty"               jsonschema:"the first address it leases from; needed, with last and mask, to make a scope"`
		Last             string    `json:"last,omitempty"                jsonschema:"the last address it leases from"`
		Mask             string    `json:"mask,omitempty"                jsonschema:"the network's mask, as 255.255.255.0 or as its bits, 24"`
		LeaseTime        string    `json:"lease_time,omitempty"          jsonschema:"how long a lease runs, as 12h or 7d"`
		Domain           *string   `json:"domain,omitempty"              jsonschema:"the domain machines are told they are in, and the one their names are recorded under with dns_updates"`
		DNSUpdates       *bool     `json:"dns_updates,omitempty"         jsonschema:"have the server record each lease's and reservation's host name under domain itself, with its PTR"`
		Router           *string   `json:"router,omitempty"              jsonschema:"the gateway machines are given"`
		DNSServers       *[]string `json:"dns_servers,omitempty"         jsonschema:"the name servers machines are told to use, by address, in order"`
		UseThisDNSServer *bool     `json:"use_this_dns_server,omitempty" jsonschema:"tell machines to resolve through this server itself, at its own address on the network, whatever dns_servers holds"`
		Exclusions       *[]string `json:"exclusions,omitempty"          jsonschema:"runs of the range never to lease from, each as its first and last address with a dash between: the whole list, an empty one clearing it"`
		OnlyReserved     *bool     `json:"only_reserved,omitempty"       jsonschema:"lease to no machine the scope has no reservation for"`
		Enabled          *bool     `json:"enabled,omitempty"             jsonschema:"true switches the scope on, so that it leases, and false off. A scope that is made is left off unless this says otherwise"`
		DryRun           bool      `json:"dry_run,omitempty"             jsonschema:"change nothing, and answer with what would be done"`
	}
	type dhcpScopeSetOut struct {
		Server  string    `json:"server"`
		Scope   string    `json:"scope"`
		Changed bool      `json:"changed"          jsonschema:"something was changed; with a dry run, something would be"`
		Changes []string  `json:"changes"          jsonschema:"each change made, in order; with a dry run, each that would be"`
		Before  *scopeRow `json:"before,omitempty" jsonschema:"the scope as it was; absent for one that was made"`
		After   *scopeRow `json:"after,omitempty"  jsonschema:"the scope as it is now, read back; absent from a dry run"`
		Note    string    `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "dhcp_scope_set",
		Description: "Make a DHCP scope on one server, or change one that is there: the range it leases from and what it leaves out, the mask, how long a lease runs, the gateway, name servers and domain machines are given, whether the server records leases in DNS, and whether it is switched on. Only what is given is changed. A scope that is made is left switched off unless enabled says otherwise - a second server answering on a network is not something to do by accident; the server switches a new scope on as it makes it, and this switches it off again at once. A range that shares addresses with a scope another server here has on is refused for a scope that is to be on, since two servers do not tell each other what they have leased: give each a part of the network. dhcp_scopes gives what is there.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dhcpScopeSetIn) (*mcp.CallToolResult, dhcpScopeSetOut, error) {
		name := strings.TrimSpace(in.Scope)
		if name == "" {
			return nil, dhcpScopeSetOut{}, errors.New("which scope: give its name")
		}
		srv, held, err := r.dhcpOn(ctx, in.Server)
		if err != nil {
			return nil, dhcpScopeSetOut{}, err
		}
		existing := held.scope(name)
		out := dhcpScopeSetOut{Server: srv.Name, Scope: name, Changes: []string{}}
		done := &changes{dry: in.DryRun}

		// what the scope is to be: what it is, with what was given over it
		want := technitium.NewScope{Name: name}
		var wasOn bool
		exclusions := [][2]string{}
		if existing != nil {
			row := scopeRowOf(srv.Name, held, existing)
			out.Before, name, wasOn = &row, existing.listed.Name, existing.listed.Enabled
			want.Name, want.StartingAddress, want.EndingAddress, want.SubnetMask = name, existing.listed.StartingAddress, existing.listed.EndingAddress, existing.listed.SubnetMask
			for _, e := range existing.details.Exclusions {
				exclusions = append(exclusions, [2]string{e.StartingAddress, e.EndingAddress})
			}
		}
		for what, end := range map[string]struct {
			text string
			into *string
		}{"first": {in.First, &want.StartingAddress}, "last": {in.Last, &want.EndingAddress}} {
			if strings.TrimSpace(end.text) == "" {
				continue
			}
			addr, ok := ipv4(end.text)
			if !ok {
				return nil, dhcpScopeSetOut{}, fmt.Errorf("%s %q is not an IPv4 address", what, end.text)
			}
			*end.into = addr.String()
		}
		if strings.TrimSpace(in.Mask) != "" {
			mask, ok := maskOf(in.Mask)
			if !ok {
				return nil, dhcpScopeSetOut{}, fmt.Errorf("mask %q is no subnet mask: give it as 255.255.255.0, or as its bits, 24", in.Mask)
			}
			want.SubnetMask = mask.String()
		}
		if want.StartingAddress == "" || want.EndingAddress == "" || want.SubnetMask == "" {
			return nil, dhcpScopeSetOut{}, fmt.Errorf("%s has no scope named %s (it has %s), and one is made with the first and last address of its range and its mask: give first, last and mask", srv.Name, name, held.scopeNames())
		}
		first, _ := ipv4(want.StartingAddress)
		last, _ := ipv4(want.EndingAddress)
		mask, _ := ipv4(want.SubnetMask)
		network := netip.PrefixFrom(first, bits.LeadingZeros32(^number(mask))).Masked()
		switch {
		case number(last) < number(first):
			return nil, dhcpScopeSetOut{}, fmt.Errorf("the range ends at %s, before it starts at %s. Nothing was changed", last, first)
		case !network.Contains(last):
			return nil, dhcpScopeSetOut{}, fmt.Errorf("%s and %s are not in one network with the mask %s: the first is in %s. Nothing was changed", first, last, mask, network)
		default:
		}
		if in.Exclusions != nil {
			exclusions = [][2]string{}
			for _, text := range given(in.Exclusions) {
				from, to, ok := rangeOf(text)
				if !ok || number(from) < number(first) || number(to) > number(last) {
					return nil, dhcpScopeSetOut{}, fmt.Errorf("the exclusion %q is not a run of the range %s-%s: give its first and last address with a dash between. Nothing was changed", text, first, last)
				}
				exclusions = append(exclusions, [2]string{from.String(), to.String()})
			}
		}
		if in.Router != nil && strings.TrimSpace(*in.Router) != "" {
			router, ok := ipv4(*in.Router)
			if !ok || !network.Contains(router) {
				return nil, dhcpScopeSetOut{}, fmt.Errorf("the gateway %q is not an address in %s, the scope's network. Nothing was changed", *in.Router, network)
			}
			want.RouterAddress = router.String()
		}
		for _, text := range given(in.DNSServers) {
			addr, ok := parseAddr(text)
			if !ok {
				return nil, dhcpScopeSetOut{}, fmt.Errorf("the name server %q is not an address: machines are told name servers by address. Nothing was changed", text)
			}
			want.DNSServers = append(want.DNSServers, addr.String())
		}
		if strings.TrimSpace(in.LeaseTime) != "" {
			if want.LeaseTime, err = lengthOf(in.LeaseTime); err != nil {
				return nil, dhcpScopeSetOut{}, fmt.Errorf("lease_time: %w", err)
			}
		}
		if in.Domain != nil {
			want.DomainName = cleanName(*in.Domain)
		}
		want.DNSUpdates, want.UseThisDNSServer, want.AllowOnlyReservedLeases = in.DNSUpdates, in.UseThisDNSServer, in.OnlyReserved

		// the scope as it would be, to hold against the others
		on := wasOn
		if in.Enabled != nil {
			on = *in.Enabled
		}
		planned := &dhcpScope{listed: technitium.Scope{Name: name, StartingAddress: want.StartingAddress, EndingAddress: want.EndingAddress, SubnetMask: want.SubnetMask}, details: &technitium.ScopeDetails{}}
		for _, e := range exclusions {
			planned.details.Exclusions = append(planned.details.Exclusions, struct {
				StartingAddress string `json:"startingAddress"`
				EndingAddress   string `json:"endingAddress"`
			}{e[0], e[1]})
		}
		for i := range held.scopes {
			other := &held.scopes[i]
			whole, ok := other.span()
			if other != existing && ok && number(first) <= whole.last && number(last) >= whole.first {
				return nil, dhcpScopeSetOut{}, fmt.Errorf("the range %s-%s runs into that of scope %s on %s, %s-%s: a server's scopes each lease a part of their own. Nothing was changed", first, last, other.listed.Name, srv.Name, other.listed.StartingAddress, other.listed.EndingAddress)
			}
		}
		if on {
			others := slices.DeleteFunc(r.servers.Every(), func(o *servers.Server) bool { return o.Name == srv.Name })
			for _, a := range ask(ctx, others, readDHCP) {
				if a.Err != nil {
					out.Note = note(out.Note, fmt.Sprintf("%s could not be asked for its scopes, so whether it leases any of these addresses is not known: %s", a.Server.Name, a.Err))

					continue
				}
				for i := range a.Value.scopes {
					other := &a.Value.scopes[i]
					if both := shared(planned, other); other.listed.Enabled && len(both) > 0 {
						return nil, dhcpScopeSetOut{}, fmt.Errorf("%s leases %s from its scope %s, which is on, and this scope would lease the same: two servers do not tell each other what they have leased, and two machines would be given one address. Give this scope another part of the network, or exclude those addresses from one of the two. Nothing was changed", a.Server.Name, spans(both), other.listed.Name)
					}
				}
			}
		}

		// what differs from what is there
		if existing == nil {
			done.did("made the scope %s on %s, leasing %s-%s in %s", name, srv.Name, first, last, network)
		} else {
			d := existing.details
			var had [][2]string
			for _, e := range d.Exclusions {
				had = append(had, [2]string{e.StartingAddress, e.EndingAddress})
			}
			same := want.StartingAddress == existing.listed.StartingAddress && want.EndingAddress == existing.listed.EndingAddress && want.SubnetMask == existing.listed.SubnetMask && (in.Exclusions == nil || slices.Equal(exclusions, had)) && (in.Router == nil || want.RouterAddress == d.RouterAddress) && (in.DNSServers == nil || slices.Equal(want.DNSServers, d.DNSServers)) && (in.Domain == nil || want.DomainName == cleanName(d.DomainName))
			same = same && (want.LeaseTime == 0 || want.LeaseTime == time.Duration(d.LeaseTimeDays*24*60+d.LeaseTimeHours*60+d.LeaseTimeMinutes)*time.Minute) && (in.DNSUpdates == nil || *in.DNSUpdates == d.DNSUpdates) && (in.UseThisDNSServer == nil || *in.UseThisDNSServer == d.UseThisDNSServer) && (in.OnlyReserved == nil || *in.OnlyReserved == d.AllowOnlyReservedLeases)
			if !same {
				done.did("set the scope %s on %s as asked: it leases %s-%s in %s", name, srv.Name, first, last, network)
			}
		}
		set := len(done.said) > 0
		want.Exclusions = nil
		if in.Exclusions != nil {
			want.Exclusions = exclusions
		}
		if set && !in.DryRun {
			if err := srv.Client.SetScope(ctx, want); err != nil {
				return nil, dhcpScopeSetOut{}, fmt.Errorf("setting the scope %s: %w. Nothing was changed", name, err)
			}
		}
		// the server switches a scope on as it makes it
		switch nowOn := wasOn || (existing == nil && set); {
		case on && !nowOn:
			if done.did("switched the scope on: it leases from now") {
				if err := srv.Client.EnableScope(ctx, name); err != nil {
					return nil, dhcpScopeSetOut{}, fmt.Errorf("switching the scope %s on: %w. The rest of what was asked was set", name, err)
				}
			}
		case !on && nowOn && existing == nil:
			if done.did("switched the scope off again, the server having switched it on as it made it: give enabled to have it lease") {
				if err := srv.Client.DisableScope(ctx, name); err != nil {
					return nil, dhcpScopeSetOut{}, fmt.Errorf("the scope %s was made and is switched on, and switching it off again failed: %w. It is leasing: switch it off, or delete it, in the server's console", name, err)
				}
			}
		case !on && nowOn:
			if done.did("switched the scope off: it leases nothing, and keeps its reservations and what it has leased") {
				if err := srv.Client.DisableScope(ctx, name); err != nil {
					return nil, dhcpScopeSetOut{}, fmt.Errorf("switching the scope %s off: %w. The rest of what was asked was set", name, err)
				}
			}
		default:
		}
		if out.Changes, out.Changed = done.said, len(done.said) > 0; in.DryRun {
			return nil, out, nil
		}
		if !out.Changed {
			out.After = out.Before

			return nil, out, nil
		}

		now, err := readDHCP(ctx, srv)
		if err != nil {
			return nil, dhcpScopeSetOut{}, fmt.Errorf("the change was made, and the scope could not be read back: %w", err)
		}
		made := now.scope(name)
		if made == nil || made.listed.StartingAddress != want.StartingAddress || made.listed.EndingAddress != want.EndingAddress || made.listed.Enabled != on {
			return nil, dhcpScopeSetOut{}, fmt.Errorf("the server took the change and the scope %s on %s is not as asked: %+v", name, srv.Name, made)
		}
		row := scopeRowOf(srv.Name, &now, made)
		out.After = &row
		if own, ok := ipv4(made.listed.InterfaceAddress); on && (!ok || own.IsUnspecified()) {
			out.Note = note(out.Note, fmt.Sprintf("%s has no address of its own in %s: it hears machines there only through a relay", srv.Name, network))
		}

		return nil, out, nil
	})
}
