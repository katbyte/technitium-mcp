package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/katbyte/go-kt/parallel"
	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// outsideAskers is how many names are asked of the outside at once, and
	// outsideMost how many one call asks before it stops and says so
	outsideAskers = 4
	outsideMost   = 2000
)

// outside is what the outside world is told for a name.
type outside struct {
	// result is how the question went, and addresses what the name ends at
	result    string
	addresses []string
	// err is why nobody outside could be asked
	err string
}

// resolves reports whether the outside has an address for the name.
func (o *outside) resolves() bool { return o.err == "" && len(o.addresses) > 0 }

// askOutside has a server put a name to the name servers that stand for the
// outside, in turn, until one answers.
func askOutside(ctx context.Context, srv *servers.Server, resolvers []string, name, recordType string) outside {
	var out outside
	for _, resolver := range resolvers {
		res, err := srv.Client.Resolve(ctx, technitium.ResolveQuery{Via: resolver, Name: name, Type: recordType})
		if err != nil {
			out.err = err.Error()

			continue
		}
		out = outside{result: res.RCode}
		for i := range res.Answer {
			if addr, ok := res.Answer[i].Address(); ok {
				out.addresses = append(out.addresses, addr.String())
			}
		}
		slices.Sort(out.addresses)

		return out
	}

	return out
}

// inside is a name the servers' own zones hold an address for, or lead to
// one from.
type inside struct {
	name, zone string
	// ends are the addresses it ends at, and holds whether it holds one
	// itself rather than by a CNAME
	ends  []string
	holds bool
	// on are the servers whose zones have it so
	on []string
}

// zoneThenName orders names as a zone tree reads, a zone at a time.
func zoneThenName(x, y *inside) int {
	return cmp.Or(cmp.Compare(nameOrder(x.zone), nameOrder(y.zone)), cmp.Compare(nameOrder(x.name), nameOrder(y.name)))
}

// private reports whether any of some addresses is one of a private network.
func private(addresses []string) bool {
	return slices.ContainsFunc(addresses, func(text string) bool {
		addr, err := netip.ParseAddr(text)

		return err == nil && (addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast())
	})
}

func registerSplitAudit(r *registry) {
	type auditSplitIn struct {
		serverArg

		Resolvers []string `json:"resolvers"        jsonschema:"the name servers that stand for the outside world, by address: a public resolver, as 1.1.1.1. A configured server asks them each name; the second is asked when the first does not answer"`
		Zone      string   `json:"zone,omitempty"   jsonschema:"only the zones whose name matches: with a * or a ? the whole name must match, without either the text may be anywhere in it. Every name asked outside is one more question for the resolver, so a zone at a time is kinder"`
		Names     []string `json:"names,omitempty"  jsonschema:"host names to check as well that the servers' zones may not hold - the names a reverse proxy serves, say: one that resolves outside and has no record here is found"`
		Mirror    []string `json:"mirror,omitempty" jsonschema:"pairs of a zone here and another domain meant to answer alike, as example.com=example.org: each name with an address in the zone is looked up under the other domain as a client of the server would, and found when it ends elsewhere, or nowhere"`
		Limit     int      `json:"limit,omitempty"  jsonschema:"the most findings to give (default 200)"`
		Offset    int      `json:"offset,omitempty" jsonschema:"how many findings to pass over first, to read on from a limit"`
	}
	type auditSplitOut struct {
		Findings []finding       `json:"findings"           jsonschema:"what was found, zone by zone"`
		Total    int             `json:"total"              jsonschema:"how many things were found, before the limit"`
		Counts   map[string]int  `json:"counts"             jsonschema:"how many of each kind"`
		Asked    []string        `json:"asked"              jsonschema:"the servers whose zones were read"`
		Outside  int             `json:"outside"            jsonschema:"how many names were asked of the outside"`
		Internal []string        `json:"internal,omitempty" jsonschema:"the zones of which no name resolves outside: kept for the inside alone, and nothing in them is found for that"`
		Failed   []serverFailure `json:"failed,omitempty"   jsonschema:"the servers that could not be asked, and why"`
		Unread   []zoneProblem   `json:"unread,omitempty"   jsonschema:"zones a server lists and would not give the records of: nothing in them was audited"`
		Note     string          `json:"note,omitempty"`
	}
	problems := [][2]string{
		{"public_gone", "a name with an address here, in a zone whose other names resolve outside, that the outside no longer has: an override left behind, or a name never published"},
		{"private_outside", "a name the outside is given a private address for: the inside's addressing, published"},
		{"no_override", "a name given in names that resolves outside and has no record here: a client inside is sent round by the outside address"},
		{"mirror_differs", "a name under a mirror's other domain that ends somewhere else than the name it mirrors, or nowhere"},
	}
	kinds := make([]string, 0, len(problems))
	for _, p := range problems {
		kinds = append(kinds, p[0]+": "+p[1])
	}
	add(r, readTool, &mcp.Tool{
		Name:        "audit_split",
		Description: "Find where the inside and the outside of a split horizon do not fit, by asking the outside: every name the servers' zones hold an address for is put to the resolvers named, through a configured server, and held against what the zones say. A name answered differently inside and out is the split working, and is not found. It asks other people's name servers one question a name, which is why it is no part of audit_all and why it wants its resolvers named. The findings: " + strings.Join(kinds, "; ") + ".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in auditSplitIn) (*mcp.CallToolResult, auditSplitOut, error) {
		var resolvers []string
		for _, text := range in.Resolvers {
			if text = strings.TrimSpace(text); text == "" {
				continue
			}
			if _, ok := parseAddr(text); !ok {
				return nil, auditSplitOut{}, fmt.Errorf("the resolver %q is not an address: give the name servers that stand for the outside by address, as 1.1.1.1", text)
			}
			resolvers = append(resolvers, text)
		}
		if len(resolvers) == 0 {
			return nil, auditSplitOut{}, errors.New("which resolvers: give the address of a name server that stands for the outside world, as 1.1.1.1. Every name is asked of it, so it is yours to choose")
		}
		type mirror struct{ zone, other string }
		var mirrors []mirror
		for _, pair := range in.Mirror {
			zone, other, ok := strings.Cut(pair, "=")
			if zone, other = cleanName(zone), cleanName(other); !ok || zone == "" || other == "" {
				return nil, auditSplitOut{}, fmt.Errorf("the mirror %q is not a zone and another domain with = between, as example.com=example.org", pair)
			}
			mirrors = append(mirrors, mirror{zone: zone, other: other})
		}
		a, err := r.audited(ctx, in.Server, needs{})
		if err != nil {
			return nil, auditSplitOut{}, err
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, auditSplitOut{}, err
		}
		// the outside is asked through the first server that was read
		asker := picked[slices.IndexFunc(picked, func(srv *servers.Server) bool { return srv.Name == a.inv.asked[0] })]

		// every name the zones hold an address for, or lead to one from, once
		zones := newPattern(in.Zone)
		byName := map[string]*inside{}
		var names []*inside
		for _, v := range a.views {
			for _, z := range v.zones {
				if !zones.matches(z.name) {
					continue
				}
				for name, records := range z.records {
					if strings.HasPrefix(name, "*.") || v.zoneFor(name) != z {
						continue
					}
					ends := v.resolve(name).ends
					if len(ends) == 0 {
						continue
					}
					if byName[name] == nil {
						byName[name] = &inside{name: name, zone: z.name, ends: ends}
						names = append(names, byName[name])
					}
					byName[name].on = append(byName[name].on, v.server)
					byName[name].holds = byName[name].holds || slices.ContainsFunc(enabled(records), func(rec *technitium.Record) bool {
						_, isAddr := rec.Address()

						return isAddr
					})
				}
			}
		}
		slices.SortFunc(names, zoneThenName)

		out := auditSplitOut{Counts: map[string]int{}, Asked: a.inv.asked, Failed: a.inv.failed, Unread: a.inv.problems, Findings: []finding{}}
		if len(names) > outsideMost {
			out.Note = note(out.Note, fmt.Sprintf("the zones hold %d names with an address and the first %d were asked of the outside: take a zone at a time with zone", len(names), outsideMost))
			names = names[:outsideMost]
		}
		told := make([]outside, len(names))
		if err := parallel.Each(ctx, len(names), outsideAskers, func(ctx context.Context, i int) error {
			recordType := "A"
			if addr, err := netip.ParseAddr(names[i].ends[0]); err == nil && addr.Is6() {
				recordType = "AAAA"
			}
			told[i] = askOutside(ctx, asker, resolvers, names[i].name, recordType)

			return nil
		}); err != nil {
			return nil, auditSplitOut{}, err
		}
		out.Outside = len(names)

		// a zone some name of which resolves outside is one the outside knows: there a name it lacks is missing from it
		known := map[string]bool{}
		var unasked int
		for i, n := range names {
			known[n.zone] = known[n.zone] || told[i].resolves()
			if told[i].err != "" {
				unasked++
			}
		}
		if unasked > 0 {
			out.Note = note(out.Note, fmt.Sprintf("%d names could not be asked of the outside, and nothing is found for them: %s", unasked, told[slices.IndexFunc(told, func(o outside) bool { return o.err != "" })].err))
		}
		var found []finding
		say := func(n *inside, f finding) {
			if len(n.on) != len(a.views) {
				f.Servers = n.on
			}
			found = append(found, f)
		}
		for i, n := range names {
			switch o := &told[i]; {
			case o.err != "":
			case private(o.addresses):
				say(n, finding{Problem: "private_outside", Zone: n.zone, Name: n.name, Detail: fmt.Sprintf("the outside is told %s is at %s, a private address: the inside's addressing is published, and a client outside is sent nowhere", n.name, strings.Join(o.addresses, ", ")), Fix: "remove the record from the zone the outside is served, or give it the public address"})
			case !o.resolves() && known[n.zone]:
				say(n, finding{Problem: "public_gone", Zone: n.zone, Name: n.name, Detail: fmt.Sprintf("%s ends at %s here and the outside has no address for it (%s), though it has for other names of %s: an override whose public name is gone, or a name that was never published", n.name, strings.Join(n.ends, ", "), o.result, n.zone), Fix: "remove the record if the name is no longer used; leave it if the name is meant for the inside alone"})
			default:
			}
		}
		for zone, outsideToo := range known {
			if !outsideToo {
				out.Internal = append(out.Internal, zone)
			}
		}
		slices.SortFunc(out.Internal, func(x, y string) int { return cmp.Compare(nameOrder(x), nameOrder(y)) })

		// names given beside the zones': one the outside has and no zone here does
		for _, text := range in.Names {
			name := cleanName(text)
			if name == "" || byName[name] != nil {
				continue
			}
			here := slices.ContainsFunc(a.views, func(v *view) bool {
				at := v.lookup(name)

				return at.status == nameExists || at.status == nameWildcard
			})
			o := askOutside(ctx, asker, resolvers, name, "A")
			out.Outside++
			switch {
			case o.err != "" || !o.resolves():
			case private(o.addresses):
				found = append(found, finding{Problem: "private_outside", Name: name, Detail: fmt.Sprintf("the outside is told %s is at %s, a private address: the inside's addressing is published, and a client outside is sent nowhere", name, strings.Join(o.addresses, ", ")), Fix: "remove the record from the zone the outside is served, or give it the public address"})
			case !here:
				found = append(found, finding{Problem: "no_override", Name: name, Detail: fmt.Sprintf("%s resolves outside to %s and no zone here has a record for it: a client inside is told the outside address, and goes out and back to reach what is beside it", name, strings.Join(o.addresses, ", ")), Fix: "add a record for it here with its inside address"})
			default:
			}
		}

		// a zone's names under the domain that mirrors it, as a client of the server is answered
		for _, m := range mirrors {
			for _, n := range names {
				if n.zone != m.zone || !n.holds {
					continue
				}
				twin := strings.TrimSuffix(n.name, m.zone) + m.other
				res, err := asker.Client.Resolve(ctx, technitium.ResolveQuery{Name: twin})
				if err != nil {
					out.Note = note(out.Note, fmt.Sprintf("%s could not be resolved: %s", twin, err))

					continue
				}
				var ends []string
				for i := range res.Answer {
					if addr, ok := res.Answer[i].Address(); ok {
						ends = append(ends, addr.String())
					}
				}
				slices.Sort(ends)
				switch {
				case slices.Equal(ends, n.ends):
				case len(ends) == 0:
					say(n, finding{Problem: "mirror_differs", Zone: n.zone, Name: n.name, Detail: fmt.Sprintf("%s ends at %s, and %s, which is meant to answer alike, ends nowhere when %s is asked (%s)", n.name, strings.Join(n.ends, ", "), twin, asker.Name, res.RCode), Fix: "give " + twin + " the same record, or take the mirror as not covering this name"})
				default:
					say(n, finding{Problem: "mirror_differs", Zone: n.zone, Name: n.name, Detail: fmt.Sprintf("%s ends at %s, and %s, which is meant to answer alike, ends at %s when %s is asked", n.name, strings.Join(n.ends, ", "), twin, strings.Join(ends, ", "), asker.Name), Fix: "set the two alike"})
				}
			}
		}

		sortFindings(found)
		for i := range found {
			out.Counts[found[i].Problem]++
		}
		out.Total = len(found)
		found = found[min(max(in.Offset, 0), len(found)):]
		if limit := limitOr(in.Limit); len(found) > limit {
			found = found[:limit]
			out.Note = note(out.Note, fmt.Sprintf("%d things were found and %d are given, starting at the %s: read on with offset %d, or narrow it with zone", out.Total, limit, ordinal(max(in.Offset, 0)+1), max(in.Offset, 0)+limit))
		}
		out.Findings = append(out.Findings, found...)

		return nil, out, nil
	})
}
