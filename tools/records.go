package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// foundRow is a record found, with the zone it is in and how it was reached.
type foundRow struct {
	Zone string `json:"zone"`
	recordRow

	Via []string `json:"via,omitempty" jsonschema:"for a record found through a chain: what it points at and each name after that, ending at the address or the name asked for. A record that holds the address, or points straight at the name, has none"`
}

// located is a record with the zone it is in.
type located struct {
	zone   int
	record *technitium.Record
}

// match is a record found on one server, and the chain it was reached by.
type match struct {
	located

	via []string
}

// seeds is what a search by address or by target starts from.
type seeds struct {
	// direct are the records that are themselves the answer
	direct []located
	// ends are the names that end at what was asked for, each with the
	// chain from it: for an address, the names holding it; for a target,
	// the target itself
	ends map[string][]string
}

// chase finds, among one server's records, every record that ends at what
// the seeds stand for: the direct ones, and then whatever points at a name
// already known to end there, round after round until a round finds nothing
// new or the rounds allowed are used (fewer than none is no limit). A CNAME's
// own name becomes such a name; an MX's or an NS's does not.
func chase(all []located, from seeds, rounds int) []match {
	found := make([]match, 0, len(from.direct))
	seen := map[*technitium.Record]bool{}
	for _, d := range from.direct {
		found, seen[d.record] = append(found, match{located: d}), true
	}

	ends := from.ends
	for round := 0; rounds < 0 || round < rounds; round++ {
		// what a round learns is for the next: a record is reached by the
		// shortest chain there is to it
		learned := map[string][]string{}
		for _, l := range all {
			if seen[l.record] {
				continue
			}
			target := cleanName(l.record.Target())
			chain, ok := ends[target]
			if target == "" || !ok {
				continue
			}
			path := append([]string{target}, chain...)
			m := match{located: l, via: path}
			// pointing straight at the name asked for is no chain
			if len(chain) == 0 {
				m.via = nil
			}
			found, seen[l.record] = append(found, m), true
			if name := cleanName(l.record.Name); aliases(l.record.Type) && ends[name] == nil && learned[name] == nil {
				learned[name] = path
			}
		}
		if len(learned) == 0 {
			break
		}
		maps.Copy(ends, learned)
	}

	return found
}

// seedsFor is where a search of one server's records starts: every record
// when neither an address nor a target is asked for, and otherwise the
// records holding the address (with the PTR for it) or pointing at the
// target, with the names a chain may end at.
func seedsFor(all []located, addr netip.Addr, hasAddr bool, target string) seeds {
	from := seeds{ends: map[string][]string{}}
	if hasAddr {
		reverse := reverseName(addr)
		for _, l := range all {
			held, ok := l.record.Address()
			switch {
			case ok && held.Unmap() == addr.Unmap():
				from.direct = append(from.direct, l)
				from.ends[cleanName(l.record.Name)] = []string{addr.String()}
			case l.record.Type == "PTR" && cleanName(l.record.Name) == reverse:
				from.direct = append(from.direct, l)
			default:
			}
		}
	}
	if target != "" {
		// the first round of the chase finds what points straight at it
		from.ends[target] = []string{}
	}

	return from
}

func registerRecordTools(r *registry) {
	type recordFindIn struct {
		serverArg

		Address  string   `json:"address,omitempty"  jsonschema:"an IPv4 or IPv6 address: finds the A and AAAA records holding exactly it, the PTR record for it, and everything that ends at one of those names through a chain of CNAMEs - what would break, or move, if the address changed. An address nothing holds finds nothing, which is how to check that one is free of records"`
		Target   string   `json:"target,omitempty"   jsonschema:"a domain name: finds the records pointing at exactly it (CNAME, ANAME, MX, SRV, NS, PTR, DNAME) and everything that ends there through a chain"`
		Name     string   `json:"name,omitempty"     jsonschema:"keep the records whose own name matches: with a * (any run of characters) or a ? (any one) the whole name must match, as in *.van.example.com; without either the text may be anywhere in the name"`
		Value    string   `json:"value,omitempty"    jsonschema:"keep the records whose value matches, the same way: 10.0.0. finds every address in that range"`
		Types    []string `json:"types,omitempty"    jsonschema:"keep the records of these types, e.g. A, CNAME"`
		Zone     string   `json:"zone,omitempty"     jsonschema:"look only in the zones whose name matches, the same way; left out is every zone but the catalog zones, whose records are the list of their member zones and are searched only when zone names one"`
		Comment  string   `json:"comment,omitempty"  jsonschema:"keep the records whose comment matches, the same way; * alone keeps every record that has one"`
		Disabled *bool    `json:"disabled,omitempty" jsonschema:"true keeps only the disabled records, false only the enabled; left out keeps both"`
		Direct   bool     `json:"direct,omitempty"   jsonschema:"with address or target: only the records that hold the address or point straight at the name, and nothing reached through a chain"`
		Details  bool     `json:"details,omitempty"  jsonschema:"add each server's own facts about each record: when it last answered a query and when it was last changed"`
		Limit    int      `json:"limit,omitempty"    jsonschema:"the most records to give (default 200)"`
		Offset   int      `json:"offset,omitempty"   jsonschema:"how many matching records to pass over first, to read on from a limit"`
	}
	type recordFindOut struct {
		Records     []foundRow      `json:"records"                jsonschema:"the records found, zone by zone in the order a zone tree reads; a record two servers hold alike is one row"`
		Total       int             `json:"total"                  jsonschema:"how many records were found, before the limit"`
		ReverseName string          `json:"reverse_name,omitempty" jsonschema:"with address: the name its PTR record belongs at, whether or not one is there"`
		Zones       int             `json:"zones"                  jsonschema:"how many zones were read, every one whole"`
		Asked       []string        `json:"asked"                  jsonschema:"the servers that answered"`
		Failed      []serverFailure `json:"failed,omitempty"       jsonschema:"the servers that could not be asked, and why: what they hold is not in this answer"`
		Problems    []zoneProblem   `json:"problems,omitempty"     jsonschema:"zones a server lists and would not give the records of: what they hold is not in this answer"`
		Note        string          `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "record_find",
		Description: "Find records across every zone of the configured servers. By address: what holds it, its PTR, and everything that ends at it through a chain of CNAMEs, which is what to know before an address changes hands or to check that one is free. By target: what points at a name, directly or through a chain. By name, value, type or comment: a search of every zone at once. Every zone is read whole, so nothing is missed, and a record not every server asked holds - its zone missing there, or the record - names the ones that do in only_on.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in recordFindIn) (*mcp.CallToolResult, recordFindOut, error) {
		target := cleanName(in.Target)
		var (
			addr    netip.Addr
			hasAddr bool
		)
		if text := strings.TrimSpace(in.Address); text != "" {
			parsed, err := netip.ParseAddr(text)
			if err != nil {
				return nil, recordFindOut{}, fmt.Errorf("address %q is not an IPv4 or IPv6 address: to search values by a pattern, such as a range, use value", in.Address)
			}
			addr, hasAddr = parsed, true
		}
		if hasAddr && target != "" {
			return nil, recordFindOut{}, errors.New("give an address or a target, not both: each is its own search")
		}
		if !hasAddr && target == "" && strings.TrimSpace(in.Name+in.Value+in.Comment) == "" && len(in.Types) == 0 && in.Disabled == nil {
			return nil, recordFindOut{}, errors.New("say what to find: an address, a target, or a name, value, comment or types to match. Every record of one zone is what zone_records gives")
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, recordFindOut{}, err
		}

		zones := newPattern(in.Zone)
		// a catalog zone is searched only when zone asks for zones by name
		inv, err := readInventory(ctx, picked, func(z *technitium.Zone) bool {
			return zones.matches(z.Name) && (served(z) || (in.Zone != "" && !z.Internal))
		})
		if err != nil {
			return nil, recordFindOut{}, err
		}
		out := recordFindOut{Zones: len(inv.zones), Asked: inv.asked, Failed: inv.failed, Problems: inv.problems}
		if hasAddr {
			out.ReverseName = reverseName(addr)
		}

		// each server is searched by itself: a chain is followed through the
		// records one server holds, never from one server's into another's.
		// Asked for the direct ones alone, an address is its holders and no
		// round of pointers, and a target is the one round that points at it
		searching := hasAddr || target != ""
		rounds := -1
		if in.Direct {
			rounds = 0
			if target != "" {
				rounds = 1
			}
		}
		matches := map[string][]match{}
		for _, server := range inv.asked {
			var all []located
			for i, zone := range inv.zones {
				for c := range zone.copies {
					if zone.copies[c].server != server {
						continue
					}
					for j := range zone.copies[c].records {
						all = append(all, located{zone: i, record: &zone.copies[c].records[j]})
					}
				}
			}
			if !searching {
				found := make([]match, 0, len(all))
				for _, l := range all {
					found = append(found, match{located: l})
				}
				matches[server] = found

				continue
			}
			matches[server] = chase(all, seedsFor(all, addr, hasAddr, target), rounds)
		}

		filter := recordFilter{types: in.Types, name: newPattern(in.Name), value: newPattern(in.Value), comment: newPattern(in.Comment), hasComment: strings.TrimSpace(in.Comment) != "", disabled: in.Disabled}
		rows := mergeFound(inv, matches, filter, in.Details)
		out.Total = len(rows)

		rows = rows[min(max(in.Offset, 0), len(rows)):]
		if limit := limitOr(in.Limit); len(rows) > limit {
			rows = rows[:limit]
			out.Note = fmt.Sprintf("%d records were found and %d are given, starting at the %s: read on with offset %d, or narrow it with zone, types, name or value", out.Total, limit, ordinal(max(in.Offset, 0)+1), max(in.Offset, 0)+limit)
		}
		out.Records = rows

		return nil, out, nil
	})
}

// mergeFound is what each server's search found, as one table: zone by zone,
// a record the servers holding its zone found alike - by the same chain - as
// one row, and one only some found naming them.
func mergeFound(inv *inventory, matches map[string][]match, filter recordFilter, details bool) []foundRow {
	// each zone's matches, apart by the chain they were reached through: two
	// servers that reach a record differently have not found it alike
	type group struct {
		via    []string
		copies []zoneCopy
	}
	groups := make([]map[string]*group, len(inv.zones))
	for server, found := range matches {
		for _, m := range found {
			if groups[m.zone] == nil {
				groups[m.zone] = map[string]*group{}
			}
			key := strings.Join(m.via, "\x00")
			g := groups[m.zone][key]
			if g == nil {
				// every server asked is in the group, with what it found or
				// with nothing - a server that does not hold the zone
				// included: that is how a record comes to be only on the
				// others, which is the answer to "is it there on both"
				g = &group{via: m.via}
				for _, asked := range inv.asked {
					g.copies = append(g.copies, zoneCopy{server: asked, copied: slices.ContainsFunc(inv.zones[m.zone].copies, func(c zoneCopy) bool { return c.server == asked && c.copied })})
				}
				groups[m.zone][key] = g
			}
			for c := range g.copies {
				if g.copies[c].server == server {
					g.copies[c].records = append(g.copies[c].records, *m.record)
				}
			}
		}
	}

	rows := make([]foundRow, 0, len(inv.zones))
	for i, zone := range inv.zones {
		var inZone []foundRow
		for _, g := range groups[i] {
			found, _ := mergeRecords(g.copies, filter, details)
			for f := range found {
				inZone = append(inZone, foundRow{Zone: zone.name, recordRow: found[f].recordRow, Via: g.via})
			}
		}
		slices.SortFunc(inZone, func(a, b foundRow) int {
			return cmp.Or(cmp.Compare(nameOrder(a.Name), nameOrder(b.Name)), cmp.Compare(a.Type, b.Type), cmp.Compare(a.Value, b.Value), cmp.Compare(a.TTL, b.TTL), cmp.Compare(strings.Join(a.OnlyOn, ","), strings.Join(b.OnlyOn, ",")))
		})
		rows = append(rows, inZone...)
	}

	return rows
}
