package tools

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// statusDiffers is a name the servers asked do not answer alike.
const statusDiffers = "differs"

// nameOn is what one server's own zones give for a name.
type nameOn struct {
	Server   string   `json:"server,omitempty"   jsonschema:"the server this is the answer of, in a row's per-server answers"`
	Status   string   `json:"status"             jsonschema:"exists: there are records at the name. wildcard: there are none, and a wildcard answers for it. disabled: its only records are disabled, so it does not resolve. delegated: it is under a part of the zone handed to other name servers. missing: a zone here is where it belongs and holds nothing for it. no_zone: no zone here holds it, so the server resolves it as it does any name not its own"`
	Zone     string   `json:"zone,omitempty"     jsonschema:"the zone the name belongs in: where a record for it would go"`
	Records  []string `json:"records,omitempty"  jsonschema:"the records answering for the name, each as its type and value"`
	Wildcard string   `json:"wildcard,omitempty" jsonschema:"the wildcard name whose records answer, when no record is at the name itself"`
	Chain    []string `json:"chain,omitempty"    jsonschema:"each name a CNAME at the name leads through, in order"`
	EndsAt   []string `json:"ends_at,omitempty"  jsonschema:"the addresses the name ends at, its CNAMEs followed through the server's own zones"`
	Problem  string   `json:"problem,omitempty"  jsonschema:"why the name ends nowhere when it should: a CNAME whose target has no record, a loop, a target in no zone here, a delegation"`
}

// same reports whether two servers answer a name alike.
func (n *nameOn) same(o *nameOn) bool {
	return n.Status == o.Status && n.Zone == o.Zone && n.Wildcard == o.Wildcard && n.Problem == o.Problem && slices.Equal(n.Records, o.Records) && slices.Equal(n.Chain, o.Chain) && slices.Equal(n.EndsAt, o.EndsAt)
}

// nameRow is one name asked about.
type nameRow struct {
	Name string `json:"name"`
	nameOn

	PerServer []nameOn `json:"per_server,omitempty" jsonschema:"each server's own answer, when they do not answer alike and status is differs"`
	Expected  string   `json:"expected,omitempty"   jsonschema:"what the name was expected to end at"`
	Unmet     string   `json:"unmet,omitempty"      jsonschema:"how the name falls short of what was expected of it, on which servers"`
}

// nameOnOf is one server's answer for a name.
func nameOnOf(v *view, name string) nameOn {
	res := v.resolve(name)
	on := nameOn{Status: res.status, Zone: res.zone, Wildcard: res.wildcard, Chain: res.chain, EndsAt: res.ends, Problem: res.problem}
	for _, rec := range res.records {
		text := rec.Type + " " + rec.Value()
		if rec.Disabled {
			text += " (disabled)"
		}
		on.Records = append(on.Records, text)
	}
	slices.Sort(on.Records)
	if res.status == nameDelegated {
		on.Problem = "it is under " + res.delegated + ", which is delegated to other name servers"
	}

	return on
}

// meets says how a server's answer falls short of what a name is expected to
// end at - an address, or a name it should pass through or end at - and ""
// when it does not fall short.
func meets(on *nameOn, expected string) string {
	if on.Status != nameExists && on.Status != nameWildcard {
		return "it is " + strings.ReplaceAll(on.Status, "_", " ")
	}
	if addr, err := netip.ParseAddr(expected); err == nil {
		if slices.Contains(on.EndsAt, addr.String()) {
			return ""
		}
		if len(on.EndsAt) == 0 {
			return "it ends at no address"
		}

		return "it ends at " + strings.Join(on.EndsAt, ", ")
	}
	if slices.Contains(on.Chain, cleanName(expected)) {
		return ""
	}
	if len(on.Chain) == 0 {
		return "it points at no name"
	}

	return "it points at " + strings.Join(on.Chain, " > ")
}

func registerNameAudit(r *registry) {
	type auditNamesIn struct {
		serverArg

		Names   []string          `json:"names"             jsonschema:"the host names to check, as many as there are: every name a reverse proxy routes, every name a certificate carries"`
		Expect  map[string]string `json:"expect,omitempty"  jsonschema:"what some of the names should end at, by name: an address, or a name its CNAMEs should lead to or through. A name that is in names and falls short is said so in unmet"`
		Subtree string            `json:"subtree,omitempty" jsonschema:"a domain: also list the names under it that have an address or a CNAME and are not in names - records nothing in the list uses, which may be left over"`
		Only    []string          `json:"only,omitempty"    jsonschema:"give only the names with these statuses, e.g. missing, wildcard, differs; none gives every name. The counts are of every name either way"`
	}
	type unlisted struct {
		Name    string   `json:"name"`
		Records []string `json:"records"           jsonschema:"what is at the name, each as its type and value"`
		OnlyOn  []string `json:"only_on,omitempty" jsonschema:"the servers holding it, when not every server asked does"`
	}
	type auditNamesOut struct {
		Names    []nameRow       `json:"names"              jsonschema:"the names asked about, in the order given"`
		Counts   map[string]int  `json:"counts"             jsonschema:"how many names have each status"`
		Unmet    int             `json:"unmet"              jsonschema:"how many names fall short of what expect says of them"`
		Unlisted []unlisted      `json:"unlisted,omitempty" jsonschema:"with subtree: the names under it that have an address or a CNAME and were not asked about"`
		Asked    []string        `json:"asked"              jsonschema:"the servers that answered"`
		Failed   []serverFailure `json:"failed,omitempty"   jsonschema:"the servers that could not be asked, and why"`
		Problems []zoneProblem   `json:"problems,omitempty" jsonschema:"zones a server lists and would not give the records of: a name in one reads as missing there"`
		Note     string          `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "audit_names",
		Description: "Check a list of host names against the servers' own zones and say of each whether it has records, where it ends when its CNAMEs are followed, or why it does not: missing from the zone it belongs in, answered only by a wildcard, disabled, delegated, or in no zone here at all. Give it every name a reverse proxy routes to find the ones with no record. expect holds some of them to an address or a name; subtree lists the names under a domain that nothing in the list uses. The zones are read whole and the names looked up in them, so a thousand names cost no more than one; a name the servers answer differently is differs, with each server's answer.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in auditNamesIn) (*mcp.CallToolResult, auditNamesOut, error) {
		var names []string
		for _, name := range in.Names {
			if name = cleanName(name); name != "" && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			return nil, auditNamesOut{}, errors.New("which names: give the host names to check in names")
		}
		expect := map[string]string{}
		for name, want := range in.Expect {
			if !slices.Contains(names, cleanName(name)) {
				return nil, auditNamesOut{}, fmt.Errorf("expect names %s, which is not in names", name)
			}
			expect[cleanName(name)] = strings.TrimSpace(want)
		}
		for _, status := range in.Only {
			if !slices.Contains([]string{nameExists, nameWildcard, nameDisabled, nameDelegated, nameMissing, nameNoZone, statusDiffers}, status) {
				return nil, auditNamesOut{}, fmt.Errorf("only takes exists, wildcard, disabled, delegated, missing, no_zone and differs, not %q", status)
			}
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, auditNamesOut{}, err
		}

		inv, err := readInventory(ctx, picked, served)
		if err != nil {
			return nil, auditNamesOut{}, err
		}
		views := make([]*view, 0, len(inv.asked))
		for _, server := range inv.asked {
			views = append(views, viewOf(inv, server))
		}

		out := auditNamesOut{Counts: map[string]int{}, Asked: inv.asked, Failed: inv.failed, Problems: inv.problems}
		for _, name := range names {
			row := nameRow{Name: name, Expected: expect[name]}
			answers := make([]nameOn, 0, len(views))
			var short []string
			for _, v := range views {
				on := nameOnOf(v, name)
				if row.Expected != "" {
					if how := meets(&on, row.Expected); how != "" {
						short = append(short, v.server+": "+how)
					}
				}
				answers = append(answers, on)
			}

			row.nameOn = answers[0]
			if slices.ContainsFunc(answers, func(o nameOn) bool { return !o.same(&answers[0]) }) {
				row.nameOn = nameOn{Status: statusDiffers}
				for i := range answers {
					answers[i].Server = views[i].server
				}
				row.PerServer = answers
			}
			if len(short) > 0 {
				row.Unmet = strings.Join(short, "; ")
				// said once when every server falls short the same way
				if _, how, _ := strings.Cut(short[0], ": "); len(short) == len(views) && !slices.ContainsFunc(short, func(s string) bool { return !strings.HasSuffix(s, ": "+how) }) {
					row.Unmet = how
				}
				out.Unmet++
			}
			out.Counts[row.Status]++
			if len(in.Only) == 0 || slices.Contains(in.Only, row.Status) {
				out.Names = append(out.Names, row)
			}
		}

		if subtree := cleanName(in.Subtree); subtree != "" {
			seen := map[string]*unlisted{}
			for _, v := range views {
				for _, z := range v.zones {
					for name, records := range z.records {
						if (name != subtree && !strings.HasSuffix(name, "."+subtree)) || slices.Contains(names, name) || strings.HasPrefix(name, "*.") {
							continue
						}
						var holds []string
						for _, rec := range enabled(records) {
							if _, isAddr := rec.Address(); isAddr || aliases(rec.Type) {
								holds = append(holds, rec.Type+" "+rec.Value())
							}
						}
						if len(holds) == 0 {
							continue
						}
						slices.Sort(holds)
						if seen[name] == nil {
							seen[name] = &unlisted{Name: name, Records: holds}
						}
						seen[name].OnlyOn = append(seen[name].OnlyOn, v.server)
					}
				}
			}
			for _, u := range seen {
				if len(u.OnlyOn) == len(views) {
					u.OnlyOn = nil
				}
				out.Unlisted = append(out.Unlisted, *u)
			}
			slices.SortFunc(out.Unlisted, func(a, b unlisted) int { return strings.Compare(nameOrder(a.Name), nameOrder(b.Name)) })
		}

		return nil, out, nil
	})
}
