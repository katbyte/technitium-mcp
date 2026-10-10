package tools

import (
	"cmp"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// The answers a server's own zones give for a name, as view.lookup finds
// them.
const (
	// nameExists: there are records at the name
	nameExists = "exists"
	// nameWildcard: there are none, and a wildcard's answer for it
	nameWildcard = "wildcard"
	// nameDisabled: the only records at the name are disabled, so it does
	// not resolve though it looks as if it should
	nameDisabled = "disabled"
	// nameDelegated: the name is under a part of the zone handed to other
	// name servers
	nameDelegated = "delegated"
	// nameMissing: a zone here is where the name belongs, and has nothing
	// for it
	nameMissing = "missing"
	// nameNoZone: no zone here holds the name, so the server resolves it
	// like any name that is not its own
	nameNoZone = "no_zone"
)

// maxChain is how many names a chain of CNAMEs is followed through: more is
// a loop, or as good as one.
const maxChain = 16

// viewZone is one zone of a server as a name is looked up in it.
type viewZone struct {
	name string
	// records are the zone's records by the name they are at
	records map[string][]*technitium.Record
	// names are every name with a record and every name above one: a name
	// with nothing at it and something under it exists all the same
	names map[string]bool
}

// view is one server's zones as it answers from them: what a name looked up
// there finds, without asking the server. It is how the tools that check
// many names, or every record, read each zone once.
type view struct {
	server string
	// zones are longest name first, so the first that holds a name is the
	// closest
	zones []*viewZone
}

// signing reports whether a record type is one DNSSEC keeps beside the
// records it signs: it is at a name without being an answer for it.
func signing(recordType string) bool {
	switch recordType {
	case "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DNSKEY":
		return true
	default:
		return false
	}
}

// viewOf is the view of one server in an inventory.
func viewOf(inv *inventory, server string) *view {
	v := &view{server: server}
	for _, zone := range inv.zones {
		for c := range zone.copies {
			if zone.copies[c].server != server {
				continue
			}
			vz := &viewZone{name: cleanName(zone.name), records: map[string][]*technitium.Record{}, names: map[string]bool{}}
			for i := range zone.copies[c].records {
				rec := &zone.copies[c].records[i]
				if signing(rec.Type) {
					continue
				}
				name := cleanName(rec.Name)
				vz.records[name] = append(vz.records[name], rec)
				for at := name; at != vz.name && strings.HasSuffix(at, "."+vz.name); _, at, _ = strings.Cut(at, ".") {
					vz.names[at] = true
				}
			}
			vz.names[vz.name] = true
			v.zones = append(v.zones, vz)
		}
	}
	slices.SortFunc(v.zones, func(a, b *viewZone) int { return cmp.Compare(len(b.name), len(a.name)) })

	return v
}

// zoneFor is the closest zone the server holds for a name, nil when it holds
// none.
func (v *view) zoneFor(name string) *viewZone {
	for _, z := range v.zones {
		if name == z.name || strings.HasSuffix(name, "."+z.name) {
			return z
		}
	}

	return nil
}

// nameAnswer is what a server's own zones give for a name.
type nameAnswer struct {
	status string
	// zone is the zone the name belongs in, "" when the server holds none
	zone string
	// records answer for the name: the ones at it, or a wildcard's
	records []*technitium.Record
	// wildcard is the wildcard name that answers, and delegated the name the
	// zone hands on from
	wildcard, delegated string
}

// enabled are the records of a list that are not disabled.
func enabled(records []*technitium.Record) []*technitium.Record {
	out := make([]*technitium.Record, 0, len(records))
	for _, rec := range records {
		if !rec.Disabled {
			out = append(out, rec)
		}
	}

	return out
}

// lookup is what the server's own zones give for a name, by the rules a name
// server answers by: the records at the name; or, with none there, a
// delegation above it; or the wildcard at the closest name above it that
// exists; or nothing.
func (v *view) lookup(name string) nameAnswer {
	name = cleanName(name)
	z := v.zoneFor(name)
	if z == nil {
		return nameAnswer{status: nameNoZone}
	}
	out := nameAnswer{zone: z.name}

	// a part of the zone handed to other name servers answers for
	// everything under it, whatever else is there
	for at := name; at != z.name; _, at, _ = strings.Cut(at, ".") {
		if at != name && slices.ContainsFunc(enabled(z.records[at]), func(r *technitium.Record) bool { return r.Type == "NS" }) {
			out.status, out.delegated = nameDelegated, at

			return out
		}
	}

	if at := z.records[name]; len(at) > 0 {
		out.records = enabled(at)
		out.status = nameExists
		if len(out.records) == 0 {
			out.status, out.records = nameDisabled, at
		}

		return out
	}
	// a name with nothing at it and something under it exists, and no
	// wildcard answers for a name that exists
	if z.names[name] {
		out.status = nameMissing

		return out
	}

	// the wildcard that answers is the one at the closest name above that exists
	encloser := name
	for encloser != z.name && !z.names[encloser] {
		_, encloser, _ = strings.Cut(encloser, ".")
	}
	if wild := enabled(z.records["*."+encloser]); len(wild) > 0 {
		out.status, out.wildcard, out.records = nameWildcard, "*."+encloser, wild

		return out
	}
	out.status = nameMissing

	return out
}

// resolved is where a name ends when its CNAMEs are followed through the
// server's own zones.
type resolved struct {
	nameAnswer

	// chain is each name the lookup passed through after the first
	chain []string
	// ends are the addresses it ends at
	ends []string
	// problem is why it ends nowhere, when it does: a target with no
	// record, a loop, a target in no zone here
	problem string
}

// resolve looks a name up and follows the CNAME it finds, and the next, to
// the addresses at the end - as far as the server's own zones go.
func (v *view) resolve(name string) resolved {
	out := resolved{nameAnswer: v.lookup(name)}
	at, seen := out.nameAnswer, map[string]bool{cleanName(name): true}
	for {
		var alias *technitium.Record
		for _, rec := range at.records {
			if addr, ok := rec.Address(); ok && !rec.Disabled {
				out.ends = append(out.ends, addr.String())
			}
			if aliases(rec.Type) && !rec.Disabled && alias == nil {
				alias = rec
			}
		}
		if alias == nil || len(out.ends) > 0 {
			slices.Sort(out.ends)

			return out
		}

		target := cleanName(alias.Target())
		out.chain = append(out.chain, target)
		if seen[target] || len(out.chain) > maxChain {
			out.problem = "the chain loops back to " + target

			return out
		}
		seen[target] = true
		at = v.lookup(target)
		switch at.status {
		case nameNoZone:
			out.problem = target + " is in no zone here, so where it ends is not this server's to say"

			return out
		case nameMissing:
			out.problem = target + " has no record in " + at.zone

			return out
		case nameDisabled:
			out.problem = target + " has only disabled records"

			return out
		case nameDelegated:
			out.problem = target + " is under " + at.delegated + ", which is delegated to other name servers"

			return out
		default:
		}
	}
}
