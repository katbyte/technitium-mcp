package tools

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/katbyte/go-kt/parallel"
	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// zoneReaders is how many of a server's zones are read at once.
const zoneReaders = 4

// zoneProblem is a zone a server lists and would not give the records of.
type zoneProblem struct {
	Server string `json:"server"`
	Zone   string `json:"zone"`
	Error  string `json:"error"`
}

// held is one server's zones with their records.
type held struct {
	zones    []technitium.Zone
	catalogs []technitium.Zone
	records  [][]technitium.Record
	problems []zoneProblem
}

// inventoryZone is one zone name as each server read holds it.
type inventoryZone struct {
	name string
	// copies are the servers holding the zone, in the servers' own order,
	// each with its records
	copies []zoneCopy
}

// inventory is every zone of the servers asked with every record in it,
// read once for a call: what the tools that look across zones work from.
type inventory struct {
	// asked are the servers that answered
	asked    []string
	failed   []serverFailure
	problems []zoneProblem
	// zones are in the order a zone tree reads
	zones []*inventoryZone
	// catalogs are the catalog zones each server holds, by server, each
	// with whether it is the catalog itself or a copy the server follows:
	// they are in no other list here, since nothing resolves from one
	catalogs map[string][]technitium.Zone
}

// readInventory reads every zone the servers hold that keep lets through,
// whole: the servers at once, and a few of a server's zones at a time. A
// zone a server will not give the records of is a problem said beside the
// rest; a server that cannot be asked at all is a failure; and only every
// server failing is an error.
func readInventory(ctx context.Context, picked []*servers.Server, keep func(z *technitium.Zone) bool) (*inventory, error) {
	answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (held, error) {
		zones, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
		if err != nil {
			return held{}, err
		}
		var catalogs []technitium.Zone
		for i := range zones {
			if zones[i].Type == technitium.ZoneCatalog || zones[i].Type == technitium.ZoneSecondaryCatalog {
				catalogs = append(catalogs, zones[i])
			}
		}
		zones = slices.DeleteFunc(zones, func(z technitium.Zone) bool { return !keep(&z) })

		out := held{zones: zones, catalogs: catalogs, records: make([][]technitium.Record, len(zones))}
		failed := make([]error, len(zones))
		// a zone that cannot be read is kept as that zone's own failure, and
		// the rest are read all the same
		if err := parallel.Each(ctx, len(zones), zoneReaders, func(ctx context.Context, i int) error {
			read, readErr := srv.Client.ZoneRecords(ctx, zones[i].Name)
			if failed[i] = readErr; readErr == nil {
				out.records[i] = read.Records
			}

			return nil
		}); err != nil {
			return held{}, err
		}
		for i, zoneErr := range failed {
			if zoneErr != nil {
				out.problems = append(out.problems, zoneProblem{Server: srv.Name, Zone: zones[i].Name, Error: zoneErr.Error()})
			}
		}

		return out, nil
	})
	failed, err := failures(answers)
	if err != nil {
		return nil, err
	}

	inv := &inventory{failed: failed, catalogs: map[string][]technitium.Zone{}}
	byName := map[string]*inventoryZone{}
	for _, a := range answers {
		if a.Err != nil {
			continue
		}
		inv.asked = append(inv.asked, a.Server.Name)
		inv.problems = append(inv.problems, a.Value.problems...)
		inv.catalogs[a.Server.Name] = a.Value.catalogs
		for i := range a.Value.zones {
			z := &a.Value.zones[i]
			if slices.ContainsFunc(a.Value.problems, func(p zoneProblem) bool { return p.Zone == z.Name }) {
				continue
			}
			key := strings.ToLower(z.Name)
			if byName[key] == nil {
				byName[key] = &inventoryZone{name: z.Name}
				inv.zones = append(inv.zones, byName[key])
			}
			byName[key].copies = append(byName[key].copies, zoneCopy{server: a.Server.Name, copied: isCopy(z.Type), records: a.Value.records[i], zone: *z})
		}
	}
	slices.SortFunc(inv.zones, func(a, b *inventoryZone) int { return cmp.Compare(nameOrder(a.name), nameOrder(b.name)) })

	return inv, nil
}

// served reports whether a zone is one a server answers names from: not one
// it made for its own use, and not a catalog, whose records are the list of
// its member zones kept as PTR and TXT records - bookkeeping that points at
// every zone it lists, and nothing anyone resolves.
func served(z *technitium.Zone) bool {
	return !z.Internal && z.Type != technitium.ZoneCatalog && z.Type != technitium.ZoneSecondaryCatalog
}

// cleanName is a domain name as two are compared: lower case, with no dot at
// its end.
func cleanName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// reverseName is the name the PTR record for an address is at:
// 4.0.0.10.in-addr.arpa for 10.0.0.4, and for an IPv6 address its 32 hex
// digits backwards under ip6.arpa.
func reverseName(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()

		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0])) + ".in-addr.arpa"
	}

	const hex = "0123456789abcdef"
	b := addr.As16()
	parts := make([]string, 0, 32)
	for i := 15; i >= 0; i-- {
		parts = append(parts, string(hex[b[i]&0xf]), string(hex[b[i]>>4]))
	}

	return strings.Join(parts, ".") + ".ip6.arpa"
}

// parseAddr reads an IPv4 or IPv6 address, reporting false for anything
// else.
func parseAddr(text string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(text))

	return addr, err == nil
}

// aliases reports whether a record of this type makes its own name another
// name for its target, so that what points at the one ends at the other: a
// CNAME does, and Technitium's ANAME; an MX or an NS names a host and stays
// what it is.
func aliases(recordType string) bool {
	return recordType == "CNAME" || recordType == "ANAME"
}
