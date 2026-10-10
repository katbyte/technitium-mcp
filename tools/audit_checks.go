package tools

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/katbyte/go-kt/spelling"
	"github.com/katbyte/go-kt/whitespace"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

const (
	// chainMost is how many CNAMEs a name may take to reach an address
	// before it is a long chain
	chainMost = 4
	// differMost is how many of a zone's differing records a finding names
	differMost = 5
	// ttlShort and ttlLong are the TTLs under and over which one is said
	ttlShort = 60
	ttlLong  = 7 * 24 * 3600
	// normMost is how many records a zone needs before one of them can be
	// said to stand apart from the rest, and ttlApart how many times its
	// TTL must be the usual one's, or the usual one its
	normMost = 5
	ttlApart = 10
	// placeFew is how many addresses of the other kind a zone may hold and
	// have them said to be out of place
	placeFew = 2
)

// auditServers finds where the servers asked do not hold the same.
func auditServers(a *audited) []finding {
	var found []finding
	for _, zone := range a.inv.zones {
		holders := make([]string, 0, len(zone.copies))
		var primaries []string
		for i := range zone.copies {
			c := &zone.copies[i]
			holders = append(holders, c.server)
			if c.zone.Type == technitium.ZonePrimary {
				primaries = append(primaries, c.server)
			}
			if c.zone.SyncFailed {
				found = append(found, finding{Problem: "sync_failed", Zone: zone.name, Servers: []string{c.server}, Detail: fmt.Sprintf("%s holds %s as a %s zone and its last transfer from the primary failed", c.server, zone.name, c.zone.Type), Fix: "see that the primary allows the transfer from " + c.server + " and can be reached from it; the zone's options on the primary say who may transfer"})
			}
			if c.zone.IsExpired {
				found = append(found, finding{Problem: "copy_expired", Zone: zone.name, Servers: []string{c.server}, Detail: fmt.Sprintf("%s holds %s as a %s zone that has expired: it answers nothing from it", c.server, zone.name, c.zone.Type), Fix: "get a transfer through: the copy is served again once one succeeds"})
			}
			if c.zone.NotifyFailed {
				found = append(found, finding{Problem: "notify_failed", Zone: zone.name, Servers: []string{c.server}, Detail: fmt.Sprintf("%s could not tell %s that %s had changed", c.server, strings.Join(c.zone.NotifyFailedFor, ", "), zone.name), Fix: "a secondary that is not told waits for its own refresh: see that it can be reached from " + c.server})
			}
		}

		var missing []string
		for _, asked := range a.inv.asked {
			if !slices.Contains(holders, asked) {
				missing = append(missing, asked)
			}
		}
		if len(missing) > 0 {
			found = append(found, finding{Problem: "zone_missing", Zone: zone.name, Servers: holders, Detail: fmt.Sprintf("%s is on %s and not on %s", zone.name, strings.Join(holders, ", "), strings.Join(missing, ", ")), Fix: a.missingFix(zone, missing)})
		}
		if len(primaries) > 1 {
			found = append(found, finding{Problem: "two_primaries", Zone: zone.name, Servers: primaries, Detail: fmt.Sprintf("%s each hold %s as a primary zone of their own: a change made on one does not reach the other", strings.Join(primaries, " and "), zone.name), Fix: "keep one as the primary and make the other a secondary of it, or in a cluster make the zone a member of the cluster's catalog; until then every change is made on each"})
		}

		// a copy against the primary it is a copy of, when both were asked
		for i := range zone.copies {
			c := &zone.copies[i]
			if !c.copied || len(primaries) != 1 {
				continue
			}
			primary := zone.copies[slices.IndexFunc(zone.copies, func(o zoneCopy) bool { return o.server == primaries[0] })]
			if c.zone.SOASerial != primary.zone.SOASerial {
				found = append(found, finding{Problem: "copy_behind", Zone: zone.name, Servers: []string{c.server}, Detail: fmt.Sprintf("%s holds %s at serial %d and its primary %s is at %d", c.server, zone.name, c.zone.SOASerial, primary.server, primary.zone.SOASerial), Fix: "a copy catches up by itself within its refresh time; one that stays behind has failed to transfer"})
			}
		}

		if len(zone.copies) < 2 {
			continue
		}
		rows, _ := mergeRecords(zone.copies, recordFilter{}, false)
		var differ []string
		for i := range rows {
			// each server's SOA is its own to differ in: its serial and its name for itself
			if row := &rows[i]; row.OnlyOn != nil && row.Type != "SOA" {
				differ = append(differ, fmt.Sprintf("%s %s %s (ttl %d) on %s alone", row.Name, row.Type, row.Value, row.TTL, strings.Join(row.OnlyOn, ", ")))
			}
		}
		if len(differ) > 0 {
			detail := fmt.Sprintf("%d records of %s are not the same on %s: %s", len(differ), zone.name, strings.Join(holders, " and "), strings.Join(differ[:min(len(differ), differMost)], "; "))
			if len(differ) > differMost {
				detail += fmt.Sprintf("; and %d more", len(differ)-differMost)
			}
			found = append(found, finding{Problem: "records_differ", Zone: zone.name, Detail: detail, Fix: "zone_records gives every record with the servers that hold it: a record on one server alone is added on the other or removed"})
		}
	}

	return found
}

// missingFix is what would give a zone to the servers that lack it: in a
// cluster, making it a member of the catalog they follow.
func (a *audited) missingFix(zone *inventoryZone, missing []string) string {
	for i := range zone.copies {
		c := &zone.copies[i]
		if c.zone.Type != technitium.ZonePrimary || c.zone.Catalog != "" {
			continue
		}
		for _, catalog := range a.inv.catalogs[c.server] {
			if catalog.Type != technitium.ZoneCatalog {
				continue
			}
			follows := true
			for _, m := range missing {
				if !slices.ContainsFunc(a.inv.catalogs[m], func(z technitium.Zone) bool {
					return sameName(z.Name, catalog.Name) && z.Type == technitium.ZoneSecondaryCatalog
				}) {
					follows = false
				}
			}
			if follows {
				return fmt.Sprintf("%s holds the catalog %s, which %s follows, and this zone is not a member of it: made a member, in its options on %s, it is given to %s as a secondary", c.server, catalog.Name, strings.Join(missing, ", "), c.server, strings.Join(missing, ", "))
			}
		}
	}

	return "if " + strings.Join(missing, ", ") + " should answer for it too, make it a secondary of the zone there; if not, nothing is wrong"
}

// auditTargets finds the records that point at a name and end nowhere.
func auditTargets(a *audited) []finding {
	return a.perServer(func(v *view) []finding {
		var found []finding
		for _, z := range v.zones {
			for name, records := range z.records {
				live := enabled(records)
				cname := slices.IndexFunc(live, func(r *technitium.Record) bool { return r.Type == "CNAME" })
				if cname >= 0 {
					if name == z.name {
						found = append(found, finding{Problem: "cname_at_apex", Zone: z.name, Name: name, Detail: name + " is its zone's own name and has a CNAME to " + live[cname].Target() + ": a zone's SOA and NS records are at that name, and a CNAME may share it with nothing", Fix: "use an ANAME, which answers with the target's addresses, or address records"})
					}
					var beside []string
					for _, rec := range live {
						// a zone's own name always has its SOA and NS: said above
						if rec.Type != "CNAME" && name != z.name {
							beside = append(beside, rec.Type+" "+rec.Value())
						}
					}
					if len(beside) > 0 {
						slices.Sort(beside)
						found = append(found, finding{Problem: "cname_with_others", Zone: z.name, Name: name, Detail: name + " has a CNAME to " + live[cname].Target() + " and beside it " + strings.Join(beside, ", ") + ": a resolver that follows the CNAME never sees the rest", Fix: "keep the CNAME or the other records, not both"})
					}
				}

				for _, rec := range live {
					target := cleanName(rec.Target())
					switch {
					case aliases(rec.Type):
						res := v.resolve(name)
						switch {
						case strings.Contains(res.problem, "loops"):
							found = append(found, finding{Problem: "loop", Zone: z.name, Name: name, Detail: name + " leads through " + strings.Join(res.chain, " > ") + ": " + res.problem, Fix: "point one of the names in the loop at where they should all end"})
						case strings.Contains(res.problem, "has no record") || strings.Contains(res.problem, "only disabled"):
							found = append(found, finding{Problem: "dangling", Zone: z.name, Name: name, Detail: name + " is a " + rec.Type + " that leads through " + strings.Join(res.chain, " > ") + ", and " + res.problem, Fix: "add the missing record, point " + name + " at a name that has one, or remove it"})
						case res.problem == "" && len(res.chain) > chainMost:
							found = append(found, finding{Problem: "long_chain", Zone: z.name, Name: name, Detail: fmt.Sprintf("%s takes %d CNAMEs to reach an address: %s", name, len(res.chain), strings.Join(res.chain, " > ")), Fix: "point it straight at the last name"})
						default:
						}
					case rec.Type == "MX" || rec.Type == "SRV" || rec.Type == "NS":
						at := v.lookup(target)
						switch at.status {
						case nameMissing, nameDisabled:
							found = append(found, finding{Problem: "target_missing", Zone: z.name, Name: name, Detail: fmt.Sprintf("the %s at %s names %s, which has no record in %s", rec.Type, name, target, at.zone), Fix: "add an address for " + target + ", or name a host that has one"})
						case nameExists:
							if slices.ContainsFunc(at.records, func(r *technitium.Record) bool { return r.Type == "CNAME" }) {
								found = append(found, finding{Problem: "target_is_cname", Zone: z.name, Name: name, Detail: fmt.Sprintf("the %s at %s names %s, which is a CNAME: an %s may only name a host with an address of its own", rec.Type, name, target, rec.Type), Fix: "name the host the CNAME leads to"})
							}
						default:
						}
					default:
					}
				}
			}
		}

		return found
	})
}

// reverseAddr reads the address a PTR record's own name stands for, IPv4 or
// IPv6.
func reverseAddr(name string) (netip.Addr, bool) {
	if labels, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		parts := strings.Split(labels, ".")
		if len(parts) != 4 {
			return netip.Addr{}, false
		}
		slices.Reverse(parts)

		return parseAddr(strings.Join(parts, "."))
	}
	labels, ok := strings.CutSuffix(name, ".ip6.arpa")
	if !ok {
		return netip.Addr{}, false
	}
	nibbles := strings.Split(labels, ".")
	if len(nibbles) != 32 {
		return netip.Addr{}, false
	}
	slices.Reverse(nibbles)
	var text strings.Builder
	for i, nibble := range nibbles {
		if i > 0 && i%4 == 0 {
			text.WriteByte(':')
		}
		text.WriteString(nibble)
	}

	return parseAddr(text.String())
}

// subnetOf is the network an address is counted in when no reverse zone
// holds it: its /24, or for IPv6 its /64.
func subnetOf(addr netip.Addr) netip.Prefix {
	bits := 24
	if addr.Is6() {
		bits = 64
	}
	prefix, _ := addr.Prefix(bits)

	return prefix
}

// reverseZoneFor is the name of the reverse zone that would hold a /24's PTR
// records: the form a tool that makes one is given.
func reverseZoneFor(prefix netip.Prefix) string {
	if !prefix.Addr().Is4() {
		return prefix.String()
	}
	_, zone, _ := strings.Cut(reverseName(prefix.Addr()), ".")

	return zone
}

// auditReverse finds where addresses and their PTR records do not agree.
func auditReverse(a *audited) []finding {
	return a.perServer(func(v *view) []finding {
		var found []finding

		// every address a name holds, and the PTR records there are
		holders := map[netip.Addr][]string{}
		var order []netip.Addr
		for _, z := range v.zones {
			for name, records := range z.records {
				for _, rec := range enabled(records) {
					if addr, ok := rec.Address(); ok && !strings.HasPrefix(name, "*.") {
						if holders[addr] == nil {
							order = append(order, addr)
						}
						holders[addr] = append(holders[addr], name)
					}
					if rec.Type != "PTR" {
						continue
					}
					addr, ok := reverseAddr(name)
					host := cleanName(rec.Target())
					at := v.lookup(host)
					if !ok || at.status == nameNoZone || at.status == nameDelegated {
						continue
					}
					var has []string
					for _, held := range at.records {
						if heldAddr, isAddr := held.Address(); isAddr {
							has = append(has, heldAddr.String())
						}
					}
					if slices.Contains(has, addr.String()) {
						continue
					}
					what := "has no address record"
					if len(has) > 0 {
						what = "holds " + strings.Join(has, ", ")
					}
					found = append(found, finding{Problem: "ptr_stale", Zone: z.name, Name: name, Detail: fmt.Sprintf("the PTR for %s names %s, which %s", addr, host, what), Fix: "point it at the host that holds " + addr.String() + ", or remove it"})
				}
			}
		}
		slices.SortFunc(order, func(x, y netip.Addr) int { return x.Compare(y) })

		subnets := map[netip.Prefix][]string{}
		var subnetOrder []netip.Prefix
		for _, addr := range order {
			names := holders[addr]
			slices.Sort(names)
			at := v.lookup(reverseName(addr))
			switch at.status {
			case nameNoZone:
				// an address of someone else's has its reverse zone with them
				if !addr.IsPrivate() {
					continue
				}
				subnet := subnetOf(addr)
				if subnets[subnet] == nil {
					subnetOrder = append(subnetOrder, subnet)
				}
				subnets[subnet] = append(subnets[subnet], addr.String())
			case nameMissing, nameDisabled:
				found = append(found, finding{Problem: "no_ptr", Zone: at.zone, Name: reverseName(addr), Detail: fmt.Sprintf("%s is held by %s and has no PTR record", addr, strings.Join(names, ", ")), Fix: "record_set name=" + reverseName(addr) + " type=PTR value=" + names[0]})
			case nameExists:
				var named []string
				for _, rec := range at.records {
					if rec.Type == "PTR" {
						named = append(named, cleanName(rec.Target()))
					}
				}
				if len(named) > 1 {
					found = append(found, finding{Problem: "several_ptrs", Zone: at.zone, Name: reverseName(addr), Detail: fmt.Sprintf("%s has %d PTR records, naming %s: which a lookup gets is not said", addr, len(named), strings.Join(named, ", ")), Fix: "keep the one for the host's own name"})
				}
				if len(named) > 0 && !slices.ContainsFunc(named, func(n string) bool { return slices.Contains(names, n) }) {
					found = append(found, finding{Problem: "ptr_elsewhere", Zone: at.zone, Name: reverseName(addr), Detail: fmt.Sprintf("%s is held by %s and its PTR names %s", addr, strings.Join(names, ", "), strings.Join(named, ", ")), Fix: "point the PTR at one of the names that hold the address"})
				}
			default:
			}
		}
		for _, subnet := range subnetOrder {
			addrs := subnets[subnet]
			detail := fmt.Sprintf("%d addresses in %s are held by records and no reverse zone here holds their PTRs: %s", len(addrs), subnet, strings.Join(addrs[:min(len(addrs), differMost)], ", "))
			if len(addrs) > differMost {
				detail += fmt.Sprintf(" and %d more", len(addrs)-differMost)
			}
			found = append(found, finding{Problem: "no_reverse_zone", Zone: reverseZoneFor(subnet), Detail: detail, Fix: "make the reverse zone for " + subnet.String() + " and give each address its PTR, or leave it if nothing looks these addresses up"})
		}

		return found
	})
}

// auditOverlaps finds records that are never served or probably not meant.
func auditOverlaps(a *audited) []finding {
	return a.perServer(func(v *view) []finding {
		var found []finding
		for _, z := range v.zones {
			for name, records := range z.records {
				live := enabled(records)
				if len(live) == 0 {
					continue
				}
				// the closest zone for the name answers for it: a record of the
				// same name in a zone above never does. The NS and DS records
				// that hand the lower zone over are what belong there
				if closest := v.zoneFor(name); closest != z {
					var never []string
					for _, rec := range live {
						if name == closest.name && (rec.Type == "NS" || rec.Type == "DS") {
							continue
						}
						never = append(never, rec.Type+" "+rec.Value())
					}
					if len(never) > 0 {
						slices.Sort(never)
						found = append(found, finding{Problem: "shadowed", Zone: z.name, Name: name, Detail: fmt.Sprintf("%s has records in %s (%s), and the server also holds the zone %s, which answers for that name instead: these are never served", name, z.name, strings.Join(never, ", "), closest.name), Fix: "move them into " + closest.name + " if they are meant, or remove them"})
					}
				}

				if strings.HasPrefix(name, "*.") {
					var gives []string
					for _, rec := range live {
						gives = append(gives, rec.Type+" "+rec.Value())
					}
					slices.Sort(gives)
					found = append(found, finding{Problem: "wildcard", Zone: z.name, Name: name, Detail: fmt.Sprintf("every name under %s with no record of its own is answered with %s: a mistyped name resolves, and a name removed goes on resolving", strings.TrimPrefix(name, "*."), strings.Join(gives, ", ")), Fix: "nothing, if it is meant: it is listed so that it is known"})
				}

				var nets []string
				for _, rec := range live {
					if addr, ok := rec.Address(); ok && addr.Is4() {
						if net := subnetOf(addr).String(); !slices.Contains(nets, net) {
							nets = append(nets, net)
						}
					}
				}
				if len(nets) > 1 {
					slices.Sort(nets)
					found = append(found, finding{Problem: "addresses_apart", Zone: z.name, Name: name, Detail: fmt.Sprintf("%s has addresses in %s: a client is given all of them and uses any", name, strings.Join(nets, " and ")), Fix: "keep the address the host really has, unless it is on both networks on purpose"})
				}
			}
			found = append(found, outOfPlace(z)...)
		}

		return found
	})
}

// sortedNames are the names of a zone that have records, in order, so that
// what is found in it comes out the same way every time.
func sortedNames(z *viewZone) []string {
	names := make([]string, 0, len(z.records))
	for name := range z.records {
		names = append(names, name)
	}
	slices.Sort(names)

	return names
}

// outOfPlace finds the few public addresses in a zone of private ones, or
// the few private ones in a zone of public: probably not meant, and in a
// zone the outside is served, the inside's addressing published.
func outOfPlace(z *viewZone) []finding {
	type held struct {
		name string
		addr netip.Addr
	}
	var local, global []held
	for _, name := range sortedNames(z) {
		for _, rec := range enabled(z.records[name]) {
			addr, ok := rec.Address()
			switch {
			case !ok || !addr.Is4() || strings.HasPrefix(name, "*."):
			case addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast():
				local = append(local, held{name: name, addr: addr})
			default:
				global = append(global, held{name: name, addr: addr})
			}
		}
	}
	few, many, kind, rest := global, local, "public", "private"
	if len(local) < len(global) {
		few, many, kind, rest = local, global, "private", "public"
	}
	if len(few) == 0 || len(few) > placeFew || len(many) < normMost {
		return nil
	}

	found := make([]finding, 0, len(few))
	for _, h := range few {
		found = append(found, finding{Problem: "address_out_of_place", Zone: z.name, Name: h.name, Detail: fmt.Sprintf("%s holds %s, a %s address, in a zone whose %d other addresses are %s", h.name, h.addr, kind, len(many), rest), Fix: "nothing, if it is meant - a gateway's outside address, say; a mistyped address, or one that belongs in another zone, is put right"})
	}

	return found
}

// ttlOutliers finds the records of a zone whose TTL is far from the one
// nearly all its records have: ten times it or a tenth of it. The records
// that hold an address or a CNAME are the ones counted, the zone's own SOA
// and NS having times of their own.
func ttlOutliers(z *viewZone) []finding {
	counts := map[int]int{}
	total := 0
	for _, records := range z.records {
		for _, rec := range records {
			if _, isAddr := rec.Address(); (isAddr || rec.Type == "CNAME") && rec.TTL > 0 {
				counts[rec.TTL]++
				total++
			}
		}
	}
	usual := 0
	for ttl, n := range counts {
		if n > counts[usual] || (n == counts[usual] && ttl < usual) {
			usual = ttl
		}
	}
	// a zone needs a usual TTL to have one that stands apart from it: most of enough records
	if total < normMost || counts[usual]*5 < total*3 {
		return nil
	}

	var found []finding
	for _, name := range sortedNames(z) {
		for _, rec := range z.records[name] {
			_, isAddr := rec.Address()
			apart := rec.TTL >= usual*ttlApart || rec.TTL*ttlApart <= usual
			// a TTL under a minute or over a week is said for itself already
			if (!isAddr && rec.Type != "CNAME") || !apart || rec.TTL < ttlShort || rec.TTL > ttlLong {
				continue
			}
			found = append(found, finding{Problem: "ttl_outlier", Zone: z.name, Name: name, Detail: fmt.Sprintf("the %s at %s has a TTL of %d seconds, where %d of the zone's %d such records have %d", rec.Type, name, rec.TTL, counts[usual], total, usual), Fix: "set it to " + strconv.Itoa(usual) + " unless it is meant: a TTL lowered for a change and never raised again is the usual cause"})
		}
	}

	return found
}

// namedTwoWays finds a host's names made two ways in one zone: one written
// with a hyphen, as emby-dock, where the same host's other names are written
// under it with a dot, as jf.dock.
func namedTwoWays(z *viewZone) []finding {
	// the names that have names under them, each with one of those
	under := map[string]string{}
	for _, name := range sortedNames(z) {
		if _, parent, ok := strings.Cut(name, "."); ok && parent != z.name && !strings.HasPrefix(name, "*.") && under[parent] == "" {
			under[parent] = name
		}
	}

	var found []finding
	for _, name := range sortedNames(z) {
		label, rest, ok := strings.Cut(name, ".")
		if !ok || strings.HasPrefix(label, "*") || !strings.Contains(label, "-") || !slices.ContainsFunc(z.records[name], func(rec *technitium.Record) bool {
			_, isAddr := rec.Address()

			return isAddr || rec.Type == "CNAME"
		}) {
			continue
		}
		// the host is the part before the first hyphen, or the part after the last
		first, _, _ := strings.Cut(label, "-")
		last := label[strings.LastIndex(label, "-")+1:]
		for _, host := range []string{first, last} {
			if dotted := under[host+"."+rest]; host != "" && dotted != "" {
				found = append(found, finding{Problem: "named_two_ways", Zone: z.name, Name: name, Detail: fmt.Sprintf("%s is written with a hyphen, and %s has names written under it with a dot, as %s: one host's names made two ways", name, host+"."+rest, dotted), Fix: "name them one way, if they are the same kind of thing; nothing, if " + label + " is a name of its own"})

				break
			}
		}
	}

	return found
}

// underscored reports whether a host's name has an underscore that does not
// belong: anywhere but at the start of a label, where one names a service
// (_sip._tcp, _dmarc, _acme-challenge) and is as it should be.
func underscored(name string) bool {
	for label := range strings.SplitSeq(name, ".") {
		if strings.Contains(strings.TrimPrefix(label, "_"), "_") {
			return true
		}
	}

	return false
}

// numbered reports whether two names differ only in their digits: host1 and
// host2 are two hosts, not one mistyped.
func numbered(a, b string) bool {
	strip := func(s string) string {
		return strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) {
				return -1
			}

			return r
		}, s)
	}

	if strip(a) == strip(b) {
		return true
	}

	// pimox5a and pimox5b: one run of hosts, lettered after a number
	ra, rb := []rune(a), []rune(b)
	if len(ra) != len(rb) || len(ra) < 2 {
		return false
	}
	last := len(ra) - 1

	return string(ra[:last]) == string(rb[:last]) && unicode.IsDigit(ra[last-1]) && unicode.IsLetter(ra[last]) && unicode.IsLetter(rb[last])
}

// auditNaming finds names and values that are probably slips.
func auditNaming(a *audited) []finding {
	return a.perServer(func(v *view) []finding {
		var found []finding
		for _, z := range v.zones {
			// the names that are hosts, by the name above each, for the slips
			siblings := map[string][]string{}
			for name, records := range z.records {
				holdsAddress := false
				for _, rec := range records {
					if _, isAddr := rec.Address(); isAddr || rec.Type == "CNAME" {
						holdsAddress = true
					}
					for what, text := range map[string]string{"name": rec.Name, "value": rec.Value(), "comment": rec.Comments} {
						// a TXT record's value is free text, its spaces its own,
						// and an SOA's is the server's to write
						if text == "" || (what == "value" && (rec.Type == "TXT" || rec.Type == "SOA")) {
							continue
						}
						problems := whitespace.Problems(text, whitespace.Name)
						if what == "name" && strings.ContainsFunc(text, whitespace.Any) && len(problems) == 0 {
							problems = []string{"space"}
						}
						if len(problems) > 0 {
							found = append(found, finding{Problem: "space", Zone: z.name, Name: name, Detail: fmt.Sprintf("the %s of the %s record at %s has %s: %q", what, rec.Type, name, strings.ReplaceAll(strings.Join(problems, ", "), "_", " "), whitespace.Visible(text, whitespace.Name)), Fix: fmt.Sprintf("it should read %q", whitespace.Fixed(text, whitespace.Name))})
						}
					}
					if rec.Type != "SOA" && rec.TTL > 0 && rec.TTL < ttlShort {
						found = append(found, finding{Problem: "ttl_short", Zone: z.name, Name: name, Detail: fmt.Sprintf("the %s at %s has a TTL of %d seconds: every client asks again within the minute", rec.Type, name, rec.TTL), Fix: "raise it once the record has stopped changing"})
					}
					if rec.Type != "SOA" && rec.TTL > ttlLong {
						found = append(found, finding{Problem: "ttl_long", Zone: z.name, Name: name, Detail: fmt.Sprintf("the %s at %s has a TTL of %s: a change to it is not seen until that has passed", rec.Type, name, days(rec.TTL)), Fix: "lower it well before the record next changes"})
					}
				}
				if holdsAddress {
					if underscored(name) {
						found = append(found, finding{Problem: "underscore", Zone: z.name, Name: name, Detail: name + " holds an address or a CNAME and has an underscore in its name, which a host's name may not: browsers and certificates refuse it", Fix: "use a hyphen"})
					}
					if label, parent, ok := strings.Cut(name, "."); ok && !strings.HasPrefix(label, "*") {
						siblings[parent] = append(siblings[parent], label)
					}
				}
			}

			found = append(found, ttlOutliers(z)...)
			found = append(found, namedTwoWays(z)...)

			for parent, labels := range siblings {
				slices.Sort(labels)
				for i, one := range labels {
					for _, other := range labels[i+1:] {
						if spelling.TypoApart(spelling.Key(one), spelling.Key(other)) && !numbered(one, other) {
							found = append(found, finding{Problem: "near_duplicate", Zone: z.name, Name: one + "." + parent, Detail: fmt.Sprintf("%s.%s and %s.%s differ by a slip of the keyboard", one, parent, other, parent), Fix: "if one is a misspelling of the other, remove it"})
						}
					}
				}
			}
		}

		return found
	})
}

// days is a number of seconds in days, to one decimal.
func days(seconds int) string {
	return strconv.FormatFloat(float64(seconds)/86400, 'f', 1, 64) + " days"
}

// auditState lists what is switched off or set to vanish.
func auditState(a *audited) []finding {
	var found []finding
	for _, zone := range a.inv.zones {
		var disabledOn []string
		for i := range zone.copies {
			if zone.copies[i].zone.Disabled {
				disabledOn = append(disabledOn, zone.copies[i].server)
			}
		}
		if len(disabledOn) > 0 {
			f := finding{Problem: "zone_disabled", Zone: zone.name, Detail: zone.name + " is disabled: the server holds it and answers nothing from it", Fix: "enable it, or delete it if it is not coming back"}
			if len(disabledOn) != len(a.inv.asked) {
				f.Servers = disabledOn
			}
			found = append(found, f)
		}
	}

	return append(found, a.perServer(func(v *view) []finding {
		var found []finding
		for _, z := range v.zones {
			for name, records := range z.records {
				for _, rec := range records {
					if rec.Disabled {
						found = append(found, finding{Problem: "record_disabled", Zone: z.name, Name: name, Detail: fmt.Sprintf("the %s %s at %s is disabled: the server holds it and does not answer with it", rec.Type, rec.Value(), name), Fix: "enable it with record_set, or delete it"})
					}
					if rec.ExpiryTTL > 0 {
						found = append(found, finding{Problem: "record_expires", Zone: z.name, Name: name, Detail: fmt.Sprintf("the %s %s at %s deletes itself %s after its last change", rec.Type, rec.Value(), name, days(rec.ExpiryTTL)), Fix: "nothing, if that is meant"})
					}
				}
			}
		}

		return found
	})...)
}
