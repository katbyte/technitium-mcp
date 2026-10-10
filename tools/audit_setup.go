package tools

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// tokenIdle is how long an API token may go unused before it is said to be.
const tokenIdle = 90 * 24 * time.Hour

// setupRead is what one server says of itself and of how each of its zones
// is served, for the audits of that and of what is left open.
type setupRead struct {
	// name is the server's own domain name
	name string
	// options are each zone's, by the zone's name; a zone whose options
	// would not be read has none
	options map[string]*technitium.ZoneOptions
	// cluster is how the server stands in a cluster, nil when it would not say
	cluster *technitium.Cluster

	// read for the audit of what is left open; nil or empty for what would
	// not be read, which unread says
	settings        *technitium.Settings
	sessions        []technitium.OpenSession
	defaultPassword bool
	update          *technitium.Update
	unread          []string
}

// readSetup reads how every server asked serves each of its zones, and with
// security what each leaves open besides. What a server will not give is
// said beside the findings: nothing was found there because nothing was
// looked at.
func (a *audited) readSetup(ctx context.Context, picked []*servers.Server, security bool) {
	a.setup = map[string]*setupRead{}
	for _, answer := range ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (setupRead, error) {
		out := setupRead{options: map[string]*technitium.ZoneOptions{}}
		status, err := srv.Client.Status(ctx)
		if err != nil {
			return setupRead{}, err
		}
		out.name, out.defaultPassword = cleanName(status.Server), status.HasDefaultCredentials
		// how the server stands in a cluster names the cluster's other nodes, which are servers too, read here or not
		if state, err := srv.Client.ClusterState(ctx); err == nil {
			out.cluster = state
		}
		for _, zone := range a.inv.zones {
			for i := range zone.copies {
				if zone.copies[i].server != srv.Name {
					continue
				}
				if o, err := srv.Client.ZoneOptions(ctx, zone.copies[i].zone.Name); err == nil {
					out.options[cleanName(zone.name)] = o
				} else {
					out.unread = append(out.unread, "the options of "+zone.name+" ("+err.Error()+")")
				}
			}
		}
		if !security {
			return out, nil
		}

		if out.settings, err = srv.Client.Settings(ctx); err != nil {
			out.unread = append(out.unread, "its settings ("+err.Error()+")")
		}
		if out.sessions, err = srv.Client.Sessions(ctx); err != nil {
			out.unread = append(out.unread, "its sessions and tokens ("+err.Error()+")")
		}
		// whether a newer version is out is the server's to ask, of its maker: one that cannot is not said to be behind
		if update, err := srv.Client.CheckForUpdate(ctx); err == nil {
			out.update = update
		}

		return out, nil
	}) {
		switch {
		case !slices.Contains(a.inv.asked, answer.Server.Name):
		case answer.Err != nil:
			a.setupFailed = append(a.setupFailed, serverFailure{Server: answer.Server.Name, Error: answer.Err.Error()})
		default:
			a.setup[answer.Server.Name] = &answer.Value
			a.knows(answer.Value.cluster)
		}
	}
}

// apex are the name servers a copy of a zone names in its own NS records,
// and the primary its SOA record names.
func apex(c *zoneCopy, zone string) (nameServers []string, primary string) {
	for i := range c.records {
		rec := &c.records[i]
		if !sameName(rec.Name, zone) || rec.Disabled {
			continue
		}
		switch rec.Type {
		case "NS":
			nameServers = append(nameServers, cleanName(rec.Target()))
		case "SOA":
			primary = cleanName(rec.SOA().Primary)
		default:
		}
	}
	slices.Sort(nameServers)

	return nameServers, primary
}

// auditZones finds where a zone's own records and options do not fit the
// servers that hold it: name servers that are none of them, a holder none
// of them names, a primary the SOA does not name, and a primary that will
// not give its copies the zone or tell them it changed.
func auditZones(a *audited) []finding {
	var found []finding
	// every server asked by its own name, and every node of their cluster by its: a node that could not be read is a server all the same
	names := map[string]string{}
	for _, node := range a.nodeNames {
		names[node] = node
	}
	for server, setup := range a.setup {
		names[setup.name] = server
	}

	for _, zone := range a.inv.zones {
		var primaries, copies []*zoneCopy
		for i := range zone.copies {
			c := &zone.copies[i]
			switch {
			case a.setup[c.server] == nil:
			case c.zone.Type == technitium.ZonePrimary:
				primaries = append(primaries, c)
			case c.zone.Type == technitium.ZoneSecondary:
				copies = append(copies, c)
			default:
			}
		}

		for _, p := range primaries {
			own := a.setup[p.server].name
			nameServers, primary := apex(p, zone.name)
			for _, ns := range nameServers {
				if names[ns] == "" {
					found = append(found, finding{Problem: "ns_unknown", Zone: zone.name, Name: zone.name, Servers: []string{p.server}, Detail: fmt.Sprintf("%s names %s as a name server of its own, which is the name of no server asked: a resolver sent there for the zone finds no answer, and a transfer or a notify kept to the zone's name servers counts it in", zone.name, ns), Fix: "remove the NS record unless that server does hold the zone; record_delete name=" + zone.name + " type=NS value=" + ns})
				}
			}
			if !slices.Contains(nameServers, own) {
				found = append(found, finding{Problem: "ns_missing", Zone: zone.name, Name: zone.name, Servers: []string{p.server}, Detail: fmt.Sprintf("%s holds %s as its primary and calls itself %s, which none of the zone's NS records names: they name %s", p.server, zone.name, own, orNone(nameServers)), Fix: "record_set name=" + zone.name + " type=NS value=" + own + ": a server renamed since the zone was made leaves its old name behind"})
			}
			if primary != "" && primary != own {
				found = append(found, finding{Problem: "soa_primary", Zone: zone.name, Name: zone.name, Servers: []string{p.server}, Detail: fmt.Sprintf("the SOA record of %s names %s as the zone's primary, and the server that holds it as its primary calls itself %s", zone.name, primary, own), Fix: "set the SOA's primary name server to " + own + " in the zone's SOA record: a server renamed since the zone was made leaves its old name there"})
			}
			if len(primaries) != 1 || len(copies) == 0 {
				continue
			}

			// a primary with copies among the servers asked: does it give them the zone, and tell them
			holders := make([]string, 0, len(copies))
			for _, c := range copies {
				holders = append(holders, c.server)
				if name := a.setup[c.server].name; !slices.Contains(nameServers, name) {
					found = append(found, finding{Problem: "ns_missing", Zone: zone.name, Name: zone.name, Servers: []string{c.server}, Detail: fmt.Sprintf("%s holds a copy of %s and calls itself %s, which none of the zone's NS records names: they name %s", c.server, zone.name, name, orNone(nameServers)), Fix: "record_set name=" + zone.name + " type=NS value=" + name + " on " + p.server + ": a resolver following the zone's name servers never asks " + c.server + ", and a transfer kept to them refuses it"})
				}
			}
			o := a.setup[p.server].options[cleanName(zone.name)]
			if o == nil {
				continue
			}
			if o.ZoneTransfer == technitium.PolicyDeny {
				found = append(found, finding{Problem: "transfer_denied", Zone: zone.name, Name: zone.name, Servers: []string{p.server}, Detail: fmt.Sprintf("%s lets nobody transfer %s, and %s holds a copy of it: the copy cannot be brought up to date", p.server, zone.name, strings.Join(holders, ", ")), Fix: "allow the zone's name servers, or the copies' addresses, to transfer it, in the zone's options on " + p.server})
			}
			if o.Notify == technitium.NotifyNone {
				found = append(found, finding{Problem: "notify_none", Zone: zone.name, Name: zone.name, Servers: []string{p.server}, Detail: fmt.Sprintf("%s tells nobody when %s changes, and %s holds a copy of it: the copy learns of a change only when it next checks, which its refresh time sets", p.server, zone.name, strings.Join(holders, ", ")), Fix: "have the zone notify its name servers, or the copies by address, in the zone's options on " + p.server})
			}
		}
	}

	return append(found, reverseZoneShapes(a)...)
}

// reverseZoneShapes finds reverse zones that are the wrong shape: one made
// for a single address, which the server makes one of per machine when a
// scope's network is smaller than a /24 and no zone covers it, and one that
// holds no PTR record at all.
func reverseZoneShapes(a *audited) []finding {
	type under struct {
		singles []string
		whole   bool
	}
	var found []finding
	parents := map[string]*under{}
	for _, zone := range a.inv.zones {
		name := cleanName(zone.name)
		labels, reverse := strings.CutSuffix(name, ".in-addr.arpa")
		if !reverse {
			continue
		}
		var holders []string
		ptrs, catalog := 0, false
		for i := range zone.copies {
			c := &zone.copies[i]
			holders = append(holders, c.server)
			catalog = catalog || strings.Contains(c.zone.Type, "Catalog")
			for r := range c.records {
				if c.records[r].Type == "PTR" {
					ptrs++
				}
			}
		}
		if catalog {
			continue
		}
		on := holders
		if len(holders) == len(a.views) {
			on = nil
		}
		octets := strings.Split(labels, ".")
		switch len(octets) {
		case 4:
			parent := strings.Join(octets[1:], ".") + ".in-addr.arpa"
			if parents[parent] == nil {
				parents[parent] = &under{}
			}
			parents[parent].singles = append(parents[parent].singles, octets[0])
		case 3:
			if parents[name] == nil {
				parents[name] = &under{}
			}
			parents[name].whole = true
		default:
		}
		if ptrs == 0 {
			found = append(found, finding{Problem: "reverse_zone_empty", Zone: name, Name: name, Servers: on, Detail: fmt.Sprintf("the reverse zone %s holds no PTR record: it answers that no address in it has a name, where without it the servers would ask elsewhere", name), Fix: "delete it (zone_delete) unless PTRs are about to be put in it"})
		}
	}

	for _, parent := range slices.Sorted(maps.Keys(parents)) {
		p := parents[parent]
		if len(p.singles) < 2 || p.whole {
			continue
		}
		slices.SortFunc(p.singles, func(x, y string) int {
			a, _ := strconv.Atoi(x)
			b, _ := strconv.Atoi(y)

			return a - b
		})
		octets := strings.Split(strings.TrimSuffix(parent, ".in-addr.arpa"), ".")
		slices.Reverse(octets)
		network := strings.Join(octets, ".") + ".0/24"
		found = append(found, finding{Problem: "reverse_zone_per_address", Zone: parent, Name: parent, Detail: fmt.Sprintf("%d reverse zones each hold one address of %s (%s) and no zone holds the network: the server makes one zone per machine when a DHCP scope's network is smaller than a /24 and nothing covers it", len(p.singles), network, strings.Join(p.singles, ", ")), Fix: fmt.Sprintf("make the zone %s (zone_create), put the PTRs in it (record_set) and delete the small zones (zone_delete): the server writes a PTR into whichever zone covers the address", parent)})
	}

	return found
}

// orNone is a list of names in words, or "none" for an empty one.
func orNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}

	return strings.Join(names, ", ")
}

// auditSecurity finds what the servers leave open: resolving for anyone, a
// console in the clear, the password a server ships with, zones anyone may
// transfer or change, tokens nobody uses, and a version that is behind.
func auditSecurity(a *audited) []finding {
	return a.perServer(func(v *view) []finding {
		setup := a.setup[v.server]
		if setup == nil {
			return nil
		}
		var found []finding
		if setup.defaultPassword {
			found = append(found, finding{Problem: "default_password", Detail: "the admin account still has the password the server ships with: anyone who can reach the console is its administrator", Fix: "change it, in the console under the account's own menu"})
		}
		if s := setup.settings; s != nil {
			if s.Recursion == technitium.PolicyAllow {
				found = append(found, finding{Problem: "recursion_open", Detail: "the server resolves any name for anyone who can reach it: reached from outside, it can be used to flood others with answers they did not ask for", Fix: "resolve for private networks alone, or for the networks named, in the server's settings under Recursion"})
			}
			if !s.WebServiceEnableTLS {
				found = append(found, finding{Problem: "console_plain", Detail: "the web console and the API answer over plain HTTP alone: a password or a token sent to it crosses the network in the clear", Fix: "turn on HTTPS for the web service in the server's settings, or reach it only over a network you trust"})
			}
		}
		if u := setup.update; u != nil && u.Available {
			found = append(found, finding{Problem: "update_available", Detail: fmt.Sprintf("version %s is out and the server runs %s", u.UpdateVersion, u.CurrentVersion), Fix: "update the server: " + u.ChangeLogLink})
		}
		for i := range setup.sessions {
			s := &setup.sessions[i]
			if seen, ok := technitium.ParseTime(s.LastSeen); ok && s.Type == technitium.SessionAPIToken && !s.IsCurrentSession && time.Since(seen) > tokenIdle {
				found = append(found, finding{Problem: "token_unused", Name: s.TokenName, Detail: fmt.Sprintf("the API token %q of %s was last used on %s, %d days ago: a token does not expire, and one nobody uses is a way in nobody watches", s.TokenName, s.Username, seen.UTC().Format(time.DateOnly), int(time.Since(seen).Hours()/24)), Fix: "delete it, in the console under Administration, Sessions, unless something still needs it"})
			}
		}

		for _, z := range v.zones {
			o := setup.options[z.name]
			if o == nil || o.Type != technitium.ZonePrimary {
				continue
			}
			if o.ZoneTransfer == technitium.PolicyAllow {
				found = append(found, finding{Problem: "transfer_open", Zone: z.name, Name: z.name, Detail: fmt.Sprintf("anyone who can reach the server may transfer %s whole: every name in it, in one request", z.name), Fix: "allow the zone's own name servers alone, or the networks named, in the zone's options"})
			}
			switch {
			case o.Update == technitium.PolicyDeny || o.Update == "":
			case o.Update == technitium.PolicyAllow:
				found = append(found, finding{Problem: "update_open", Zone: z.name, Name: z.name, Detail: fmt.Sprintf("anyone who can reach the server may change the records of %s by a DNS update, with no key asked for", z.name), Fix: "deny updates, or require a key and name what it may change, in the zone's options"})
			case len(o.UpdateSecurityPolicies) == 0:
				found = append(found, finding{Problem: "update_open", Zone: z.name, Name: z.name, Detail: fmt.Sprintf("the records of %s may be changed by a DNS update from an address that is allowed (%s), with no key asked for: an address is easily borrowed", z.name, o.Update), Fix: "require a key and name what it may change, in the zone's options"})
			default:
			}
		}

		return found
	})
}
