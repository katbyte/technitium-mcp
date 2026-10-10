package tools

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// finding is one thing an audit found wrong.
type finding struct {
	Problem string   `json:"problem"           jsonschema:"what kind of thing is wrong, by its short name; the audit's description says what each is"`
	Zone    string   `json:"zone,omitempty"`
	Name    string   `json:"name,omitempty"`
	Detail  string   `json:"detail"            jsonschema:"what is wrong, with the values at fault"`
	Fix     string   `json:"fix,omitempty"     jsonschema:"what would put it right"`
	Servers []string `json:"servers,omitempty" jsonschema:"the servers it is so on, when not every server asked"`
}

// audited is what an audit reads: every zone of the servers asked, and each
// server's own view of them.
type audited struct {
	inv   *inventory
	views []*view

	// dhcp is each server's DHCP, for the audits that read it: a server
	// whose DHCP could not be read is in dhcpFailed instead
	dhcp       map[string]*dhcpHeld
	dhcpFailed []serverFailure
	// addresses are the addresses each server says are its own; a server
	// that would not say has no entry
	addresses map[string][]netip.Addr

	// blocking is each server's blocking, for the audit of it: a server
	// whose blocking could not be read is in blockingFailed instead
	blocking       map[string]*blockingRead
	blockingFailed []serverFailure

	// setup is what each server says of itself and of each zone's options,
	// for the audits of how zones are served and of what is left open: a
	// server that would say nothing is in setupFailed instead
	setup       map[string]*setupRead
	setupFailed []serverFailure

	// more is what each server says of its cluster, its accounts, its
	// signed zones, its queries and its apps, for the audits of those: a
	// server that would say none of it is in moreFailed instead
	more       map[string]*moreRead
	moreFailed []serverFailure

	// reached are the addresses the servers are configured at, read or not,
	// and nodeNames and nodeAddresses every node of a cluster a server asked
	// is in, by what that server says of it. A zone's NS record or a scope's
	// name server naming one of these names a server, not a stranger, even
	// when that server could not be read
	reached       []netip.Addr
	nodeNames     []string
	nodeAddresses []netip.Addr
}

// knows notes the nodes of a cluster as one server says they are, so that a
// node that could not be read itself is still known as a server.
func (a *audited) knows(state *technitium.Cluster) {
	if state == nil {
		return
	}
	for _, n := range state.Nodes {
		if name := cleanName(n.Name); name != "" && !slices.Contains(a.nodeNames, name) {
			a.nodeNames = append(a.nodeNames, name)
		}
		for _, text := range n.IPAddresses {
			if addr, ok := parseAddr(text); ok && !slices.Contains(a.nodeAddresses, addr) {
				a.nodeAddresses = append(a.nodeAddresses, addr)
			}
		}
	}
}

// knownAddress reports whether an address is one a server asked has, one
// a server is configured at, or one of a node of their cluster.
func (a *audited) knownAddress(addr netip.Addr) bool {
	for _, addrs := range a.addresses {
		if slices.Contains(addrs, addr) {
			return true
		}
	}

	return slices.Contains(a.reached, addr) || slices.Contains(a.nodeAddresses, addr)
}

// needs is what an audit reads beside the zones.
type needs struct {
	// dhcp is the servers' DHCP, blocking their lists of blocked and
	// allowed names, setup each zone's options, and security the servers'
	// settings, sessions and version as well
	dhcp, blocking, setup, security bool
	// cluster is how each server stands in a cluster, access its accounts
	// and who may do what, dnssec the keys of its signed zones, queries
	// what it was asked and how it answered, and apps what it runs
	cluster, access, dnssec, queries, apps bool
}

// perServer runs a check on each server's own zones and gives each thing
// found once, naming the servers it is on when that is not all of them.
func (a *audited) perServer(check func(v *view) []finding) []finding {
	type seen struct {
		f       finding
		servers []string
	}
	var order []string
	found := map[string]*seen{}
	for _, v := range a.views {
		for _, f := range check(v) {
			key := f.Problem + "\x00" + f.Zone + "\x00" + f.Name + "\x00" + f.Detail
			if found[key] == nil {
				found[key] = &seen{f: f}
				order = append(order, key)
			}
			if !slices.Contains(found[key].servers, v.server) {
				found[key].servers = append(found[key].servers, v.server)
			}
		}
	}

	out := make([]finding, 0, len(order))
	for _, key := range order {
		s := found[key]
		if len(s.servers) != len(a.views) {
			s.f.Servers = s.servers
		}
		out = append(out, s.f)
	}

	return out
}

// audit is one audit: its tool, what it looks for, and how.
type audit struct {
	name, description string
	// problems are the kinds of thing it finds, each with what it is
	problems [][2]string
	// needs is what it reads beside the zones
	needs needs
	run   func(a *audited) []finding
}

// audits are every audit, in the order audit_all runs them.
var audits = []audit{
	{
		name:        "audit_servers",
		description: "Find where the configured servers, which are meant to hold the same zones, do not: a zone one holds and another lacks, a copy behind its primary or whose last transfer failed, a zone held as a separate primary on two servers so that a change on one never reaches the other, and the records that differ between them.",
		problems: [][2]string{
			{"zone_missing", "a zone some of the servers hold and others do not"},
			{"two_primaries", "a zone two servers each hold as their own primary: nothing carries a change from one to the other"},
			{"records_differ", "a zone whose records are not the same on every server holding it"},
			{"copy_behind", "a secondary whose serial is not its primary's: it has not taken the primary's last changes"},
			{"sync_failed", "a secondary whose last transfer from its primary failed"},
			{"copy_expired", "a secondary that has expired: it has gone without a transfer for so long the server no longer answers from it"},
			{"notify_failed", "a primary that could not tell a secondary of its last change"},
		},
		run: auditServers,
	},
	{
		name:        "audit_targets",
		description: "Find the records that point at a name and end nowhere or wrongly, by following each through the servers' own zones: a CNAME whose target has no record, a chain of CNAMEs that loops or runs long, a CNAME at a zone's own name or beside other records, and an MX, SRV or NS whose target is missing or is itself a CNAME. A target in no zone the servers hold is not judged: where it ends is not theirs to say.",
		problems: [][2]string{
			{"dangling", "a CNAME or ANAME whose target, or a name further down its chain, has no record in the zone it belongs in"},
			{"loop", "a chain of CNAMEs that comes back to a name it has passed"},
			{"long_chain", "a name that takes more than four CNAMEs to reach an address"},
			{"cname_at_apex", "a CNAME at a zone's own name, which a zone's SOA and NS records cannot share"},
			{"cname_with_others", "a CNAME beside other records at one name, which a CNAME cannot share"},
			{"target_missing", "an MX, SRV or NS whose target has no record in the zone it belongs in"},
			{"target_is_cname", "an MX, SRV or NS whose target is a CNAME, which those may not point at"},
		},
		run: auditTargets,
	},
	{
		name:        "audit_reverse",
		description: "Find where addresses and their PTR records do not agree: an address in a subnet the server holds a reverse zone for with no PTR, a PTR naming a host that does not hold that address, an address with more than one PTR, and a subnet with addresses in use and no reverse zone at all.",
		problems: [][2]string{
			{"no_ptr", "an address a name holds, with a reverse zone for it on the server and no PTR record in it"},
			{"ptr_stale", "a PTR naming a host that the server's zones say does not hold that address, or has no record"},
			{"ptr_elsewhere", "an address whose PTR names a host other than any that holds it"},
			{"several_ptrs", "an address with more than one PTR record"},
			{"no_reverse_zone", "a subnet with addresses in use for which the server holds no reverse zone"},
		},
		run: auditReverse,
	},
	{
		name:        "audit_overlaps",
		description: "Find records that are never served or probably not meant: a record in a zone at a name that a zone further down also holds on the same server, so the lower zone answers and this record never does; several addresses at one name in different networks; the odd public address in a zone of private ones, or the reverse; and the wildcards, each of which answers for every name under it that has no record - a mistyped one included.",
		problems: [][2]string{
			{"shadowed", "a record at a name that belongs to a zone further down on the same server, which answers instead"},
			{"addresses_apart", "one name with addresses in different networks"},
			{"wildcard", "a wildcard record: every name under it with no record of its own gets its answer"},
			{"address_out_of_place", "one or two public addresses in a zone of private ones, or private in a zone of public"},
		},
		run: auditOverlaps,
	},
	{
		name:        "audit_naming",
		description: "Find names and values that are probably slips: a space or an invisible character in a name, a value or a comment; an underscore in a host's name; two names in one zone a typing slip apart; a TTL so short that it is asked for constantly or so long that a change takes days to be seen, or far from the one the rest of its zone has; and one host's names written two ways.",
		problems: [][2]string{
			{"space", "a space out of place, or an invisible character, in a name, a value or a comment"},
			{"underscore", "an underscore in the name of a record that holds an address or a CNAME: a host's name may not have one"},
			{"near_duplicate", "two names in one zone that differ by a slip of the keyboard"},
			{"ttl_short", "a TTL under a minute"},
			{"ttl_long", "a TTL over a week"},
			{"ttl_outlier", "a TTL ten times, or a tenth of, the one nearly all the zone's records have"},
			{"named_two_ways", "a name written with a hyphen beside the same host's names written under it with a dot"},
		},
		run: auditNaming,
	},
	{
		name:        "audit_state",
		description: "List what is switched off or set to vanish, so none is forgotten: zones that are disabled, records that are disabled, and records set to delete themselves.",
		problems: [][2]string{
			{"zone_disabled", "a zone that is disabled: the server holds it and answers nothing from it"},
			{"record_disabled", "a record that is disabled"},
			{"record_expires", "a record set to delete itself a while after its last change"},
		},
		run: auditState,
	},
	{
		name:        "audit_dhcp",
		description: "Find what is wrong with the servers' DHCP and where it and their zones do not agree, from every scope, reservation and lease of every server asked: DHCP that one server alone gives, two servers leasing the same addresses, a scope running out, a scope telling machines to resolve through a server that is none of these or leaving one of these out, reservations that cannot work or have no name in DNS, records made by hand at addresses a scope gives out by itself, and records the server wrote for a lease that are still there when the lease is not.",
		problems: [][2]string{
			{"dhcp_one_server", "one server alone leases addresses, with another asked that could and does not"},
			{"ranges_overlap", "two servers leasing the same addresses, which do not tell each other what they have given"},
			{"pool_low", "a scope with a tenth or less of its addresses free"},
			{"scope_domain_unknown", "a scope whose domain no server asked holds a zone for"},
			{"scope_dns_unknown", "a scope telling machines to resolve through an address that is no server asked, none configured here and no node of their cluster"},
			{"scope_dns_same", "a scope telling machines to resolve through one server twice, as this server and by its address"},
			{"scope_dns_missing", "a scope whose name servers leave out a server asked"},
			{"reservation_outside", "a reservation for an address outside its scope's network"},
			{"reservation_no_mac", "a reservation for a hardware address of all zeros, which no machine has"},
			{"reservation_shared", "one address reserved for more than one machine"},
			{"reservation_leased_away", "a reserved address that another machine holds a lease on"},
			{"reservation_no_record", "a reservation with no address record for its name, or with no name and no record naming its address"},
			{"reservation_record_elsewhere", "a reservation whose name holds another address in DNS"},
			{"static_in_pool", "a record made by hand at an address a scope gives out by itself, with no reservation"},
			{"address_leased_elsewhere", "a record made by hand at an address a scope has leased to another machine"},
			{"lease_name_taken", "a lease under a name that a record made by hand holds for another address"},
			{"record_left_behind", "a record the server wrote for a lease or a reservation that is no longer there"},
		},
		needs: needs{dhcp: true},
		run:   auditDHCP,
	},
	{
		name:        "audit_blocking",
		description: "Find what is wrong with what the servers block, from each one's settings and its own lists of blocked and allowed names: blocking switched off or paused with lists still set, block lists that are not being fetched or hold nothing, an entry that blocks nothing because a zone on the server answers for the name or an allowed entry wins over it, an entry another above it already stands for, and servers that do not block the same - where a name resolves or not by which server a client asks.",
		problems: [][2]string{
			{"blocking_off", "blocking switched off on a server that has lists or names to block"},
			{"blocking_paused", "blocking paused: off for a while, coming back on by itself"},
			{"lists_not_fetched", "block lists more than an hour past the time they were due to be fetched, or not fetched since they were set"},
			{"lists_empty", "block lists that hold no names between them: none has loaded"},
			{"entry_never_applies", "a blocked name that a zone on the server answers for, or that the server refuses itself, before any list is looked at"},
			{"entry_overridden", "a blocked name that is on the allowed list too, which wins"},
			{"entry_redundant", "an entry with another above it on the same list, which already stands for it"},
			{"blocking_differs", "servers that do not block alike: on and off, other lists, or names on one's own lists and not the other's"},
		},
		needs: needs{blocking: true},
		run:   auditBlocking,
	},
	{
		name:        "audit_zones",
		description: "Find where a zone's own records and options do not fit the servers that hold it, from each zone's NS and SOA records, its options, and what each server calls itself: a name server the zone names that is no server asked and no node of their cluster, a server holding the zone that none of its NS records names, an SOA naming a primary that is not the server holding it as one - each of which a renamed server leaves behind - and a primary that lets no copy transfer the zone or tells none when it changes; and reverse zones of the wrong shape, one address each or holding no PTR at all.",
		problems: [][2]string{
			{"ns_unknown", "an NS record at a zone's own name for a server that is none of those asked, and no node of their cluster"},
			{"reverse_zone_per_address", "reverse zones of one address each under a /24 no zone holds, as the server makes for a scope smaller than a /24"},
			{"reverse_zone_empty", "a reverse zone with no PTR record in it"},
			{"ns_missing", "a server holding a zone, as its primary or as a copy, that none of the zone's NS records names"},
			{"soa_primary", "an SOA record naming a primary other than the server that holds the zone as its primary"},
			{"transfer_denied", "a primary that lets nobody transfer a zone another server asked holds a copy of"},
			{"notify_none", "a primary that tells nobody when a zone changes, with a copy on another server asked"},
		},
		needs: needs{setup: true},
		run:   auditZones,
	},
	{
		name:        "audit_security",
		description: "Find what the servers leave open, from each one's settings, its sessions and tokens, and each zone's options: a server that resolves for anyone, a console that answers over plain HTTP alone, the password a server ships with, a zone anyone may transfer whole or change by a DNS update with no key, an API token nobody has used in ninety days, and a server behind the version that is out.",
		problems: [][2]string{
			{"default_password", "the admin account still has the password the server ships with"},
			{"recursion_open", "a server that resolves any name for anyone who can reach it"},
			{"console_plain", "a web console and API that answer over plain HTTP alone"},
			{"transfer_open", "a zone anyone who can reach the server may transfer whole"},
			{"update_open", "a zone that may be changed by a DNS update with no key asked for"},
			{"token_unused", "an API token not used in ninety days"},
			{"update_available", "a server behind the version that is out"},
		},
		needs: needs{setup: true, security: true},
		run:   auditSecurity,
	},
	{
		name:        "audit_cluster",
		description: "Find where a cluster of servers is not whole, from what each node says of it: a node the others cannot reach, nodes that do not agree who the nodes are, a secondary that has stopped fetching the primary's configuration, nodes on different versions of the server, a cluster of one, a node of the cluster that is not configured here and so was read by no audit, and servers that are in no cluster while the others are in one. Servers that are all in no cluster have nothing to find.",
		problems: [][2]string{
			{"node_unreachable", "a node of the cluster that another node cannot reach"},
			{"nodes_disagree", "nodes of one cluster that list different nodes: one was dropped and still thinks it is in"},
			{"config_stale", "a secondary node that has not fetched the primary's configuration for more than twice as long as it is set to"},
			{"versions_differ", "nodes of one cluster on different versions of the server"},
			{"single_node", "a cluster with its primary and no other node"},
			{"node_not_configured", "a node of the cluster that is not among the servers configured here, so no audit read it"},
			{"outside_cluster", "a server in no cluster, while others asked are in one"},
		},
		needs: needs{cluster: true},
		run:   auditCluster,
	},
	{
		name:        "audit_access",
		description: "Find accounts and permissions that leave a server easier to take than it need be, from every account, its groups, sessions and tokens, and what each section allows: an administrator who signs in with a password alone, an account nobody has ever used, a switched-off account whose tokens are still there, the admin account the server ships with left on beside another administrator, and a section that every account may change. Only an administrator's token can read these.",
		problems: [][2]string{
			{"admin_no_two_factor", "an account in the Administrators group with no second factor"},
			{"account_never_used", "an account that is switched on, has never signed in and has no token"},
			{"disabled_with_tokens", "an account that is switched off and still has API tokens, which work again when it is switched back on"},
			{"everyone_may_change", "a section the Everyone group may modify or delete in"},
			{"stock_admin", "the admin account the server ships with switched on beside another administrator"},
		},
		needs: needs{access: true},
		run:   auditAccess,
	},
	{
		name:        "audit_dnssec",
		description: "Find what the keys of the signed zones are waiting for or leave weak, on the server each zone is signed on: a key signing key that is ready and waits for its DS record to be put at the parent zone, a key that was made and never put in the zone, a zone whose names anyone can list because it proves absence with NSEC, a zone signing key the server never replaces, a key of an algorithm that is no longer trusted, and signatures the server has let expire. A zone that is not signed has nothing to find.",
		problems: [][2]string{
			{"ds_wanted_at_parent", "a key signing key that is Ready: its DS record is to be given to the parent zone"},
			{"key_not_published", "a key that was generated and never put in the zone"},
			{"nsec_walkable", "a zone signed with NSEC, whose names anyone can list"},
			{"key_never_replaced", "a zone signing key in use that the server is set never to replace"},
			{"weak_algorithm", "a key of an algorithm with MD5 or SHA-1 in it"},
			{"signature_expired", "a signed zone holding signatures past their expiration, which the server should have renewed"},
		},
		needs: needs{dnssec: true},
		run:   auditDNSSEC,
	},
	{
		name:        "audit_queries",
		description: "Find what the servers' own account of the last day's queries says is wrong, from each one's check of itself, its statistics and its log of queries: a server that cannot resolve a name right now, a forwarder of its that does not answer, answers with a failure or is slow, a server with no log of queries to look anything up in, one answering too many queries with a failure, one client asking for most of everything, a busy client with no name, a name asked for far more often than its TTL allows by something that does not cache, and the names in the servers' own zones that clients keep asking for and that do not exist - a name something is set to use that was never made, was removed, or is misspelt.",
		problems: [][2]string{
			{"not_resolving", "a server that could not resolve a name for itself when asked"},
			{"forwarder_unanswering", "a forwarder that gave the server no answer when asked for the root's name servers"},
			{"forwarder_failing", "a forwarder that answered that with a failure or a refusal"},
			{"forwarder_slow", "a forwarder that took half a second or more to answer"},
			{"no_query_log", "a server with no app keeping a log of queries"},
			{"failing", "a server that answered five or more in every hundred of the last day's queries with a server failure"},
			{"one_client", "one client that asked sixty or more in every hundred of the last day's queries"},
			{"name_not_found", "a name under a zone the servers hold that was asked for five or more times in the last day and does not exist"},
			{"client_unnamed", "a client that asked a thousand or more queries in the last day and has no name"},
			{"client_not_caching", "a name the servers hold asked for ten times more in the last day than its TTL lets a client that caches ask"},
		},
		needs: needs{queries: true},
		run:   auditQueries,
	},
	{
		name:        "audit_apps",
		description: "Find where the DNS apps the servers run are not what they should be: an app behind the version its maker's store has, an app one server runs and another does not, and an app the servers run at different versions or configured differently, so that they do not answer alike. A server that cannot ask the store is not said to be behind it.",
		problems: [][2]string{
			{"app_update", "an installed app the store has a newer version of"},
			{"app_only_on", "an app installed on some of the servers asked and not on others"},
			{"app_versions_differ", "an app that is not at one version on every server"},
			{"app_config_differs", "an app that is not configured alike on every server"},
		},
		needs: needs{apps: true},
		run:   auditApps,
	},
}

// auditIn is what every audit takes.
type auditIn struct {
	serverArg

	Zone     string   `json:"zone,omitempty"     jsonschema:"give only what was found in the zones whose name matches: with a * or a ? the whole name must match, without either the text may be anywhere in it. Every zone is still read: what is wrong in one zone is often seen from another"`
	Problems []string `json:"problems,omitempty" jsonschema:"give only these kinds of finding, by their short names"`
	Limit    int      `json:"limit,omitempty"    jsonschema:"the most findings to give (default 200)"`
	Offset   int      `json:"offset,omitempty"   jsonschema:"how many findings to pass over first, to read on from a limit"`
}

// auditOut is what every audit answers.
type auditOut struct {
	Findings []finding       `json:"findings"         jsonschema:"what was found, zone by zone"`
	Total    int             `json:"total"            jsonschema:"how many things were found, before the limit"`
	Counts   map[string]int  `json:"counts"           jsonschema:"how many of each kind"`
	Zones    int             `json:"zones"            jsonschema:"how many zones were read, every one whole"`
	Asked    []string        `json:"asked"            jsonschema:"the servers that answered"`
	Failed   []serverFailure `json:"failed,omitempty" jsonschema:"the servers that could not be asked, and why: nothing of theirs was audited"`
	Unread   []zoneProblem   `json:"unread,omitempty" jsonschema:"zones a server lists and would not give the records of: nothing in them was audited"`
	Note     string          `json:"note,omitempty"`
}

// audited reads everything an audit needs from the servers asked: every
// zone whole, and what else it says it needs.
func (r *registry) audited(ctx context.Context, server string, need needs) (*audited, error) {
	picked, err := r.servers.Pick(server)
	if err != nil {
		return nil, err
	}
	inv, err := readInventory(ctx, picked, served)
	if err != nil {
		return nil, err
	}
	a := &audited{inv: inv}
	for _, name := range inv.asked {
		a.views = append(a.views, viewOf(inv, name))
	}
	// the address each server is configured at, when it is one: a server that could not be read is still a server
	for _, srv := range picked {
		if u, err := url.Parse(srv.Client.BaseURL()); err == nil {
			if addr, ok := parseAddr(u.Hostname()); ok {
				a.reached = append(a.reached, addr)
			}
		}
	}
	if need.dhcp {
		a.readDHCP(ctx, picked)
	}
	if need.blocking {
		a.readBlocking(ctx, picked)
	}
	if need.setup {
		a.readSetup(ctx, picked, need.security)
	}
	if need.cluster || need.access || need.dnssec || need.queries || need.apps {
		a.readMore(ctx, picked, need)
	}

	return a, nil
}

// unread says which servers' DHCP or blocking an audit could not read, for
// its note: nothing was found there because nothing was looked at.
func (a *audited) unread() string {
	var said string
	for _, f := range a.dhcpFailed {
		said = note(said, fmt.Sprintf("the DHCP of %s could not be read, so none of it was audited: %s", f.Server, f.Error))
	}
	for _, f := range a.blockingFailed {
		said = note(said, fmt.Sprintf("the blocking of %s could not be read, so none of it was audited: %s", f.Server, f.Error))
	}
	for _, f := range a.setupFailed {
		said = note(said, fmt.Sprintf("%s would not say what it calls itself, so how it serves its zones was not audited: %s", f.Server, f.Error))
	}
	for _, v := range a.views {
		if setup := a.setup[v.server]; setup != nil && len(setup.unread) > 0 {
			said = note(said, fmt.Sprintf("%s would not give %s: nothing was found there because nothing was looked at", v.server, strings.Join(setup.unread, ", ")))
		}
		if more := a.more[v.server]; more != nil && len(more.unread) > 0 {
			said = note(said, fmt.Sprintf("%s would not give %s: nothing was found there because nothing was looked at", v.server, strings.Join(more.unread, ", ")))
		}
	}

	return said
}

// sortFindings puts findings in the order a zone tree reads, a zone's own
// before those of names in it.
func sortFindings(found []finding) {
	slices.SortStableFunc(found, func(a, b finding) int {
		return cmp.Or(cmp.Compare(nameOrder(a.Zone), nameOrder(b.Zone)), cmp.Compare(nameOrder(a.Name), nameOrder(b.Name)), cmp.Compare(a.Problem, b.Problem))
	})
}

func registerAudits(r *registry) {
	for _, au := range audits {
		kinds := make([]string, 0, len(au.problems))
		for _, p := range au.problems {
			kinds = append(kinds, p[0]+": "+p[1])
		}
		add(r, readTool, &mcp.Tool{
			Name:        au.name,
			Description: au.description + " Every zone is read whole on every server asked. The findings: " + strings.Join(kinds, "; ") + ".",
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in auditIn) (*mcp.CallToolResult, auditOut, error) {
			for _, want := range in.Problems {
				if !slices.ContainsFunc(au.problems, func(p [2]string) bool { return p[0] == want }) {
					return nil, auditOut{}, fmt.Errorf("%s finds no %q: it finds %s", au.name, want, strings.Join(problemNames(&au), ", "))
				}
			}
			a, err := r.audited(ctx, in.Server, au.needs)
			if err != nil {
				return nil, auditOut{}, err
			}

			zones := newPattern(in.Zone)
			out := auditOut{Counts: map[string]int{}, Zones: len(a.inv.zones), Asked: a.inv.asked, Failed: a.inv.failed, Unread: a.inv.problems, Findings: []finding{}, Note: a.unread()}
			found := au.run(a)
			sortFindings(found)
			for i := range found {
				f := &found[i]
				if !zones.matches(f.Zone) || (len(in.Problems) > 0 && !slices.Contains(in.Problems, f.Problem)) {
					continue
				}
				out.Counts[f.Problem]++
				out.Total++
				out.Findings = append(out.Findings, *f)
			}
			out.Findings = out.Findings[min(max(in.Offset, 0), len(out.Findings)):]
			if limit := limitOr(in.Limit); len(out.Findings) > limit {
				out.Findings = out.Findings[:limit]
				out.Note = note(out.Note, fmt.Sprintf("%d things were found and %d are given, starting at the %s: read on with offset %d, or narrow it with zone or problems", out.Total, limit, ordinal(max(in.Offset, 0)+1), max(in.Offset, 0)+limit))
			}

			return nil, out, nil
		})
	}

	type auditRow struct {
		Audit  string         `json:"audit"            jsonschema:"the audit's tool: call it for what it found"`
		Total  int            `json:"total"`
		Counts map[string]int `json:"counts,omitempty" jsonschema:"how many of each kind it found"`
	}
	type auditAllOut struct {
		Audits []auditRow      `json:"audits"           jsonschema:"every audit, with how much it found"`
		Total  int             `json:"total"            jsonschema:"how many things were found in all"`
		Zones  int             `json:"zones"            jsonschema:"how many zones were read, every one whole"`
		Asked  []string        `json:"asked"            jsonschema:"the servers that answered"`
		Failed []serverFailure `json:"failed,omitempty" jsonschema:"the servers that could not be asked, and why: nothing of theirs was audited"`
		Unread []zoneProblem   `json:"unread,omitempty" jsonschema:"zones a server lists and would not give the records of: nothing in them was audited"`
		Note   string          `json:"note,omitempty"`
	}
	type auditAllIn struct {
		serverArg

		Zone string `json:"zone,omitempty" jsonschema:"count only what was found in the zones whose name matches: with a * or a ? the whole name must match, without either the text may be anywhere in it"`
	}
	names := make([]string, 0, len(audits))
	for _, au := range audits {
		names = append(names, au.name)
	}
	add(r, readTool, &mcp.Tool{
		Name:        "audit_all",
		Description: "Run every audit over the configured servers in one reading of their zones, their DHCP, their blocking and their settings, and answer with how much each found, by kind: where to look first. The audits, each of which gives its findings when called itself: " + strings.Join(names, ", ") + ".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in auditAllIn) (*mcp.CallToolResult, auditAllOut, error) {
		a, err := r.audited(ctx, in.Server, needs{dhcp: true, blocking: true, setup: true, security: true, cluster: true, access: true, dnssec: true, queries: true, apps: true})
		if err != nil {
			return nil, auditAllOut{}, err
		}
		zones := newPattern(in.Zone)
		out := auditAllOut{Zones: len(a.inv.zones), Asked: a.inv.asked, Failed: a.inv.failed, Unread: a.inv.problems, Note: a.unread()}
		for _, au := range audits {
			row := auditRow{Audit: au.name, Counts: map[string]int{}}
			for _, f := range au.run(a) {
				if zones.matches(f.Zone) {
					row.Counts[f.Problem]++
					row.Total++
				}
			}
			out.Total += row.Total
			out.Audits = append(out.Audits, row)
		}

		return nil, out, nil
	})
}

// problemNames are the short names of what an audit finds.
func problemNames(au *audit) []string {
	names := make([]string, 0, len(au.problems))
	for _, p := range au.problems {
		names = append(names, p[0])
	}

	return names
}
