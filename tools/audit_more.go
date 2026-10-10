package tools

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// What the audits of queries go by: how far back the log is read for names
// that do not exist and how many of its entries, how often a name must have
// been asked for to be worth saying, and what share of a day's queries
// failing or coming from one client is worth saying.
const (
	notFoundWindow  = 24 * time.Hour
	notFoundEntries = 2000
	notFoundOften   = 5
	notFoundMost    = 25
	failingShare    = 5
	failingQueries  = 100
	oneClientShare  = 60
	oneClientAsked  = 1000
	// unnamedAsked is how many queries in a day make a client without a name worth one, and notCachingAsked how many for a name make its asker worth a look when they are notCachingSlack times what its TTL lets a client that caches ask
	unnamedAsked    = 1000
	notCachingAsked = 1000
	notCachingSlack = 10
	// forwardersMost is how many of a server's forwarders are asked, and
	// forwarderSlow how long one may take to answer before it is said
	forwardersMost = 8
	forwarderSlow  = 500 * time.Millisecond
)

// forwarderAsked is one of a server's forwarders as it answered when the
// server asked it for the root's name servers, which every resolver knows
// whatever else it does: why it gave no answer, or how the answer went and
// how long it took.
type forwarderAsked struct {
	address, failed, result string
	took                    time.Duration
}

// askForwarders has a server ask each of its forwarders, all at once: one
// that is not there takes the server some twenty seconds to give up on.
func askForwarders(ctx context.Context, srv *servers.Server, forwarders []string, protocol string) []forwarderAsked {
	forwarders = forwarders[:min(len(forwarders), forwardersMost)]
	asked := make([]forwarderAsked, len(forwarders))
	var wg sync.WaitGroup
	for i, address := range forwarders {
		wg.Go(func() {
			asked[i] = forwarderAsked{address: address}
			res, err := srv.Client.Resolve(ctx, technitium.ResolveQuery{Via: address, Name: ".", Type: "NS", Protocol: protocol})
			if err != nil {
				asked[i].failed = err.Error()

				return
			}
			asked[i].result, asked[i].took = res.RCode, roundTrip(res.Metadata.RoundTripTime)
		})
	}
	wg.Wait()

	return asked
}

// roundTrip reads how long an answer took as the server writes it, 16.24 ms,
// and is 0 for what it cannot read.
func roundTrip(text string) time.Duration {
	number, unit, _ := strings.Cut(strings.TrimSpace(text), " ")
	n, err := strconv.ParseFloat(number, 64)
	if err != nil || unit != "ms" {
		return 0
	}

	return time.Duration(n * float64(time.Millisecond))
}

// moreRead is what one server says of its cluster, its accounts, its signed
// zones, its queries and its apps, each read only for the audits that ask.
type moreRead struct {
	cluster *technitium.Cluster

	users  []technitium.User
	access []technitium.Access

	// signing is how each signed zone the server is the primary of is
	// signed, by the zone's name
	signing map[string]*zoneSigning

	// stats is the last day's, notFound the names asked for in that time
	// that do not exist with how often each was, hasLog whether an app keeps
	// a log of queries, and unhealthy why the server's check of itself failed
	stats     *technitium.Stats
	notFound  map[string]int
	hasLog    bool
	unhealthy string
	// forwarders is each of the server's forwarders as it answered just now
	forwarders []forwarderAsked

	apps    []technitium.App
	store   []technitium.StoreApp
	configs map[string]string

	// unread is what the server would not give, which is said beside the
	// findings
	unread []string
}

// readMore reads what the audits of clusters, accounts, signing, queries
// and apps go by, from every server asked. What a server will not give is
// said beside the findings: nothing was found there because nothing was
// looked at.
func (a *audited) readMore(ctx context.Context, picked []*servers.Server, need needs) {
	a.more = map[string]*moreRead{}
	for _, answer := range ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (moreRead, error) {
		var out moreRead
		var err error
		gave := func(what string, err error) bool {
			if err != nil {
				out.unread = append(out.unread, what+" ("+err.Error()+")")
			}

			return err == nil
		}
		if need.cluster {
			if out.cluster, err = srv.Client.ClusterState(ctx); err != nil {
				return moreRead{}, err
			}
		}
		if need.access {
			out.readAccess(ctx, srv, gave)
		}
		if need.dnssec {
			out.signing = map[string]*zoneSigning{}
			for _, zone := range a.inv.zones {
				for i := range zone.copies {
					held := &zone.copies[i]
					if held.server != srv.Name || held.zone.Type != technitium.ZonePrimary || !held.zone.Signed() {
						continue
					}
					if signing, err := signingOfHeld(ctx, srv, &held.zone); gave("the keys of "+zone.name, err) {
						out.signing[cleanName(zone.name)] = signing
					}
				}
			}
		}
		if need.queries {
			out.readQueries(ctx, srv, gave)
		}
		if need.apps {
			out.readApps(ctx, srv, gave)
		}

		return out, nil
	}) {
		switch {
		case !slices.Contains(a.inv.asked, answer.Server.Name):
		case answer.Err != nil:
			a.moreFailed = append(a.moreFailed, serverFailure{Server: answer.Server.Name, Error: answer.Err.Error()})
		default:
			a.more[answer.Server.Name] = &answer.Value
		}
	}
}

// readAccess reads a server's accounts, each whole, and who may do what in
// each of its sections.
func (m *moreRead) readAccess(ctx context.Context, srv *servers.Server, gave func(string, error) bool) {
	listed, err := srv.Client.Users(ctx)
	if !gave("its accounts", err) {
		return
	}
	for _, u := range listed {
		if whole, err := srv.Client.User(ctx, u.Username, false); gave("the account "+u.Username, err) {
			m.users = append(m.users, *whole)
		}
	}
	m.access, err = srv.Client.Permissions(ctx)
	gave("who may do what", err)
}

// readQueries reads what a server was asked over the last day and how it
// answered: its statistics, the names asked for that do not exist, and
// whether it can resolve at all.
func (m *moreRead) readQueries(ctx context.Context, srv *servers.Server, gave func(string, error) bool) {
	if err := srv.Client.HealthCheck(ctx, "", ""); err != nil {
		m.unhealthy = err.Error()
	}
	if settings, settingsErr := srv.Client.Settings(ctx); gave("its forwarders", settingsErr) {
		m.forwarders = askForwarders(ctx, srv, settings.Forwarders, settings.ForwarderProtocol)
	}
	var err error
	if m.stats, err = srv.Client.Stats(ctx, technitium.StatsWindow{Type: "LastDay"}); !gave("its statistics", err) {
		m.stats = nil
	}
	q, _, err := logOf(ctx, srv)
	if err != nil {
		// a server with no log of queries is a finding, not something unread
		return
	}
	m.hasLog, m.notFound = true, map[string]int{}
	q.RCode, q.Start, q.PerPage = "NxDomain", time.Now().Add(-notFoundWindow), notFoundEntries
	page, err := srv.Client.QueryLog(ctx, q)
	if !gave("its log of queries", err) {
		return
	}
	for _, entry := range page.Entries {
		m.notFound[cleanName(entry.Name)]++
	}
}

// readApps reads the apps a server runs, each with its configuration, and
// what the store has of them: a server that cannot ask the store is not
// said to be behind it.
func (m *moreRead) readApps(ctx context.Context, srv *servers.Server, gave func(string, error) bool) {
	var err error
	if m.apps, err = srv.Client.Apps(ctx); !gave("its apps", err) {
		return
	}
	m.configs = map[string]string{}
	for _, app := range m.apps {
		if config, err := srv.Client.AppConfig(ctx, app.Name); gave("the configuration of the app "+app.Name, err) {
			m.configs[app.Name] = strings.TrimSpace(config)
		}
	}
	if store, err := srv.Client.StoreApps(ctx); err == nil {
		m.store = store
	}
}

// onEach runs a check on what each server asked said of itself and gives
// each thing found once, naming the servers it is so on when that is not all
// of them.
func (a *audited) onEach(check func(server string, m *moreRead) []finding) []finding {
	return a.perServer(func(v *view) []finding {
		if m := a.more[v.server]; m != nil {
			return check(v.server, m)
		}

		return nil
	})
}

// auditCluster finds where a cluster is not whole: nodes out of touch,
// nodes that do not agree who the nodes are, a secondary that has not
// fetched the configuration for too long, nodes on different versions, and
// servers that are not in the cluster the others are in.
func auditCluster(a *audited) []finding {
	var found []finding
	// what each server calls itself, and which cluster it says it is in
	domains := map[string][]string{}
	selves := map[string]string{}
	var outside []string
	for _, v := range a.views {
		m := a.more[v.server]
		if m == nil || m.cluster == nil {
			continue
		}
		selves[cleanName(m.cluster.ServerDomain)] = v.server
		if !m.cluster.Initialized {
			outside = append(outside, v.server)

			continue
		}
		domains[cleanName(m.cluster.Domain)] = append(domains[cleanName(m.cluster.Domain)], v.server)
	}
	if len(domains) == 0 {
		return nil
	}
	for _, domain := range slices.Sorted(maps.Keys(domains)) {
		members := domains[domain]
		if len(outside) > 0 {
			found = append(found, finding{Problem: "outside_cluster", Name: domain, Detail: fmt.Sprintf("%s are in the cluster %s and %s in none: nothing carries settings, accounts, lists or zones between them", orNone(members), domain, orNone(outside)), Fix: "have each join the cluster (cluster_join), or audit the servers that are meant to be apart on their own", Servers: outside})
		}

		// the nodes as each member lists them
		lists := map[string][]string{}
		for _, server := range members {
			state := a.more[server].cluster
			var names, versions []string
			for _, n := range state.Nodes {
				names = append(names, cleanName(n.Name))
				if n.Version != "" && !slices.Contains(versions, n.Version) {
					versions = append(versions, n.Version)
				}
				if n.State == "Unreachable" {
					found = append(found, finding{Problem: "node_unreachable", Name: cleanName(n.Name), Detail: fmt.Sprintf("%s cannot reach the node %s of the cluster %s, which it last heard from at %s", server, n.Name, domain, orNever(utc(n.LastSeen))), Fix: "see that the node is running and that its console answers over HTTPS at " + n.URL + " from the other nodes; a node that is gone for good is taken out with cluster_node_delete and force", Servers: []string{server}})
				}
				if _, configured := selves[cleanName(n.Name)]; !configured {
					found = append(found, finding{Problem: "node_not_configured", Name: cleanName(n.Name), Detail: fmt.Sprintf("the cluster %s has a node %s that is not among the servers configured here: nothing of it was read by any audit", domain, n.Name), Fix: "configure the node as a server here too, so the audits read every node of the cluster"})
				}
			}
			slices.Sort(names)
			lists[strings.Join(names, " ")] = append(lists[strings.Join(names, " ")], server)
			slices.Sort(versions)
			if len(versions) > 1 {
				found = append(found, finding{Problem: "versions_differ", Name: domain, Detail: fmt.Sprintf("the nodes of the cluster %s run different versions of the server: %s", domain, strings.Join(versions, ", ")), Fix: "bring every node to the same version: a cluster's nodes hand each other configuration that a newer version may write and an older one not read"})
			}
			if len(state.Nodes) == 1 {
				found = append(found, finding{Problem: "single_node", Name: domain, Detail: fmt.Sprintf("the cluster %s has one node, its primary %s: there is nothing for it to share anything with", domain, state.Nodes[0].Name), Fix: "have another server join it (cluster_join), or delete the cluster (cluster_delete) if none is meant to", Servers: []string{server}})
			}
			if self := state.Self(); self != nil && self.Type == technitium.NodeSecondary && state.ConfigRefreshIntervalSeconds > 0 {
				// a node that gives no time has only just joined, and is handed the configuration as it does: only a time that is too old is said
				synced, ok := technitium.ParseTime(state.ConfigLastSynced)
				late := 2*time.Duration(state.ConfigRefreshIntervalSeconds)*time.Second + 5*time.Minute
				if ok && time.Since(synced) > late {
					found = append(found, finding{Problem: "config_stale", Name: cleanName(self.Name), Detail: fmt.Sprintf("%s last fetched the primary's configuration at %s, and is set to every %d seconds: what was changed on the primary since has not reached it", server, utc(state.ConfigLastSynced), state.ConfigRefreshIntervalSeconds), Fix: "have it fetch now (cluster_edit with resync) and read its log for why it stopped", Servers: []string{server}})
				}
			}
		}
		if len(lists) > 1 {
			var said []string
			for _, names := range slices.Sorted(maps.Keys(lists)) {
				said = append(said, fmt.Sprintf("%s list %s", strings.Join(lists[names], " and "), strings.ReplaceAll(names, " ", ", ")))
			}
			found = append(found, finding{Problem: "nodes_disagree", Name: domain, Detail: fmt.Sprintf("the nodes of the cluster %s do not agree who its nodes are: %s", domain, strings.Join(said, "; ")), Fix: "a node the primary no longer lists was dropped and still thinks it is in: cluster_leave with force takes it out, and cluster_join has it join again"})
		}
	}

	// the same thing found from two nodes is said once
	seen := map[string]int{}
	out := found[:0]
	for _, f := range found {
		key := f.Problem + "\x00" + f.Name + "\x00" + f.Detail
		if at, dup := seen[key]; dup {
			out[at].Servers = append(out[at].Servers, f.Servers...)

			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}

	return out
}

// orNever is a time, or "never" for none.
func orNever(when string) string {
	if when == "" {
		return "never"
	}

	return when
}

// auditAccess finds accounts and permissions that leave a server easier to
// take than it need be: an administrator with no second factor, an account
// nobody has ever used, a switched-off account that still has tokens, and a
// section everyone may change.
func auditAccess(a *audited) []finding {
	return a.onEach(func(_ string, m *moreRead) []finding {
		var found []finding
		for i := range m.users {
			u := &m.users[i]
			tokens := 0
			for _, s := range u.Sessions {
				if s.Type == technitium.SessionAPIToken {
					tokens++
				}
			}
			switch {
			case u.Disabled && tokens > 0:
				found = append(found, finding{Problem: "disabled_with_tokens", Name: u.Username, Detail: fmt.Sprintf("the account %s is switched off and still has %d API tokens: they are refused now, and work again the moment the account is switched back on", u.Username, tokens), Fix: "delete the tokens (session_delete) if the account is not coming back, or the account itself (user_delete)"})
			case u.Disabled:
			case slices.Contains(u.MemberOfGroups, "Administrators") && !u.TOTPEnabled && !u.IsSSOUser:
				found = append(found, finding{Problem: "admin_no_two_factor", Name: u.Username, Detail: fmt.Sprintf("the administrator %s signs in with a password alone: whoever learns it has the whole server", u.Username), Fix: "give the account a second factor: account_edit, as the account itself, begins and enables one"})
			case signedIn(u.RecentSessionLoggedOn) == "" && len(u.Sessions) == 0:
				found = append(found, finding{Problem: "account_never_used", Name: u.Username, Detail: fmt.Sprintf("the account %s has never signed in and has no token: it is a password waiting to be guessed for nobody's use", u.Username), Fix: "delete it (user_delete), or switch it off (user_set with disabled) until it is wanted"})
			default:
			}
		}
		// the account every server ships with, which whoever tries the console tries first, while another administrator could take its place
		var admins []string
		for i := range m.users {
			if u := &m.users[i]; !u.Disabled && slices.Contains(u.MemberOfGroups, "Administrators") {
				admins = append(admins, u.Username)
			}
		}
		if i := slices.Index(admins, "admin"); i >= 0 && len(admins) > 1 {
			found = append(found, finding{Problem: "stock_admin", Name: "admin", Detail: fmt.Sprintf("the account admin, which every server ships with and which whoever tries the console tries first, is switched on beside %s: half of a sign-in is given away", strings.Join(slices.Delete(slices.Clone(admins), i, i+1), ", ")), Fix: "switch it off (user_set), signed in as the other administrator and with that account's tokens known to work; or give it a second factor"})
		}
		for i := range m.access {
			section := &m.access[i]
			for _, g := range section.Groups {
				if g.Name == "Everyone" && (g.CanModify || g.CanDelete) {
					found = append(found, finding{Problem: "everyone_may_change", Name: section.Section, Detail: fmt.Sprintf("every account, whatever its groups, may %s in %s", strings.TrimPrefix(accessEntry{Modify: g.CanModify, Delete: g.CanDelete}.may(), "view, "), section.Section), Fix: "give the Everyone group view alone in the section, or nothing (access_set), and what is to be changed there to the groups meant to change it"})
				}
			}
		}

		return found
	})
}

// auditDNSSEC finds what a signed zone's keys are waiting for or leave
// weak: a key signing key whose DS record is to go to the parent, a key
// that was made and never put in the zone, a zone anyone can list the names
// of, a key that is never replaced, and an algorithm that is no longer
// trusted.
func auditDNSSEC(a *audited) []finding {
	return append(a.onEach(func(_ string, m *moreRead) []finding {
		var found []finding
		for _, zone := range slices.Sorted(maps.Keys(m.signing)) {
			signing := m.signing[zone]
			if signing.Status == "SignedWithNSEC" {
				found = append(found, finding{Problem: "nsec_walkable", Zone: zone, Detail: zone + " proves a name is not in it with NSEC, which lets anyone list every name the zone has by following one proof to the next", Fix: "if the zone's names are not for everyone to read, have it use NSEC3 (dnssec_edit with nx_proof NSEC3)"})
			}
			for _, k := range signing.Keys {
				switch {
				case k.State == "Generated":
					found = append(found, finding{Problem: "key_not_published", Zone: zone, Detail: fmt.Sprintf("the %s %d of %s was made on %s and has never been put in the zone: it signs nothing", k.Type, k.KeyTag, zone, orNever(k.ChangedOn)), Fix: "publish it (dnssec_key_edit with action publish) if it is wanted, or delete it (dnssec_key_delete)"})
				case k.Type == technitium.KeySigningKey && k.State == "Ready":
					found = append(found, finding{Problem: "ds_wanted_at_parent", Zone: zone, Detail: fmt.Sprintf("the key signing key %d of %s is ready and waits for its DS record to be at the zone's parent: until it is, nobody who validates trusts the zone by this key", k.KeyTag, zone), Fix: "give the registrar, or the parent zone, the DS record for the key, which dnssec_get gives under ds"})
				case k.Type == technitium.ZoneSigningKey && k.State == "Active" && k.RolloverDays == 0 && !k.Retiring:
					found = append(found, finding{Problem: "key_never_replaced", Zone: zone, Detail: fmt.Sprintf("the zone signing key %d of %s is in use and is never replaced by the server: it signs with the same key for as long as nobody does it by hand", k.KeyTag, zone), Fix: "set how often it is replaced (dnssec_key_edit with rollover_days), which the server then does by itself"})
				default:
				}
				if upper := strings.ToUpper(k.Algorithm); strings.Contains(upper, "MD5") || strings.Contains(upper, "SHA1") {
					found = append(found, finding{Problem: "weak_algorithm", Zone: zone, Detail: fmt.Sprintf("the %s %d of %s signs with %s, which resolvers no longer trust or soon will not", k.Type, k.KeyTag, zone, k.Algorithm), Fix: "add a key of a current algorithm (dnssec_key_add: ECDSA is the default) and roll this one over to it"})
				}
			}
		}

		return found
	}), expiredSignatures(a)...)
}

// expiredSignatures finds signed zones holding a signature past its
// expiration: the server renews them by itself, so one that is past is a
// server that has stopped, and resolvers that validate refuse what it
// covers.
func expiredSignatures(a *audited) []finding {
	var found []finding
	now := time.Now()
	for _, zone := range a.inv.zones {
		for i := range zone.copies {
			c := &zone.copies[i]
			if c.copied {
				continue
			}
			expired, earliest := 0, time.Time{}
			for r := range c.records {
				rec := &c.records[r]
				if rec.Type != "RRSIG" {
					continue
				}
				_, text, has := strings.Cut(rec.Value(), "signatureExpiration=")
				text, _, _ = strings.Cut(text, " ")
				when, err := time.Parse(time.RFC3339, text)
				if !has || err != nil || !when.Before(now) {
					continue
				}
				expired++
				if earliest.IsZero() || when.Before(earliest) {
					earliest = when
				}
			}
			if expired == 0 {
				continue
			}
			var on []string
			if len(a.views) > 1 {
				on = []string{c.server}
			}
			found = append(found, finding{Problem: "signature_expired", Zone: cleanName(zone.name), Servers: on, Detail: fmt.Sprintf("%d signatures in %s on %s are past their expiration, the oldest since %s: the server renews them by itself and has not, and a resolver that validates refuses what they cover", expired, cleanName(zone.name), c.server, earliest.UTC().Format(time.RFC3339)), Fix: "see why the server has stopped signing (its log, and dnssec_get for the zone's keys); unsigning and signing the zone again (dnssec_unsign, dnssec_sign) starts it afresh"})
		}
	}

	return found
}

// auditQueries finds what the servers' own account of their queries says is
// wrong: a server that cannot resolve, one that keeps no log to look in,
// one failing more than it should, one client asking for most of everything,
// and the names clients keep asking for that do not exist.
func auditQueries(a *audited) []finding {
	// the names asked for and not found count across the servers asked: a client asks whichever answers
	notFound := map[string]int{}
	found := a.onEach(func(_ string, m *moreRead) []finding {
		var found []finding
		if m.unhealthy != "" {
			found = append(found, finding{Problem: "not_resolving", Detail: "the server could not resolve a name for itself just now: " + m.unhealthy, Fix: "read its log for why (the newest log file), and see that it reaches its forwarders or the root servers"})
		}
		if !m.hasLog {
			found = append(found, finding{Problem: "no_query_log", Detail: "no app on the server keeps a log of queries: who asked for what cannot be looked up afterwards, and names that do not exist cannot be found", Fix: "install the Query Logs (Sqlite) app (app_install), which logs from then on"})
		}
		for name, n := range m.notFound {
			notFound[name] += n
		}
		for _, f := range m.forwarders {
			switch {
			case f.failed != "":
				found = append(found, finding{Problem: "forwarder_unanswering", Name: f.address, Detail: fmt.Sprintf("the forwarder %s gave the server no answer when it was asked for the root's name servers, which every resolver knows: %s", f.address, f.failed), Fix: "see that the forwarder is up and that the server reaches it, or take it off the server's forwarders: a name sent to it waits for it before another is tried"})
			case f.result != "NoError":
				found = append(found, finding{Problem: "forwarder_failing", Name: f.address, Detail: fmt.Sprintf("the forwarder %s answered %s when the server asked it for the root's name servers, which every resolver knows", f.address, f.result), Fix: "see what is wrong with the forwarder itself, or take it off the server's forwarders"})
			case f.took >= forwarderSlow:
				found = append(found, finding{Problem: "forwarder_slow", Name: f.address, Detail: fmt.Sprintf("the forwarder %s took %s to answer the server, where one nearby takes a few milliseconds: every name the server has not kept waits that long", f.address, f.took.Round(time.Millisecond)), Fix: "put a nearer forwarder first, or see what is between the server and this one"})
			default:
			}
		}
		if m.stats == nil {
			return found
		}
		total := m.stats.Totals
		if total.Queries >= failingQueries && total.ServerFailure*100 >= total.Queries*failingShare {
			found = append(found, finding{Problem: "failing", Detail: fmt.Sprintf("%d of the last day's %d queries were answered with a server failure, %d in every hundred: the server could not get an answer for them", total.ServerFailure, total.Queries, total.ServerFailure*100/total.Queries), Fix: "see what they were for (the log of queries, by result ServerFailure) and that the forwarders answer: a forwarder that is down, or DNSSEC validation failing, is the usual cause"})
		}
		// a busy client with no name: nothing says what machine it is
		for _, top := range m.stats.TopClients {
			if top.Domain == "" && top.Hits >= unnamedAsked {
				found = append(found, finding{Problem: "client_unnamed", Name: top.Name, Detail: fmt.Sprintf("%s asked %d queries in the last day and has no name: no PTR record names it, and no lease or reservation gives it one", top.Name, top.Hits), Fix: "if it leases its address, reserve it with a host name (dhcp_lease_reserve) in a scope that writes records; otherwise give it a PTR record (record_set type=PTR) and a name"})
			}
		}
		// a name the servers hold asked for far more often than its TTL lets a client that caches ask
		for _, top := range m.stats.TopDomains {
			name := cleanName(top.Name)
			ttl, held := a.ttlOf(name)
			if allowed := max(1, int(notFoundWindow/time.Second)/max(1, ttl)); held && top.Hits >= notCachingAsked && top.Hits > allowed*notCachingSlack {
				found = append(found, finding{Problem: "client_not_caching", Zone: a.zoneOf(name), Name: name, Detail: fmt.Sprintf("%s was asked for %d times in the last day, where its TTL of %d seconds lets a client that caches ask %d times: whatever asks does not keep the answer, or many things ask at once", name, top.Hits, ttl, allowed), Fix: "see who asks (log_search by name, counted by client) and have it cache, or give the record a longer TTL (record_set)"})
			}
		}
		if len(m.stats.TopClients) > 0 && total.Queries >= oneClientAsked {
			if top := m.stats.TopClients[0]; top.Hits*100 >= total.Queries*oneClientShare {
				found = append(found, finding{Problem: "one_client", Name: top.Name, Detail: fmt.Sprintf("%s asked %d of the last day's %d queries, %d in every hundred: one machine asking for most of everything is usually a loop or a broken program, or another resolver forwarding everyone's queries", machine(top.Name, top.Domain), top.Hits, total.Queries, top.Hits*100/total.Queries), Fix: "see what it asks for (the log of queries, by client): a resolver in front of this server is as it should be, and anything else wants looking at"})
			}
		}

		return found
	})

	// a name counts where it is under a zone a server holds: what does not exist elsewhere is not theirs to add
	var names []string
	for name, n := range notFound {
		if n >= notFoundOften {
			names = append(names, name)
		}
	}
	slices.SortFunc(names, func(x, y string) int {
		if notFound[x] != notFound[y] {
			return notFound[y] - notFound[x]
		}

		return strings.Compare(x, y)
	})
	said := 0
	for _, name := range names {
		zone := a.zoneOf(name)
		if zone == "" || said == notFoundMost {
			continue
		}
		said++
		found = append(found, finding{Problem: "name_not_found", Zone: zone, Name: name, Detail: fmt.Sprintf("%s was asked for %d times in the last day and does not exist in %s: something is set to use a name that was never made, was removed, or is misspelt", name, notFound[name], zone), Fix: "see who asks (the log of queries, by name); add the record if the name is meant to be there (record_set), or put the name right where it is used"})
	}

	return found
}

// ttlOf is the shortest TTL of the address and alias records at a name in
// the zones the servers asked hold, and whether any server holds the name.
func (a *audited) ttlOf(name string) (ttl int, held bool) {
	for _, v := range a.views {
		z := v.zoneFor(name)
		if z == nil {
			continue
		}
		for _, rec := range z.records[name] {
			switch rec.Type {
			case "A", "AAAA", "CNAME", "HTTPS", "SVCB":
				if !held || rec.TTL < ttl {
					ttl, held = rec.TTL, true
				}
			default:
			}
		}
	}

	return ttl, held
}

// zoneOf is the closest zone the servers asked hold for a name, "" when
// they hold none.
func (a *audited) zoneOf(name string) string {
	var closest string
	for _, zone := range a.inv.zones {
		held := cleanName(zone.name)
		if (name == held || strings.HasSuffix(name, "."+held)) && len(held) > len(closest) {
			closest = held
		}
	}

	return closest
}

// auditApps finds where the apps the servers run are not what they should
// be: one behind the version the store has, one a server runs that another
// does not, and one the servers run with different versions or different
// configurations.
func auditApps(a *audited) []finding {
	found := a.onEach(func(_ string, m *moreRead) []finding {
		var found []finding
		for _, app := range m.apps {
			i := slices.IndexFunc(m.store, func(offered technitium.StoreApp) bool { return strings.EqualFold(offered.Name, app.Name) })
			if i >= 0 && (m.store[i].UpdateAvailable || m.store[i].Version != app.Version) {
				found = append(found, finding{Problem: "app_update", Name: app.Name, Detail: fmt.Sprintf("the app %s is installed at version %s and the store has %s", app.Name, app.Version, m.store[i].Version), Fix: "update it (app_install by its name), which keeps its configuration"})
			}
		}

		return found
	})

	// across the servers asked: who runs what, at which version and configured how
	type held struct{ version, config string }
	apps := map[string]map[string]held{}
	var asked []string
	for _, v := range a.views {
		m := a.more[v.server]
		if m == nil || m.apps == nil {
			continue
		}
		asked = append(asked, v.server)
		for _, app := range m.apps {
			if apps[app.Name] == nil {
				apps[app.Name] = map[string]held{}
			}
			apps[app.Name][v.server] = held{version: app.Version, config: m.configs[app.Name]}
		}
	}
	if len(asked) < 2 {
		return found
	}
	for _, name := range slices.Sorted(maps.Keys(apps)) {
		on := apps[name]
		var has, lacks, versions []string
		configs := map[string]bool{}
		for _, server := range asked {
			h, installed := on[server]
			if !installed {
				lacks = append(lacks, server)

				continue
			}
			has = append(has, server)
			versions = append(versions, server+" has "+h.version)
			configs[h.config] = true
		}
		if len(lacks) > 0 {
			found = append(found, finding{Problem: "app_only_on", Name: name, Detail: fmt.Sprintf("the app %s is installed on %s and not on %s: what it does there, the others do not", name, orNone(has), orNone(lacks)), Fix: "install it on the others (app_install) if they are meant to answer alike; a cluster's primary gives its apps to every node by itself", Servers: has})

			continue
		}
		first := on[asked[0]].version
		if slices.ContainsFunc(asked, func(server string) bool { return on[server].version != first }) {
			found = append(found, finding{Problem: "app_versions_differ", Name: name, Detail: fmt.Sprintf("the app %s is not at one version on every server: %s", name, strings.Join(versions, ", ")), Fix: "update it where it is behind (app_install by its name)"})
		}
		if len(configs) > 1 {
			found = append(found, finding{Problem: "app_config_differs", Name: name, Detail: fmt.Sprintf("the app %s is not configured alike on every server, so it does not do the same on each", name), Fix: "read its configuration on each (app_config_get), settle which is meant, and write that to the others (app_config_set)"})
		}
	}

	return found
}
