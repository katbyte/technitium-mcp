//go:build integration

package acceptance

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// What a first setup makes, named so that nothing else in the suite touches it.
const (
	setupJourneyZone    = "acc-j-setup.test"
	setupJourneyReverse = "0.73.10.in-addr.arpa"
	setupJourneyForward = "fwd.acc-j-setup.test"
	setupJourneyScope   = "acc-j-setup"
	setupJourneyUser    = "acc-j-setup"
	setupJourneyGroup   = "acc-j-setup-ops"
	setupJourneyKey     = "acc-j-setup.key"
	setupJourneyToken   = "acc-j-setup-token" //nolint:gosec // the name a token is made under, not a token
	// the names blocked and allowed are under no zone the server holds: a blocked name a zone answers for blocks nothing
	setupJourneyBlocked = "ads.acc-j-setup.example"
	setupJourneyAllowed = "good.acc-j-setup.example"
)

// A setup made from nothing with the tools alone, and taken down again: what
// the server holds is recorded; then, in the order a person would, a zone with
// its records and the reverse zone with their PTRs, a forwarder zone, a DHCP
// scope for the zone, a name blocked and one allowed, a group, an account in
// it with a token and the right to change the zone, a transfer key, a setting
// changed and the zone signed; every audit is run and finds nothing of the
// journey's own but the one thing a freshly signed zone must carry, its DS
// record waiting for the parent; then each piece is taken down in the order
// that lets it go, and the server holds exactly what it held before.
//
//nolint:paralleltest // it makes and deletes zones, a scope, an account and a group, and changes a setting, under any test running beside it
func TestJourneySetupAndTeardown(t *testing.T) {
	names(t)
	first := world.First
	c := mustClient(t, first)
	ctx := context.WithoutCancel(t.Context())
	// whatever a run before left, and whatever this one leaves should it stop part way: the setting it changes is put back once it is known
	var trigger string
	remove := func() {
		if trigger != "" {
			_, _ = c.SetSettings(ctx, map[string]string{"cachePrefetchTrigger": trigger})
		}
		for _, srv := range world.Set.Every() {
			for _, zone := range []string{setupJourneyForward, setupJourneyReverse, setupJourneyZone} {
				_ = srv.Client.DeleteZone(ctx, zone)
			}
		}
		_ = c.DeleteScope(ctx, setupJourneyScope)
		_ = c.UnblockName(ctx, setupJourneyBlocked)
		_ = c.UnallowName(ctx, setupJourneyAllowed)
		_ = c.DeleteUser(ctx, setupJourneyUser)
		_ = c.DeleteGroup(ctx, setupJourneyGroup)
		_ = c.DeleteTSIGKey(ctx, setupJourneyKey)
	}
	remove()
	t.Cleanup(remove)
	before := heldByServer(t, c)
	settings, err := c.AllSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	trigger = fmt.Sprint(settings["cachePrefetchTrigger"])

	// the zones: the one, the reverse zone for its addresses, and a forwarder zone for a network elsewhere
	suite.Call(t, "zone_create", on(map[string]any{"zone": setupJourneyZone}))
	if made := suite.Call(t, "zone_create", on(map[string]any{"zone": "10.73.0.0/24"})); made["zone"] != setupJourneyReverse {
		t.Fatalf("the reverse zone made for 10.73.0.0/24 = %v", made["zone"])
	}
	suite.Call(t, "zone_create", on(map[string]any{"zone": setupJourneyForward, "type": "Forwarder", "empty_forwarder": true}))
	// its records: two hosts with their PTRs, mail for the zone, its SPF, and an alias
	suite.Call(t, "record_set", on(map[string]any{"name": "www." + setupJourneyZone, "type": "A", "value": "10.73.0.10", "ptr": true, "comment": "the web server"}))
	suite.Call(t, "record_set", on(map[string]any{"name": "mail." + setupJourneyZone, "type": "A", "value": "10.73.0.20", "ptr": true}))
	suite.Call(t, "record_set", on(map[string]any{"name": setupJourneyZone, "type": "MX", "value": "10 mail." + setupJourneyZone}))
	suite.Call(t, "record_set", on(map[string]any{"name": setupJourneyZone, "type": "TXT", "value": "v=spf1 mx -all"}))
	suite.Call(t, "record_set", on(map[string]any{"name": "web." + setupJourneyZone, "type": "CNAME", "value": "www." + setupJourneyZone}))
	for name, recordType := range map[string]string{"www." + setupJourneyZone: "A", "mail." + setupJourneyZone: "A", setupJourneyZone: "MX", "web." + setupJourneyZone: "CNAME", "10.0.73.10.in-addr.arpa": "PTR", "20.0.73.10.in-addr.arpa": "PTR"} {
		zone := setupJourneyZone
		if recordType == "PTR" {
			zone = setupJourneyReverse
		}
		if got := onServer(t, first, zone, name, recordType); len(got) != 1 {
			t.Errorf("the server holds %s %s as %v", name, recordType, got)
		}
	}

	// the scope for the zone's network, telling machines they are in the zone and to resolve through these servers
	scope := map[string]any{"scope": setupJourneyScope, "first": "10.73.0.100", "last": "10.73.0.150", "mask": "24", "router": "10.73.0.1", "domain": setupJourneyZone, "dns_updates": true, "lease_time": "1d"}
	var dns []string
	for _, name := range names(t) {
		if address := world.Address(name); address != "" {
			dns = append(dns, address)
		}
	}
	if len(dns) > 0 {
		scope["dns_servers"] = dns
	}
	suite.Call(t, "dhcp_scope_set", on(scope))
	if scopes, err := c.Scopes(t.Context()); err != nil || !slices.ContainsFunc(scopes, func(s technitium.Scope) bool { return s.Name == setupJourneyScope }) {
		t.Fatalf("the server's scopes = %v, %v", scopes, err)
	}

	// what is blocked and what is let through, a group, an account in it with a token and the right to change the zone, and a key a copy could transfer with
	suite.Call(t, "block_set", on(map[string]any{"name": setupJourneyBlocked}))
	suite.Call(t, "block_set", on(map[string]any{"name": setupJourneyAllowed, "list": "allowed"}))
	suite.Call(t, "group_set", on(map[string]any{"group": setupJourneyGroup, "description": "runs " + setupJourneyZone}))
	suite.Call(t, "user_set", on(map[string]any{"username": setupJourneyUser, "new_password": "a first setup passw0rd", "display_name": "Setup Operator", "groups": []string{setupJourneyGroup}}))
	suite.Call(t, "token_create", on(map[string]any{"username": setupJourneyUser, "token_name": setupJourneyToken}))
	suite.Call(t, "access_set", on(map[string]any{"zone": setupJourneyZone, "groups": []map[string]any{{"name": setupJourneyGroup, "view": true, "modify": true}}}))
	suite.Call(t, "tsig_key_set", on(map[string]any{"name": setupJourneyKey}))
	// a setting, and the zone signed
	suite.Call(t, "settings_set", on(map[string]any{"settings": map[string]string{"cachePrefetchTrigger": "11"}}))
	suite.Call(t, "dnssec_sign", on(map[string]any{"zone": setupJourneyZone, "nx_proof": "NSEC3"}))
	if users, err := c.Users(t.Context()); err != nil || !slices.ContainsFunc(users, func(u technitium.User) bool { return u.Username == setupJourneyUser }) {
		t.Fatalf("the server's accounts = %v, %v", users, err)
	}
	if keys, err := c.TSIGKeyNames(t.Context()); err != nil || !slices.Contains(keys, setupJourneyKey) {
		t.Fatalf("the server's transfer keys = %v, %v", keys, err)
	}

	// the audits find nothing of the journey's own, but for what a signed zone carries once its key is ready: its DS record waiting for the parent, which the server takes a while to come to
	all := suite.Call(t, "audit_all", on(map[string]any{"zone": setupJourneyZone}))
	for _, row := range acctest.Rows(t, all["audits"], "audits") {
		if row["audit"] != "audit_dnssec" && acctest.Num(t, row["total"], "total") != 0 {
			t.Errorf("%v finds %v in the setup: %v", row["audit"], row["total"], suite.Call(t, acctest.Str(row["audit"]), on(map[string]any{"zone": setupJourneyZone}))["findings"])
		}
	}
	if found, _ := findings(t, "audit_dnssec", on(map[string]any{"zone": setupJourneyZone})); len(found) > 1 || (len(found) == 1 && found[0]["problem"] != "ds_wanted_at_parent") {
		t.Errorf("audit_dnssec on the freshly signed zone = %v, want nothing or its DS record waiting for the parent", found)
	}
	// and nothing of the journey's own among what is not a zone's: the scope, the lists, the accounts, the keys
	for _, audit := range []string{"audit_dhcp", "audit_blocking", "audit_access", "audit_security", "audit_reverse"} {
		found, _ := findings(t, audit, on(map[string]any{"zone": "*"}))
		for _, f := range found {
			if text := acctest.Str(f["name"]) + " " + acctest.Str(f["zone"]) + " " + acctest.Str(f["detail"]); strings.Contains(text, "acc-j-setup") {
				t.Errorf("%s finds something of the setup: %v", audit, f)
			}
		}
	}

	// taken down in the order that lets each go: the records with their PTRs, the zones, the scope, the lists, the token, the account, the group, the key, and the setting put back
	suite.Call(t, "record_delete", on(map[string]any{"name": "web." + setupJourneyZone, "type": "CNAME"}))
	suite.Call(t, "record_delete", on(map[string]any{"name": "www." + setupJourneyZone, "type": "A", "ptr": true}))
	suite.Call(t, "record_delete", on(map[string]any{"name": "mail." + setupJourneyZone, "type": "A", "ptr": true}))
	if got := onServer(t, first, setupJourneyReverse, "10.0.73.10.in-addr.arpa", "PTR"); len(got) != 0 {
		t.Errorf("the PTR went with its host, and the server holds %v", got)
	}
	for _, zone := range []string{setupJourneyForward, setupJourneyReverse, setupJourneyZone} {
		if dry := suite.Call(t, "zone_delete", on(map[string]any{"zone": zone, "dry_run": true})); !acctest.BoolOf(dry["changed"]) && len(acctest.Strs(t, dry["changes"], "changes")) != 1 {
			t.Errorf("a dry run of deleting %s = %v", zone, dry)
		}
		suite.Call(t, "zone_delete", on(map[string]any{"zone": zone}))
	}
	suite.Call(t, "dhcp_scope_delete", on(map[string]any{"scope": setupJourneyScope}))
	suite.Call(t, "block_delete", on(map[string]any{"name": setupJourneyBlocked}))
	suite.Call(t, "block_delete", on(map[string]any{"name": setupJourneyAllowed, "list": "allowed"}))
	sessions := acctest.Rows(t, rowOn(t, suite.Call(t, "session_list", on(map[string]any{})), first)["sessions"], "sessions")
	if i := slices.IndexFunc(sessions, func(row map[string]any) bool { return row["token_name"] == setupJourneyToken }); i < 0 {
		t.Errorf("the token made is in no session: %v", sessions)
	} else {
		suite.Call(t, "session_delete", on(map[string]any{"id": sessions[i]["id"]}))
	}
	suite.Call(t, "user_delete", on(map[string]any{"username": setupJourneyUser}))
	suite.Call(t, "group_delete", on(map[string]any{"group": setupJourneyGroup}))
	suite.Call(t, "tsig_key_delete", on(map[string]any{"name": setupJourneyKey}))
	suite.Call(t, "settings_set", on(map[string]any{"settings": map[string]string{"cachePrefetchTrigger": trigger}}))

	if after := heldByServer(t, c); after != before {
		t.Errorf("the server does not hold what it held before the setup was made and taken down:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
