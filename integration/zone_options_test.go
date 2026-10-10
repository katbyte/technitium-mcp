//go:build integration

package integration

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// A zone's options as a server gives them, its policies set one at a time
// with the rest left as they were, the zone exported as a zone file, and the
// sessions and tokens a server lists - the one these tests use among them.
func TestZoneOptionsAndExport(t *testing.T) {
	t.Parallel()

	c := first(t)
	const z = "sdk-options.test"
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	zone(t, c, z)
	if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: z, Name: "a." + z, Type: "A", Comments: "a host", Data: technitium.RData{"ipAddress": "10.4.4.6"}}); err != nil {
		t.Fatal(err)
	}

	// a new primary: anyone may ask, its own name servers may transfer it and are told of a change, and nobody may update it
	got, err := c.ZoneOptions(ctx, z)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != z || got.Type != technitium.ZonePrimary || got.Disabled || got.Catalog != "" || got.QueryAccess != technitium.PolicyAllow || got.ZoneTransfer != "AllowOnlyZoneNameServers" || got.Notify != "ZoneNameServers" || got.Update != technitium.PolicyDeny || got.NotifyFailed || len(got.UpdateSecurityPolicies) != 0 || len(got.PrimaryNameServerAddresses) != 0 {
		t.Errorf("a new primary's options = %+v: audit_zones and audit_security read them for these", got)
	}

	// one policy set leaves the others as they were
	if err := c.SetZoneOptions(ctx, z, technitium.ZoneChange{ZoneTransfer: technitium.PolicyAllow, Update: technitium.PolicyAllow}); err != nil {
		t.Fatal(err)
	}
	if got, err = c.ZoneOptions(ctx, z); err != nil || got.ZoneTransfer != technitium.PolicyAllow || got.Update != technitium.PolicyAllow || got.Notify != "ZoneNameServers" || got.QueryAccess != technitium.PolicyAllow {
		t.Errorf("after its transfer and update policies were set = %+v, %v", got, err)
	}
	if err := c.SetZoneOptions(ctx, z, technitium.ZoneChange{Notify: technitium.NotifyNone}); err != nil {
		t.Fatal(err)
	}
	if got, err = c.ZoneOptions(ctx, z); err != nil || got.Notify != technitium.NotifyNone || got.ZoneTransfer != technitium.PolicyAllow || got.Update != technitium.PolicyAllow {
		t.Errorf("after its notify policy was set = %+v, %v: setting one policy no longer leaves the others", got, err)
	}
	// a policy the server does not know is passed over without a word: it says ok, and nothing is changed
	if err := c.SetZoneOptions(ctx, z, technitium.ZoneChange{ZoneTransfer: "Whoever"}); err != nil {
		t.Errorf("a policy there is none of = %v: the server refused it, where it said ok and changed nothing when this was written", err)
	}
	if got, err = c.ZoneOptions(ctx, z); err != nil || got.ZoneTransfer != technitium.PolicyAllow {
		t.Errorf("after a policy there is none of was set, the zone's = %q, %v, want it as it was", got.ZoneTransfer, err)
	}

	// exported: a zone file, with the record's comment
	text, err := c.ExportZone(ctx, z)
	if err != nil || !strings.HasPrefix(text, "$ORIGIN "+z+".") || !strings.Contains(text, "SOA") || !strings.Contains(text, "10.4.4.6") || !strings.Contains(text, ";a host") {
		t.Errorf("ExportZone = %q, %v", text, err)
	}
	if _, err := c.ExportZone(ctx, "sdk-no-such-zone.test"); err == nil || !strings.Contains(err.Error(), "No such zone was found") {
		t.Errorf("a zone that is not there, exported = %v", err)
	}
	if _, err := c.ZoneOptions(ctx, "sdk-no-such-zone.test"); err == nil || !strings.Contains(err.Error(), "No such zone was found") {
		t.Errorf("the options of a zone that is not there = %v", err)
	}

	// a copy a cluster's catalog made says which catalog and how it transfers, and names no primary of its own: where it transfers from is the catalog's to say
	if world.Topology == testenv.Cluster {
		copied, err := server(t, world.Second).ZoneOptions(ctx, testenv.ClusterDomain)
		if err != nil || copied.Type != technitium.ZoneSecondary || copied.Catalog != testenv.ClusterCatalog || copied.PrimaryZoneTransferProtocol == "" || len(copied.PrimaryNameServerAddresses) != 0 || copied.ZoneTransfer != technitium.PolicyDeny || copied.Notify != technitium.NotifyNone {
			t.Errorf("the options of the cluster's own zone on %s = %+v, %v", world.Second, copied, err)
		}
	}

	// every server lists the token these tests are made with, in use just now, and nothing of the token itself
	for _, name := range world.Names() {
		sessions, err := server(t, name).Sessions(ctx)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(sessions, func(s technitium.OpenSession) bool { return s.IsCurrentSession })
		if i < 0 || sessions[i].Type != technitium.SessionAPIToken || sessions[i].TokenName == "" || sessions[i].Username != "admin" || sessions[i].LastSeenRemoteAddress == "" {
			t.Fatalf("%s: Sessions = %+v, want the token that asked among them", name, sessions)
		}
		if seen, ok := technitium.ParseTime(sessions[i].LastSeen); !ok || time.Since(seen) > time.Hour || time.Since(seen) < -time.Hour {
			t.Errorf("%s: the token that asked was last seen at %q", name, sessions[i].LastSeen)
		}
	}
}
