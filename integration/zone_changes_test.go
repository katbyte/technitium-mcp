//go:build integration

package integration

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// A zone changed: its policies with the lists they read, a list cleared, the
// zone switched off and on, its SOA set to name another primary, and a copy
// resynced - each read back, since the server says ok to much it does not do.
func TestZoneChanges(t *testing.T) {
	t.Parallel()

	c := first(t)
	const z = "sdk-changes.test"
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	zone(t, c, z)

	// each policy with its list
	if err := c.SetZoneOptions(ctx, z, technitium.ZoneChange{QueryAccess: "AllowOnlyPrivateNetworks", ZoneTransfer: "UseSpecifiedNetworkACL", ZoneTransferNetworks: []string{"10.0.0.3", "10.0.5.0/24"}, Notify: "SpecifiedNameServers", NotifyNameServers: []string{"10.0.0.3"}, Update: "UseSpecifiedNetworkACL", UpdateNetworks: []string{"10.0.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	got, err := c.ZoneOptions(ctx, z)
	if err != nil || got.QueryAccess != "AllowOnlyPrivateNetworks" || got.ZoneTransfer != "UseSpecifiedNetworkACL" || !slices.Equal(got.ZoneTransferNetworkACL, []string{"10.0.0.3", "10.0.5.0/24"}) || got.Notify != "SpecifiedNameServers" || !slices.Equal(got.NotifyNameServers, []string{"10.0.0.3"}) || got.Update != "UseSpecifiedNetworkACL" || !slices.Equal(got.UpdateNetworkACL, []string{"10.0.0.0/24"}) {
		t.Errorf("the options after each policy was set = %+v, %v", got, err)
	}
	// an empty list clears one, and the others stay
	if err := c.SetZoneOptions(ctx, z, technitium.ZoneChange{ZoneTransferNetworks: []string{}, NotifyNameServers: []string{}}); err != nil {
		t.Fatal(err)
	}
	if got, err = c.ZoneOptions(ctx, z); err != nil || len(got.ZoneTransferNetworkACL) != 0 || len(got.NotifyNameServers) != 0 || !slices.Equal(got.UpdateNetworkACL, []string{"10.0.0.0/24"}) || got.ZoneTransfer != "UseSpecifiedNetworkACL" {
		t.Errorf("the options after two lists were cleared = %+v, %v", got, err)
	}

	// switched off and on
	held := func() technitium.Zone {
		t.Helper()
		zones, listErr := c.Zones(ctx, technitium.ZoneFilter{})
		if listErr != nil {
			t.Fatal(listErr)
		}

		return zones[slices.IndexFunc(zones, func(zone technitium.Zone) bool { return zone.Name == z })]
	}
	if err := c.SetZoneOptions(ctx, z, technitium.ZoneChange{Disabled: new(true)}); err != nil || !held().Disabled {
		t.Errorf("the zone switched off = %+v, %v", held(), err)
	}
	if err := c.SetZoneOptions(ctx, z, technitium.ZoneChange{Disabled: new(false)}); err != nil || held().Disabled {
		t.Errorf("the zone switched back on = %+v, %v", held(), err)
	}

	// its SOA: another primary named, another mailbox and other times; its TTL kept, and the serial the server's to count
	soa := func() *technitium.Record {
		t.Helper()
		at, readErr := c.RecordsAt(ctx, z, z)
		if readErr != nil {
			t.Fatal(readErr)
		}

		return &at.Records[slices.IndexFunc(at.Records, func(rec technitium.Record) bool { return rec.Type == "SOA" })]
	}
	before := soa()
	want := before.SOA()
	if want.Primary != world.Domain(world.First) || want.Refresh == 0 || want.Expire == 0 {
		t.Fatalf("a new zone's SOA = %+v, want it to name the server that made it", want)
	}
	want.Primary, want.Responsible, want.Refresh, want.Minimum = "renamed."+z, "ops@"+z, 600, 300
	updated, err := c.UpdateSOA(ctx, z, before, want)
	if err != nil {
		t.Fatal(err)
	}
	after := soa()
	if now := after.SOA(); now.Primary != want.Primary || now.Responsible != want.Responsible || now.Refresh != 600 || now.Minimum != 300 || now.Retry != want.Retry || now.Expire != want.Expire || now.Serial < before.SOA().Serial || after.TTL != before.TTL || updated.SOA().Primary != want.Primary {
		t.Errorf("the SOA after it was set = %+v (ttl %d), answered as %+v, want %+v at the ttl %d it had", now, after.TTL, updated.SOA(), want, before.TTL)
	}

	// only a copy is resynced
	if err := c.ResyncZone(ctx, z); err == nil || !strings.Contains(err.Error(), "Secondary") {
		t.Errorf("a primary resynced = %v, want it refused as no copy", err)
	}
	if world.Topology == testenv.Cluster {
		second := server(t, world.Second)
		if err := second.ResyncZone(ctx, testenv.ClusterDomain); err != nil {
			t.Fatalf("resyncing the cluster's own zone on %s: %v", world.Second, err)
		}
		if !acctest.EventuallyWithin(time.Minute, func() bool {
			zones, listErr := second.Zones(ctx, technitium.ZoneFilter{})
			i := slices.IndexFunc(zones, func(zone technitium.Zone) bool { return zone.Name == testenv.ClusterDomain })

			return listErr == nil && i >= 0 && !zones[i].SyncFailed && !zones[i].IsExpired && zones[i].SOASerial > 0
		}) {
			t.Errorf("%s does not hold the cluster's own zone whole after it was resynced", world.Second)
		}
	}
}
