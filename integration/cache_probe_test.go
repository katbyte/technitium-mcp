//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// What a change to a server does to its cache, which is not written down
// anywhere: making or deleting a zone can empty it, whole, and nothing else
// here does. A reverse zone does, and a zone under a top-level domain
// nothing kept is under; a zone beside what is kept did not with one answer
// kept and did with several. The rule behind that was not found, so the
// tools say only that a zone made or deleted can empty the cache. The first
// server keeps an answer it got through a forwarder to the second; after
// each kind of change it is looked for again.
//
// It is why this test and TestCache do not run beside the others: those make
// zones, and would empty the cache under them.
//
//nolint:paralleltest // it watches the server's cache, which a test running beside it would empty
func TestWhatEmptiesTheCache(t *testing.T) {
	ready(t)
	if world.Topology == testenv.Single {
		t.Skip("one server has nothing to forward to, so nothing to keep")
	}
	const z, w, reverse = "sdk-emptied.test", "sdk-emptier.test", "4.7.10.in-addr.arpa"
	c, second := first(t), server(t, world.Second)
	zone(t, second, z)
	if _, err := second.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "a." + z, Type: "A", Data: technitium.RData{"ipAddress": "10.5.5.8"}}); err != nil {
		t.Fatal(err)
	}
	makeZone(t, c, technitium.NewZone{Name: z, Type: technitium.ZoneForwarder, Forwarder: world.Address(world.Second)})
	zone(t, c, w)

	kept := func() bool {
		t.Helper()
		held, err := c.Cache(t.Context(), "a."+z)
		if err != nil {
			t.Fatal(err)
		}

		return len(held.Records) > 0
	}
	fill := func() {
		t.Helper()
		if _, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "a." + z}); err != nil {
			t.Fatal(err)
		}
		if !kept() {
			t.Fatal("the answer was resolved and is not kept")
		}
	}
	step := func(what string, empties bool, do func() error) {
		t.Helper()
		fill()
		if err := do(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if got := !kept(); got != empties {
			t.Errorf("after %s the cache is emptied: %v, and it was %v when this was written: what the tools and api-defs/README.md say of it needs another look", what, got, empties)
		}
	}

	add := func(name, recordType string, data technitium.RData, ptr bool) func() error {
		return func() error {
			_, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: w, Name: name, Type: recordType, Data: data, PTR: ptr})

			return err
		}
	}
	step("making a reverse zone", true, func() error {
		_, err := c.CreateZone(t.Context(), technitium.NewZone{Name: reverse, Type: technitium.ZonePrimary})

		return err
	})
	step("adding an address with its PTR", false, add("a."+w, "A", technitium.RData{"ipAddress": "10.7.4.4"}, true))
	step("adding a delegation", false, add("sub."+w, "NS", technitium.RData{"nameServer": "ns.elsewhere.test"}, false))
	step("adding a DNAME", false, add("d."+w, "DNAME", technitium.RData{"dname": "one.test"}, false))
	step("adding an ANAME", false, add("an."+w, "ANAME", technitium.RData{"aname": "a." + w}, false))
	step("adding a CNAME", false, add("c."+w, "CNAME", technitium.RData{"cname": "a." + w}, false))
	step("adding a TXT", false, add(w, "TXT", technitium.RData{"text": "hello"}, false))
	step("deleting the reverse zone", true, func() error { return c.DeleteZone(t.Context(), reverse) })
	step("making an ordinary zone", false, func() error {
		_, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "another." + w, Type: technitium.ZonePrimary})

		return err
	})
	step("deleting an ordinary zone", false, func() error { return c.DeleteZone(t.Context(), "another."+w) })
	step("listing zones with a filter", false, func() error {
		_, err := c.Zones(t.Context(), technitium.ZoneFilter{Name: "*." + w})

		return err
	})
	step("resolving another name", false, func() error {
		_, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: "nope." + w})

		return err
	})
	step("asking for an update", false, func() error {
		_, err := c.CheckForUpdate(t.Context())

		return err
	})
	// a zone under another top-level domain than anything kept: emptied, as for a reverse zone
	step("making a zone under another top-level domain", true, func() error {
		_, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "sdk-emptier.example", Type: technitium.ZonePrimary})

		return err
	})
	step("deleting a zone under another top-level domain", true, func() error { return c.DeleteZone(t.Context(), "sdk-emptier.example") })

	// what the tools that change a zone, a scope and the blocking do
	step("setting a zone's options", false, func() error {
		return c.SetZoneOptions(t.Context(), w, technitium.ZoneChange{ZoneTransfer: technitium.PolicyAllow, Notify: technitium.NotifyNone})
	})
	step("switching a zone off", false, func() error { return c.SetZoneOptions(t.Context(), w, technitium.ZoneChange{Disabled: new(true)}) })
	step("switching a zone on", false, func() error { return c.SetZoneOptions(t.Context(), w, technitium.ZoneChange{Disabled: new(false)}) })
	step("setting a zone's SOA", false, func() error {
		at, err := c.RecordsAt(t.Context(), w, w)
		if err != nil {
			return err
		}
		for i := range at.Records {
			if at.Records[i].Type == "SOA" {
				soa := at.Records[i].SOA()
				soa.Refresh = 600
				_, err = c.UpdateSOA(t.Context(), w, &at.Records[i], soa)
			}
		}

		return err
	})
	// the blocking this test switches is left as it was, and in a cluster the second node given time to follow
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		_ = c.DeleteScope(ctx, "sdk-emptier")
		_, _ = c.SetBlocking(ctx, true)
		_, _ = c.SetBlockLists(ctx, nil)
		blockingSettled(ctx, t)
	})
	step("making a scope", false, func() error {
		return c.SetScope(t.Context(), technitium.NewScope{Name: "sdk-emptier", StartingAddress: "10.78.0.10", EndingAddress: "10.78.0.20", SubnetMask: "255.255.255.0"})
	})
	step("switching a scope off", false, func() error { return c.DisableScope(t.Context(), "sdk-emptier") })
	step("switching a scope on", false, func() error { return c.EnableScope(t.Context(), "sdk-emptier") })
	step("deleting a scope", false, func() error { return c.DeleteScope(t.Context(), "sdk-emptier") })
	step("blocking a name", false, func() error { return c.BlockName(t.Context(), "ads.sdk-emptier.example") })
	step("unblocking a name", false, func() error { return c.UnblockName(t.Context(), "ads.sdk-emptier.example") })
	step("switching blocking off", false, func() error {
		_, err := c.SetBlocking(t.Context(), false)

		return err
	})
	step("switching blocking on", false, func() error {
		_, err := c.SetBlocking(t.Context(), true)

		return err
	})
	step("pausing blocking", false, func() error {
		_, err := c.PauseBlocking(t.Context(), 1)

		return err
	})
	step("ending a pause", false, func() error {
		_, err := c.SetBlocking(t.Context(), true)

		return err
	})
	step("setting a block list", false, func() error {
		_, err := c.SetBlockLists(t.Context(), []string{"http://127.0.0.1:9/sdk-emptier.txt"})

		return err
	})
	step("clearing the block lists", false, func() error {
		_, err := c.SetBlockLists(t.Context(), nil)

		return err
	})

	// with more kept - a CNAME, the address it leads to, and the answer that a name is not there - a zone made under the same top-level domain empties it too, where with the one address kept it did not
	if _, err := second.AddRecord(t.Context(), technitium.NewRecord{Zone: z, Name: "c." + z, Type: "CNAME", Data: technitium.RData{"cname": "a." + z}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"c." + z, "nope." + z} {
		if _, err := c.Resolve(t.Context(), technitium.ResolveQuery{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	if !kept() {
		t.Fatal("the answers were resolved and are not kept")
	}
	if _, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "another2." + w, Type: technitium.ZonePrimary}); err != nil {
		t.Fatal(err)
	}
	if kept() {
		t.Error("after an ordinary zone was made with several answers kept, they are still kept: it emptied the cache when this was written, which zone_create says a zone made can do")
	}
	if err := c.DeleteZone(t.Context(), "another2."+w); err != nil {
		t.Error(err)
	}
}
