//go:build integration

package integration

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// A server's DHCP: its scopes, a scope whole, its reservations and the
// leases machines hold - which are real ones, asked for by a DHCP client on
// the servers' own network - and what all of it does to the server's zones,
// most of which is written down nowhere:
//
//   - a reservation or a lease with a host name is recorded under the scope's
//     domain with its PTR, in a zone the server makes itself when none holds
//     the domain
//   - a reservation's name is written over a record already at it, where a
//     lease's is not
//   - the server takes a reservation outside its scope's network, or for an
//     address already reserved
//   - a reservation removed takes its records with it though a machine still
//     holds the lease, a reserved lease removed takes its reservation, and a
//     scope deleted leaves its reservations' records behind
//
// The tools are written to these, and say so; a server that stops doing one
// fails here first.
func TestDHCP(t *testing.T) {
	t.Parallel()

	ready(t)
	// a new server has the scope it ships with, switched off, and no leases
	for _, name := range world.Names() {
		c := server(t, name)
		scopes, err := c.Scopes(t.Context())
		if err != nil || !slices.ContainsFunc(scopes, func(s technitium.Scope) bool {
			return s.Name == "Default" && !s.Enabled && s.StartingAddress != "" && s.SubnetMask != "" && s.NetworkAddress != ""
		}) {
			t.Errorf("%s: Scopes = %+v, %v, want the Default scope a server ships with, switched off", name, scopes, err)
		}
		if _, err := c.Leases(t.Context()); err != nil {
			t.Errorf("%s: Leases: %v", name, err)
		}
	}

	c := first(t)
	pool, leasing := world.Pool()
	if !leasing {
		t.Skip("the environment names no network to lease on: scripts/testenv.sh gives one")
	}
	const scope, domain = "sdk-dhcp", "sdk-leased.test"
	const printer, laptop, absent, taken, phone, pinned, twin, outside = "02-42-AC-00-DD-01", "02-42-AC-00-DD-02", "02-42-AC-00-DD-03", "02-42-AC-00-DD-04", "02-42-AC-00-DD-05", "02-42-AC-00-DD-06", "02-42-AC-00-DD-07", "02-42-AC-00-DD-08"
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	// a run that was cut short may have left them behind
	_ = c.DeleteScope(ctx, scope)
	_ = c.DeleteZone(ctx, domain)
	t.Cleanup(func() {
		_ = c.DeleteScope(ctx, scope)
		_ = c.DeleteZone(ctx, domain)
	})
	zone(t, c, pool.ReverseZone())

	// records are every address and PTR in the scope's zones, as name=value
	records := func() []string {
		t.Helper()
		var out []string
		for _, z := range []string{domain, pool.ReverseZone()} {
			read, err := c.ZoneRecords(ctx, z)
			if err != nil {
				continue
			}
			for i := range read.Records {
				if rec := &read.Records[i]; rec.Type == "A" || rec.Type == "PTR" {
					out = append(out, rec.Name+"="+rec.Value())
				}
			}
		}

		return out
	}
	both := func(host, address string) []string {
		return []string{host + "." + domain + "=" + address, reverseOf(t, address) + "=" + host + "." + domain}
	}
	has := func(when string, want bool, pairs ...string) {
		t.Helper()
		got := records()
		for _, pair := range pairs {
			if slices.Contains(got, pair) != want {
				t.Errorf("%s: %s recorded: %v, want %v, in %v", when, pair, !want, want, got)
			}
		}
	}
	leases := func() map[string]technitium.Lease {
		t.Helper()
		list, err := c.Leases(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]technitium.Lease{}
		for _, l := range list {
			if l.Scope == scope {
				out[l.HardwareAddress] = l
			}
		}

		return out
	}
	reserved := func() map[string]technitium.Reservation {
		t.Helper()
		got, err := c.Scope(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]technitium.Reservation{}
		for _, r := range got.ReservedLeases {
			out[r.HardwareAddress] = r
		}

		return out
	}
	reserve := func(r technitium.Reservation) {
		t.Helper()
		if err := c.AddReservation(ctx, scope, r); err != nil {
			t.Fatalf("reserving %s for %s: %v", r.Address, r.HardwareAddress, err)
		}
	}
	lease := func(hardwareAddress, hostName string) {
		t.Helper()
		if err := world.Lease(ctx, strings.ReplaceAll(hardwareAddress, "-", ":"), hostName); err != nil {
			t.Fatal(err)
		}
	}

	// a scope, made enabled, on the interface whose network it is
	want := technitium.NewScope{Name: scope, StartingAddress: pool.First.String(), EndingAddress: pool.Last.String(), SubnetMask: pool.Mask, DomainName: domain, DNSUpdates: new(true), RouterAddress: pool.Subnet.Addr().Next().String(), DNSServers: []string{world.Address(world.First), "10.99.99.99"}, LeaseTimeDays: 1, Exclusions: [][2]string{{pool.At(50), pool.At(59)}}}
	if err := c.SetScope(ctx, want); err != nil {
		t.Fatal(err)
	}
	scopes, err := c.Scopes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.IndexFunc(scopes, func(s technitium.Scope) bool { return s.Name == scope }); i < 0 || !scopes[i].Enabled || scopes[i].StartingAddress != want.StartingAddress || scopes[i].EndingAddress != want.EndingAddress || scopes[i].SubnetMask != pool.Mask || scopes[i].NetworkAddress != pool.Subnet.Addr().String() || scopes[i].BroadcastAddress == "" || scopes[i].InterfaceAddress != world.Address(world.First) {
		t.Errorf("Scopes = %+v, want %s enabled on %s", scopes, scope, world.Address(world.First))
	}
	got, err := c.Scope(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != scope || got.StartingAddress != want.StartingAddress || got.EndingAddress != want.EndingAddress || got.SubnetMask != pool.Mask || got.LeaseTimeDays != 1 || got.LeaseTimeHours != 0 || got.DomainName != domain || !got.DNSUpdates || got.DNSTTL == 0 || got.RouterAddress != want.RouterAddress || got.UseThisDNSServer || !slices.Equal(got.DNSServers, want.DNSServers) || len(got.Exclusions) != 1 || got.Exclusions[0].StartingAddress != pool.At(50) || got.Exclusions[0].EndingAddress != pool.At(59) || len(got.ReservedLeases) != 0 || got.AllowOnlyReservedLeases {
		t.Errorf("Scope = %+v", got)
	}
	// set again with less, it keeps what was left out
	if err := c.SetScope(ctx, technitium.NewScope{Name: scope, StartingAddress: want.StartingAddress, EndingAddress: want.EndingAddress, SubnetMask: pool.Mask}); err != nil {
		t.Fatal(err)
	}
	if got, err = c.Scope(ctx, scope); err != nil || got.DomainName != domain || !got.DNSUpdates || len(got.Exclusions) != 1 || len(got.DNSServers) != 2 {
		t.Errorf("after a scope was set with only its range = %+v, %v: it no longer keeps the rest", got, err)
	}
	// switched off and on, a lease time to the minute, and what a scope has on switched off again
	if err := c.DisableScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if scopes, err = c.Scopes(ctx); err != nil || slices.ContainsFunc(scopes, func(s technitium.Scope) bool { return s.Name == scope && s.Enabled }) {
		t.Errorf("a scope switched off = %+v, %v", scopes, err)
	}
	// set while it is off, a scope stays off: only one that is made is switched on
	if err := c.SetScope(ctx, technitium.NewScope{Name: scope, StartingAddress: want.StartingAddress, EndingAddress: want.EndingAddress, SubnetMask: pool.Mask}); err != nil {
		t.Fatal(err)
	}
	if scopes, err = c.Scopes(ctx); err != nil || slices.ContainsFunc(scopes, func(s technitium.Scope) bool { return s.Name == scope && s.Enabled }) {
		t.Errorf("a scope that is off, set again = %+v, %v: the server now switches it on, which dhcp_scope_set does not expect", scopes, err)
	}
	if err := c.EnableScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if scopes, err = c.Scopes(ctx); err != nil || !slices.ContainsFunc(scopes, func(s technitium.Scope) bool { return s.Name == scope && s.Enabled }) {
		t.Errorf("a scope switched back on = %+v, %v", scopes, err)
	}
	if err := c.SetScope(ctx, technitium.NewScope{Name: scope, StartingAddress: want.StartingAddress, EndingAddress: want.EndingAddress, SubnetMask: pool.Mask, LeaseTime: 36*time.Hour + 30*time.Minute, DNSUpdates: new(false), UseThisDNSServer: new(true), AllowOnlyReservedLeases: new(true)}); err != nil {
		t.Fatal(err)
	}
	if got, err = c.Scope(ctx, scope); err != nil || got.LeaseTimeDays != 1 || got.LeaseTimeHours != 12 || got.LeaseTimeMinutes != 30 || got.DNSUpdates || !got.UseThisDNSServer || !got.AllowOnlyReservedLeases || got.DomainName != domain {
		t.Errorf("after its lease time and three switches were set = %+v, %v", got, err)
	}
	if err := c.SetScope(ctx, technitium.NewScope{Name: scope, StartingAddress: want.StartingAddress, EndingAddress: want.EndingAddress, SubnetMask: pool.Mask, LeaseTimeDays: 1, LeaseTime: 24 * time.Hour, DNSUpdates: new(true), UseThisDNSServer: new(false), AllowOnlyReservedLeases: new(false), DNSServers: want.DNSServers}); err != nil {
		t.Fatal(err)
	}
	if got, err = c.Scope(ctx, scope); err != nil || got.LeaseTimeDays != 1 || got.LeaseTimeHours != 0 || !got.DNSUpdates || got.UseThisDNSServer || got.AllowOnlyReservedLeases || len(got.DNSServers) != 2 {
		t.Errorf("after they were set back = %+v, %v", got, err)
	}
	if err := c.SetScope(ctx, technitium.NewScope{Name: "sdk-dhcp-over", StartingAddress: pool.At(10), EndingAddress: pool.At(20), SubnetMask: pool.Mask}); err == nil || !strings.Contains(err.Error(), "overlapping") {
		_ = c.DeleteScope(ctx, "sdk-dhcp-over")
		t.Errorf("a scope over another's range = %v, want it refused", err)
	}

	// a reservation with a host name is recorded at once, in a zone the
	// server makes for the scope's domain, and is no lease until it is taken
	zones, err := c.Zones(ctx, technitium.ZoneFilter{})
	if err != nil || slices.ContainsFunc(zones, func(z technitium.Zone) bool { return z.Name == domain }) {
		t.Fatalf("%s is there before anything was leased: %v", domain, err)
	}
	reserve(technitium.Reservation{HostName: "printer", HardwareAddress: strings.ToLower(strings.ReplaceAll(printer, "-", ":")), Address: pool.At(40), Comments: "the printer"})
	if r := reserved()[printer]; r != (technitium.Reservation{HostName: "printer", HardwareAddress: printer, Address: pool.At(40), Comments: "the printer"}) {
		t.Errorf("the reservation = %+v, want the hardware address as the server writes one", r)
	}
	if zones, err = c.Zones(ctx, technitium.ZoneFilter{}); err != nil || !slices.ContainsFunc(zones, func(z technitium.Zone) bool { return z.Name == domain && z.Type == technitium.ZonePrimary }) {
		t.Errorf("a reservation with a host name did not make %s: %v: the server no longer makes the zone itself", domain, err)
	}
	has("a reservation nobody holds", true, both("printer", pool.At(40))...)
	if len(leases()) != 0 {
		t.Errorf("a reservation nobody holds is a lease: %+v", leases())
	}
	read, err := c.RecordsAt(ctx, "printer."+domain, domain)
	if err != nil || len(read.Records) != 1 || read.Records[0].Comments != "Via '"+scope+"' DHCP scope" {
		t.Errorf("the record a reservation made = %+v, %v, want its comment naming the scope: audit_dhcp tells the server's records by it", read, err)
	}

	// leases: a machine with a name, one with none, and the one reserved for
	lease(laptop, "laptop")
	lease(outside, "")
	lease(printer, "it-says-otherwise")
	held := leases()
	if l := held[laptop]; l.Type != "Dynamic" || l.HostName != "laptop."+domain || l.ClientIdentifier == "" || !inPool(t, pool.First, pool.Last, l.Address) {
		t.Errorf("the laptop's lease = %+v", l)
	}
	if obtained, ok := technitium.ParseTime(held[laptop].LeaseObtained); !ok {
		t.Errorf("a lease's times are not ones ParseTime reads: %+v", held[laptop])
	} else if expires, ok := technitium.ParseTime(held[laptop].LeaseExpires); !ok || expires.Sub(obtained).Hours() < 23 || expires.Sub(obtained).Hours() > 25 {
		t.Errorf("a day's lease runs from %s to %s", held[laptop].LeaseObtained, held[laptop].LeaseExpires)
	}
	if l := held[outside]; l.Type != "Dynamic" || l.HostName != "" {
		t.Errorf("the lease of a machine that gave no name = %+v", l)
	}
	if l := held[printer]; l.Type != "Reserved" || l.Address != pool.At(40) || l.HostName != "printer."+domain {
		t.Errorf("the printer's lease = %+v, want the address and the name reserved for it", l)
	}
	has("a lease with a name", true, both("laptop", held[laptop].Address)...)

	// a reservation's name is written over a record already there; a lease's is not
	for _, name := range []string{"taken", "phone"} {
		if _, err := c.AddRecord(ctx, technitium.NewRecord{Zone: domain, Name: name + "." + domain, Type: "A", Comments: "by hand", Data: technitium.RData{"ipAddress": "10.9.9.9"}}); err != nil {
			t.Fatal(err)
		}
	}
	reserve(technitium.Reservation{HostName: "taken", HardwareAddress: taken, Address: pool.At(42)})
	lease(phone, "phone")
	has("a reservation named as a record made by hand", true, both("taken", pool.At(42))...)
	has("a reservation named as a record made by hand", false, "taken."+domain+"=10.9.9.9")
	has("a lease named as a record made by hand", true, "phone."+domain+"=10.9.9.9")
	has("a lease named as a record made by hand", false, both("phone", leases()[phone].Address)...)
	if l := leases()[phone]; l.HostName != "phone."+domain {
		t.Errorf("the phone's lease = %+v, want the name it gave though the record at it is another's", l)
	}

	// what the server takes and what it refuses
	reserve(technitium.Reservation{HardwareAddress: outside, Address: "10.1.1.1"})
	reserve(technitium.Reservation{HardwareAddress: twin, Address: pool.At(40)})
	if r := reserved(); r[outside].Address != "10.1.1.1" || r[twin].Address != pool.At(40) || r[printer].Address != pool.At(40) {
		t.Errorf("the server no longer takes a reservation outside its scope's network, or for an address reserved already, which dhcp_reservation_set refuses for it: %+v", r)
	}
	for what, refused := range map[string]struct {
		err  error
		with string
	}{
		"a second reservation for one machine":    {c.AddReservation(ctx, scope, technitium.Reservation{HardwareAddress: printer, Address: pool.At(45)}), "already exists"},
		"a hardware address that is none":         {c.AddReservation(ctx, scope, technitium.Reservation{HardwareAddress: "nonsense", Address: pool.At(46)}), "not in a correct format"},
		"a reservation in no scope":               {c.AddReservation(ctx, "sdk-nope", technitium.Reservation{HardwareAddress: absent, Address: pool.At(46)}), "No such scope exists"},
		"removing a reservation that is not":      {c.RemoveReservation(ctx, scope, "02-42-AC-00-DD-77"), "No such reserved lease"},
		"removing a lease that is not":            {c.RemoveLease(ctx, scope, "02-42-AC-00-DD-77"), "No lease was found"},
		"reading a scope that is not":             {func() error { _, err := c.Scope(ctx, "sdk-nope"); return err }(), "was not found"},
		"removing a lease in a scope that is not": {c.RemoveLease(ctx, "sdk-nope", laptop), ""},
	} {
		if refused.err == nil || !strings.Contains(refused.err.Error(), refused.with) {
			t.Errorf("%s = %v, want it refused with %q", what, refused.err, refused.with)
		}
	}

	// a reservation removed takes its records with it, whether or not a machine holds the lease, and the lease stays
	reserve(technitium.Reservation{HostName: "absent", HardwareAddress: absent, Address: pool.At(41)})
	reserve(technitium.Reservation{HostName: "pinned", HardwareAddress: pinned, Address: pool.At(43)})
	lease(pinned, "pinned")
	has("two more reservations", true, slices.Concat(both("absent", pool.At(41)), both("pinned", pool.At(43)))...)
	for _, machine := range []string{absent, pinned} {
		if err := c.RemoveReservation(ctx, scope, machine); err != nil {
			t.Fatal(err)
		}
	}
	has("their reservations removed", false, slices.Concat(both("absent", pool.At(41)), both("pinned", pool.At(43)))...)
	if r := reserved(); r[absent].Address != "" || r[pinned].Address != "" {
		t.Errorf("the reservations are still there: %+v", r)
	}
	if l := leases()[pinned]; l.Address != pool.At(43) || l.Type != "Reserved" {
		t.Errorf("the lease held under a reservation that was removed = %+v: it was left as it stood, still called Reserved, when this was written", l)
	}

	// a lease removed takes its records, and a reserved one its reservation
	if err := c.RemoveLease(ctx, scope, laptop); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveLease(ctx, scope, strings.ToLower(strings.ReplaceAll(printer, "-", ":"))); err != nil {
		t.Fatal(err)
	}
	has("the laptop's and the printer's leases removed", false, slices.Concat(both("laptop", held[laptop].Address), both("printer", pool.At(40)))...)
	if now := leases(); now[laptop].Address != "" || now[printer].Address != "" || now[phone].Address == "" {
		t.Errorf("the leases after two were removed = %+v", now)
	}
	if r := reserved(); r[printer].Address != "" || r[twin].Address != pool.At(40) {
		t.Errorf("the reservations after the printer's lease was removed = %+v: a reserved lease no longer takes its reservation with it, which dhcp_lease_delete says it does", r)
	}

	// a scope deleted takes its leases, and leaves the records of its reservations behind
	if err := c.DeleteScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if now, err := c.Leases(ctx); err != nil || slices.ContainsFunc(now, func(l technitium.Lease) bool { return l.Scope == scope }) {
		t.Errorf("the leases of a scope that was deleted = %+v, %v", now, err)
	}
	has("the scope deleted", true, both("taken", pool.At(42))...)
	if err := c.DeleteScope(ctx, scope); err != nil {
		t.Errorf("deleting a scope that is not there = %v: the server said nothing of it when this was written", err)
	}
}

// reverseOf is the name an address's PTR is at.
func reverseOf(t *testing.T, address string) string {
	t.Helper()

	b := netip.MustParseAddr(address).As4()
	parts := make([]string, 0, 4)
	for i := 3; i >= 0; i-- {
		parts = append(parts, strconv.Itoa(int(b[i])))
	}

	return strings.Join(parts, ".") + ".in-addr.arpa"
}

// inPool reports whether an address is one of a range's.
func inPool(t *testing.T, first, last netip.Addr, address string) bool {
	t.Helper()

	addr, err := netip.ParseAddr(address)

	return err == nil && addr.Compare(first) >= 0 && addr.Compare(last) <= 0
}
