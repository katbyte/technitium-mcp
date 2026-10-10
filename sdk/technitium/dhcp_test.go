package technitium_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// A scope as a 15.6 server gave it once made and given a reservation.
const scopeAnswer = `{"name":"LAN","startingAddress":"10.44.0.10","endingAddress":"10.44.0.200","subnetMask":"255.255.255.0","leaseTimeDays":1,"leaseTimeHours":0,"leaseTimeMinutes":0,"domainName":"lan.test","dnsUpdates":true,"dnsTtl":900,"routerAddress":"10.44.0.1","useThisDnsServer":false,"dnsServers":["10.44.0.2","10.44.0.3"],"exclusions":[{"startingAddress":"10.44.0.10","endingAddress":"10.44.0.20"}],"reservedLeases":[{"hostName":"printer","hardwareAddress":"00-11-22-33-44-55","address":"10.44.0.50","comments":"the printer"}],"allowOnlyReservedLeases":false}`

func TestDHCP(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("dhcp/scopes/list", `{"scopes":[{"name":"Default","enabled":false,"startingAddress":"192.168.1.1","endingAddress":"192.168.1.254","subnetMask":"255.255.255.0","networkAddress":"192.168.1.0","broadcastAddress":"192.168.1.255"},{"name":"LAN","enabled":true,"startingAddress":"10.44.0.10","endingAddress":"10.44.0.200","subnetMask":"255.255.255.0","networkAddress":"10.44.0.0","broadcastAddress":"10.44.0.255","interfaceAddress":"10.44.0.2"}]}`)
	fake.Answer("dhcp/scopes/get", scopeAnswer)
	fake.Answer("dhcp/leases/list", `{"leases":[{"scope":"LAN","type":"Reserved","hardwareAddress":"00-11-22-33-44-55","clientIdentifier":"1-001122334455","address":"10.44.0.50","hostName":"printer.lan.test","leaseObtained":"2026-10-09T17:52:51Z","leaseExpires":"2026-10-10T17:52:51Z"},{"scope":"LAN","type":"Dynamic","hardwareAddress":"66-77-88-99-AA-BB","address":"10.44.0.101","hostName":null,"leaseObtained":"2026-10-09T18:00:00Z","leaseExpires":"2026-10-10T18:00:00Z"}]}`)
	for _, path := range []string{"dhcp/scopes/set", "dhcp/scopes/delete", "dhcp/scopes/addReservedLease", "dhcp/scopes/removeReservedLease", "dhcp/leases/remove", "dhcp/scopes/enable", "dhcp/scopes/disable"} {
		fake.Answer(path, `{}`)
	}
	c := client(t, fake)

	scopes, err := c.Scopes(t.Context())
	if err != nil || len(scopes) != 2 || scopes[0].Enabled || !scopes[1].Enabled || scopes[1].Name != "LAN" || scopes[1].NetworkAddress != "10.44.0.0" || scopes[1].InterfaceAddress != "10.44.0.2" {
		t.Fatalf("Scopes = %+v, %v", scopes, err)
	}

	scope, err := c.Scope(t.Context(), "LAN")
	if err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dhcp/scopes/get"); asked.Params.Get("name") != "LAN" {
		t.Errorf("the scope was read with %v", asked.Params)
	}
	if scope.StartingAddress != "10.44.0.10" || scope.EndingAddress != "10.44.0.200" || scope.LeaseTimeDays != 1 || scope.DomainName != "lan.test" || !scope.DNSUpdates || scope.RouterAddress != "10.44.0.1" || len(scope.DNSServers) != 2 || scope.UseThisDNSServer || len(scope.Exclusions) != 1 || scope.Exclusions[0].EndingAddress != "10.44.0.20" {
		t.Errorf("Scope = %+v", scope)
	}
	if len(scope.ReservedLeases) != 1 || scope.ReservedLeases[0] != (technitium.Reservation{HostName: "printer", HardwareAddress: "00-11-22-33-44-55", Address: "10.44.0.50", Comments: "the printer"}) {
		t.Errorf("its reservations = %+v", scope.ReservedLeases)
	}

	leases, err := c.Leases(t.Context())
	if err != nil || len(leases) != 2 || leases[0].Type != "Reserved" || leases[0].HostName != "printer.lan.test" || leases[1].Type != "Dynamic" || leases[1].HostName != "" || leases[1].Address != "10.44.0.101" || leases[0].LeaseExpires == "" {
		t.Errorf("Leases = %+v, %v", leases, err)
	}

	if err := c.SetScope(t.Context(), &technitium.NewScope{Name: "LAN", StartingAddress: "10.44.0.10", EndingAddress: "10.44.0.200", SubnetMask: "255.255.255.0", DomainName: "lan.test", DNSUpdates: new(true), RouterAddress: "10.44.0.1", DNSServers: []string{"10.44.0.2", "10.44.0.3"}, LeaseTimeDays: 1, Exclusions: [][2]string{{"10.44.0.10", "10.44.0.20"}, {"10.44.0.190", "10.44.0.200"}}}); err != nil {
		t.Fatal(err)
	}
	asked := fake.Last("dhcp/scopes/set")
	for param, want := range map[string]string{"name": "LAN", "startingAddress": "10.44.0.10", "endingAddress": "10.44.0.200", "subnetMask": "255.255.255.0", "domainName": "lan.test", "dnsUpdates": "true", "routerAddress": "10.44.0.1", "dnsServers": "10.44.0.2,10.44.0.3", "leaseTimeDays": "1", "exclusions": "10.44.0.10|10.44.0.20|10.44.0.190|10.44.0.200"} {
		if asked.Params.Get(param) != want {
			t.Errorf("the scope was set with %s=%q, want %q", param, asked.Params.Get(param), want)
		}
	}
	if asked.Method != http.MethodPost {
		t.Errorf("the scope was set with a %s", asked.Method)
	}

	if err := c.AddReservation(t.Context(), "LAN", technitium.Reservation{HostName: "printer", HardwareAddress: "00-11-22-33-44-55", Address: "10.44.0.50", Comments: "the printer"}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dhcp/scopes/addReservedLease"); asked.Params.Get("name") != "LAN" || asked.Params.Get("hardwareAddress") != "00-11-22-33-44-55" || asked.Params.Get("ipAddress") != "10.44.0.50" || asked.Params.Get("hostName") != "printer" || asked.Params.Get("comments") != "the printer" {
		t.Errorf("the reservation was added with %v", asked.Params)
	}
	if err := c.RemoveReservation(t.Context(), "LAN", "00-11-22-33-44-55"); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dhcp/scopes/removeReservedLease"); asked.Params.Get("name") != "LAN" || asked.Params.Get("hardwareAddress") != "00-11-22-33-44-55" {
		t.Errorf("the reservation was removed with %v", asked.Params)
	}
	if err := c.RemoveLease(t.Context(), "LAN", "66-77-88-99-AA-BB"); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dhcp/leases/remove"); asked.Params.Get("name") != "LAN" || asked.Params.Get("hardwareAddress") != "66-77-88-99-AA-BB" {
		t.Errorf("the lease was removed with %v", asked.Params)
	}
	if err := c.DeleteScope(t.Context(), "LAN"); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("dhcp/scopes/delete"); asked.Params.Get("name") != "LAN" {
		t.Errorf("the scope was deleted with %v", asked.Params)
	}

	// a lease time to the minute is sent as its days, hours and minutes, and what is switched off is said to be
	if err := c.SetScope(t.Context(), &technitium.NewScope{Name: "LAN", StartingAddress: "10.44.0.10", EndingAddress: "10.44.0.200", SubnetMask: "255.255.255.0", LeaseTime: 36*time.Hour + 30*time.Minute, DNSUpdates: new(false), UseThisDNSServer: new(true), AllowOnlyReservedLeases: new(false)}); err != nil {
		t.Fatal(err)
	}
	timed := fake.Last("dhcp/scopes/set")
	for param, want := range map[string]string{"leaseTimeDays": "1", "leaseTimeHours": "12", "leaseTimeMinutes": "30", "dnsUpdates": "false", "useThisDnsServer": "true", "allowOnlyReservedLeases": "false"} {
		if timed.Params.Get(param) != want {
			t.Errorf("the scope was set with %s=%q, want %q", param, timed.Params.Get(param), want)
		}
	}
	if timed.Params.Has("domainName") || timed.Params.Has("dnsServers") {
		t.Errorf("what was not given was sent: %v", timed.Params)
	}
	for path, call := range map[string]func(string) error{"dhcp/scopes/enable": func(name string) error { return c.EnableScope(t.Context(), name) }, "dhcp/scopes/disable": func(name string) error { return c.DisableScope(t.Context(), name) }} {
		if err := call("LAN"); err != nil || fake.Last(path).Params.Get("name") != "LAN" || fake.Last(path).Method != http.MethodPost {
			t.Errorf("%s: %v, sent %v", path, err, fake.Last(path).Params)
		}
		if err := call(""); err == nil || len(fake.Requests(path)) != 1 {
			t.Errorf("%s for no scope = %v", path, err)
		}
	}

	// what names nothing is not sent
	writes := func() int {
		return len(fake.Requests("dhcp/scopes/set")) + len(fake.Requests("dhcp/scopes/delete")) + len(fake.Requests("dhcp/scopes/addReservedLease")) + len(fake.Requests("dhcp/scopes/removeReservedLease")) + len(fake.Requests("dhcp/leases/remove"))
	}
	sent := writes()
	if _, err := c.Scope(t.Context(), ""); err == nil {
		t.Error("a scope with no name was read")
	}
	if err := c.SetScope(t.Context(), &technitium.NewScope{Name: "LAN"}); err == nil {
		t.Error("a scope with no range was set")
	}
	if err := c.DeleteScope(t.Context(), ""); err == nil {
		t.Error("a scope with no name was deleted")
	}
	if err := c.AddReservation(t.Context(), "LAN", technitium.Reservation{Address: "10.44.0.50"}); err == nil {
		t.Error("a reservation for no machine was added")
	}
	if err := c.RemoveReservation(t.Context(), "LAN", ""); err == nil {
		t.Error("a reservation for no machine was removed")
	}
	if err := c.RemoveLease(t.Context(), "", "66-77-88-99-AA-BB"); err == nil {
		t.Error("a lease in no scope was removed")
	}
	if now := writes(); now != sent {
		t.Errorf("%d refused writes reached the server", now-sent)
	}
}
