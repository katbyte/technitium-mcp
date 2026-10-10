package technitium

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Scope is a DHCP scope as the server lists it: a range of addresses it
// leases on one network.
type Scope struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// StartingAddress and EndingAddress are the range leased from
	StartingAddress  string `json:"startingAddress"`
	EndingAddress    string `json:"endingAddress"`
	SubnetMask       string `json:"subnetMask"`
	NetworkAddress   string `json:"networkAddress"`
	BroadcastAddress string `json:"broadcastAddress"`
	// InterfaceAddress is the address of the interface an enabled scope
	// serves on
	InterfaceAddress string `json:"interfaceAddress"`
}

// ScopeDetails is a scope whole: what it leases, what it tells a client, and
// the addresses it keeps for particular machines.
type ScopeDetails struct {
	Name            string `json:"name"`
	StartingAddress string `json:"startingAddress"`
	EndingAddress   string `json:"endingAddress"`
	SubnetMask      string `json:"subnetMask"`

	LeaseTimeDays    int `json:"leaseTimeDays"`
	LeaseTimeHours   int `json:"leaseTimeHours"`
	LeaseTimeMinutes int `json:"leaseTimeMinutes"`

	// DomainName is the domain a client is told it is in, and the zone its
	// name is recorded in when DNSUpdates is on
	DomainName string `json:"domainName"`
	// DNSUpdates is the server recording each lease's host name in DNS
	DNSUpdates bool `json:"dnsUpdates"`
	DNSTTL     int  `json:"dnsTtl"`

	RouterAddress string `json:"routerAddress"`
	// UseThisDNSServer tells clients to resolve through this server itself,
	// and DNSServers names others
	UseThisDNSServer bool     `json:"useThisDnsServer"`
	DNSServers       []string `json:"dnsServers"`

	// Exclusions are ranges inside the scope's that are never leased
	Exclusions []struct {
		StartingAddress string `json:"startingAddress"`
		EndingAddress   string `json:"endingAddress"`
	} `json:"exclusions"`
	// ReservedLeases are the addresses kept for particular machines
	ReservedLeases []Reservation `json:"reservedLeases"`

	// how it leases, and what else it hands out: see NewScope
	OfferDelayTime                       int             `json:"offerDelayTime"`
	PingCheckEnabled                     bool            `json:"pingCheckEnabled"`
	PingCheckTimeout                     int             `json:"pingCheckTimeout"`
	PingCheckRetries                     int             `json:"pingCheckRetries"`
	DomainSearchList                     []string        `json:"domainSearchList"`
	DNSOverwriteForDynamicLease          bool            `json:"dnsOverwriteForDynamicLease"`
	ServerAddress                        string          `json:"serverAddress"`
	ServerHostName                       string          `json:"serverHostName"`
	BootFileName                         string          `json:"bootFileName"`
	WINSServers                          []string        `json:"winsServers"`
	NTPServers                           []string        `json:"ntpServers"`
	NTPServerDomainNames                 []string        `json:"ntpServerDomainNames"`
	StaticRoutes                         []StaticRoute   `json:"staticRoutes"`
	VendorInfo                           []VendorInfo    `json:"vendorInfo"`
	CAPWAPAddresses                      []string        `json:"capwapAcIpAddresses"`
	TFTPServerAddresses                  []string        `json:"tftpServerAddresses"`
	GenericOptions                       []GenericOption `json:"genericOptions"`
	AllowOnlyReservedLeases              bool            `json:"allowOnlyReservedLeases"`
	BlockLocallyAdministeredMACAddresses bool            `json:"blockLocallyAdministeredMacAddresses"`
	IgnoreClientIdentifierOption         bool            `json:"ignoreClientIdentifierOption"`
	// AllowOnlyReservedLeases is the scope leasing to no machine it has no
	// reservation for
}

// Reservation is an address a scope keeps for one machine, by its hardware
// address.
type Reservation struct {
	HostName        string `json:"hostName"`
	HardwareAddress string `json:"hardwareAddress"`
	Address         string `json:"address"`
	Comments        string `json:"comments"`
}

// Lease is an address a machine holds now.
type Lease struct {
	Scope string `json:"scope"`
	// Type is Dynamic for an address from the scope's range, and Reserved
	// for one kept for the machine
	Type             string `json:"type"`
	HardwareAddress  string `json:"hardwareAddress"`
	ClientIdentifier string `json:"clientIdentifier"`
	Address          string `json:"address"`
	HostName         string `json:"hostName"`
	LeaseObtained    string `json:"leaseObtained"`
	LeaseExpires     string `json:"leaseExpires"`
}

// Scopes lists the server's DHCP scopes.
func (c *Client) Scopes(ctx context.Context) ([]Scope, error) {
	var out struct {
		Scopes []Scope `json:"scopes"`
	}
	if err := c.read(ctx, "dhcp/scopes/list", nil, &out); err != nil {
		return nil, err
	}

	return out.Scopes, nil
}

// Scope reads one scope whole.
func (c *Client) Scope(ctx context.Context, name string) (*ScopeDetails, error) {
	if name == "" {
		return nil, errors.New("dhcp/scopes/get: which scope")
	}

	var out ScopeDetails
	if err := c.read(ctx, "dhcp/scopes/get", url.Values{"name": {name}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Leases lists the addresses machines hold now, in every scope.
func (c *Client) Leases(ctx context.Context) ([]Lease, error) {
	var out struct {
		Leases []Lease `json:"leases"`
	}
	if err := c.read(ctx, "dhcp/leases/list", nil, &out); err != nil {
		return nil, err
	}

	return out.Leases, nil
}

// NewScope is a scope to make, or to set over the one of its name.
type NewScope struct {
	Name            string
	StartingAddress string
	EndingAddress   string
	SubnetMask      string
	DomainName      string
	// DNSUpdates has the server record each lease's host name under
	// DomainName, and its PTR; UseThisDNSServer tells machines to resolve
	// through the server itself; AllowOnlyReservedLeases leases to no
	// machine with no reservation. nil leaves each as it is
	DNSUpdates, UseThisDNSServer, AllowOnlyReservedLeases *bool
	RouterAddress                                         string
	DNSServers                                            []string
	// LeaseTimeDays is how long a lease runs in whole days, and LeaseTime
	// the same to the minute, which is used when it is given
	LeaseTimeDays int
	LeaseTime     time.Duration
	// Exclusions are ranges never leased, each as its first and last address
	Exclusions [][2]string

	// NewName renames the scope
	NewName string
	// what a scope does as it leases: how long it waits before it offers an
	// address, in milliseconds; whether it pings an address first to see
	// that nothing has it, with how long it waits and how often it tries;
	// whether a dynamic lease may write over a record made by hand; the TTL
	// of the records it writes; and whether it refuses machines with a
	// made-up hardware address or tells machines apart by hardware address
	// alone. nil leaves each as it is
	OfferDelayTime, PingCheckTimeout, PingCheckRetries, DNSTTL                                                        *int
	PingCheckEnabled, DNSOverwriteForDynamicLease, BlockLocallyAdministeredMACAddresses, IgnoreClientIdentifierOption *bool
	// what a machine that boots from the network is told: the server to
	// fetch from, by address and by name, and the file. nil leaves each
	ServerAddress, ServerHostName, BootFileName *string
	// the lists a scope hands out: the domains to search, and the WINS, NTP
	// (by address, or by name for the server to resolve), CAPWAP and TFTP
	// servers. nil leaves a list as it is and an empty one clears it
	DomainSearchList, WINSServers, NTPServers, NTPServerDomainNames, CAPWAPAddresses, TFTPServerAddresses []string
	// StaticRoutes, VendorInfo and GenericOptions are the tables: routes to
	// other networks, what a vendor's machines are told, and any option the
	// server has no name for, by its code. nil leaves one and empty clears
	StaticRoutes   []StaticRoute
	VendorInfo     []VendorInfo
	GenericOptions []GenericOption
	// ReservedLeases is every reservation of the scope, in place of the
	// ones it has: AddReservation adds one and leaves the rest. nil leaves
	// them all
	ReservedLeases []Reservation
}

// StaticRoute is a route a scope tells its machines of: the network, its
// mask, and the router that reaches it.
type StaticRoute struct {
	Destination string `json:"destination"`
	SubnetMask  string `json:"subnetMask"`
	Router      string `json:"router"`
}

// VendorInfo is what a scope tells the machines of one vendor: the class
// they say they are, and the bytes they are given, in hex.
type VendorInfo struct {
	Identifier  string `json:"identifier"`
	Information string `json:"information"`
}

// GenericOption is a DHCP option by its number, with its value as bytes in
// hex: for an option the server has no name for.
type GenericOption struct {
	Code  int    `json:"code"`
	Value string `json:"value"`
}

// SetScope makes a scope, or sets the one of its name to this: what is left
// out here an existing scope keeps, its reservations among it. A scope made
// so is enabled at once.
func (c *Client) SetScope(ctx context.Context, scope *NewScope) error {
	if scope.Name == "" || scope.StartingAddress == "" || scope.EndingAddress == "" || scope.SubnetMask == "" {
		return errors.New("dhcp/scopes/set: a scope needs a name, the first and last address of its range, and a subnet mask")
	}
	params := url.Values{"name": {scope.Name}, "startingAddress": {scope.StartingAddress}, "endingAddress": {scope.EndingAddress}, "subnetMask": {scope.SubnetMask}}
	if scope.DomainName != "" {
		params.Set("domainName", scope.DomainName)
	}
	for param, value := range map[string]*bool{"dnsUpdates": scope.DNSUpdates, "useThisDnsServer": scope.UseThisDNSServer, "allowOnlyReservedLeases": scope.AllowOnlyReservedLeases} {
		if value != nil {
			params.Set(param, strconv.FormatBool(*value))
		}
	}
	if scope.RouterAddress != "" {
		params.Set("routerAddress", scope.RouterAddress)
	}
	if len(scope.DNSServers) > 0 {
		params.Set("dnsServers", strings.Join(scope.DNSServers, ","))
	}
	if scope.LeaseTimeDays > 0 {
		params.Set("leaseTimeDays", strconv.Itoa(scope.LeaseTimeDays))
	}
	if minutes := int(scope.LeaseTime.Minutes()); minutes > 0 {
		params.Set("leaseTimeDays", strconv.Itoa(minutes/(24*60)))
		params.Set("leaseTimeHours", strconv.Itoa(minutes/60%24))
		params.Set("leaseTimeMinutes", strconv.Itoa(minutes%60))
	}
	if len(scope.Exclusions) > 0 {
		parts := make([]string, 0, 2*len(scope.Exclusions))
		for _, e := range scope.Exclusions {
			parts = append(parts, e[0], e[1])
		}
		params.Set("exclusions", strings.Join(parts, "|"))
	}
	set(params, map[string]string{"newName": scope.NewName, "pingCheckEnabled": flag(scope.PingCheckEnabled), "dnsOverwriteForDynamicLease": flag(scope.DNSOverwriteForDynamicLease), "blockLocallyAdministeredMacAddresses": flag(scope.BlockLocallyAdministeredMACAddresses), "ignoreClientIdentifierOption": flag(scope.IgnoreClientIdentifierOption)})
	for param, value := range map[string]*int{"offerDelayTime": scope.OfferDelayTime, "pingCheckTimeout": scope.PingCheckTimeout, "pingCheckRetries": scope.PingCheckRetries, "dnsTtl": scope.DNSTTL} {
		if value != nil {
			params.Set(param, strconv.Itoa(*value))
		}
	}
	for param, value := range map[string]*string{"serverAddress": scope.ServerAddress, "serverHostName": scope.ServerHostName, "bootFileName": scope.BootFileName} {
		if value != nil {
			params.Set(param, *value)
		}
	}
	for param, list := range map[string][]string{"domainSearchList": scope.DomainSearchList, "winsServers": scope.WINSServers, "ntpServers": scope.NTPServers, "ntpServerDomainNames": scope.NTPServerDomainNames, "capwapAcIpAddresses": scope.CAPWAPAddresses, "tftpServerAddresses": scope.TFTPServerAddresses} {
		if list != nil {
			params.Set(param, strings.Join(list, ","))
		}
	}
	// the tables, each with a bar between every cell and between every row
	tables := map[string][]string{}
	if scope.StaticRoutes != nil {
		tables["staticRoutes"] = []string{}
		for _, r := range scope.StaticRoutes {
			tables["staticRoutes"] = append(tables["staticRoutes"], r.Destination, r.SubnetMask, r.Router)
		}
	}
	if scope.VendorInfo != nil {
		tables["vendorInfo"] = []string{}
		for _, v := range scope.VendorInfo {
			tables["vendorInfo"] = append(tables["vendorInfo"], v.Identifier, v.Information)
		}
	}
	if scope.GenericOptions != nil {
		tables["genericOptions"] = []string{}
		for _, o := range scope.GenericOptions {
			tables["genericOptions"] = append(tables["genericOptions"], strconv.Itoa(o.Code), o.Value)
		}
	}
	if scope.ReservedLeases != nil {
		tables["reservedLeases"] = []string{}
		for _, r := range scope.ReservedLeases {
			tables["reservedLeases"] = append(tables["reservedLeases"], r.HostName, r.HardwareAddress, r.Address, r.Comments)
		}
	}
	for param, cells := range tables {
		if slices.ContainsFunc(cells, func(cell string) bool { return strings.Contains(cell, "|") }) {
			return fmt.Errorf("dhcp/scopes/set: %s is sent as a table with a bar between its cells, and a value among them holds one", param)
		}
		params.Set(param, strings.Join(cells, "|"))
	}

	return c.write(ctx, "dhcp/scopes/set", params, nil)
}

// DeleteScope deletes a scope, with its reservations and the record of its
// leases.
func (c *Client) DeleteScope(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("dhcp/scopes/delete: which scope")
	}

	return c.write(ctx, "dhcp/scopes/delete", url.Values{"name": {name}}, nil)
}

// AddReservation has a scope keep an address for one machine. The server
// takes nearly anything: an address outside the scope, one another machine
// has reserved or holds. Only a second reservation for the same machine in
// the scope is refused.
func (c *Client) AddReservation(ctx context.Context, scope string, r Reservation) error {
	if scope == "" || r.HardwareAddress == "" || r.Address == "" {
		return errors.New("dhcp/scopes/addReservedLease: a reservation needs its scope, a hardware address and the address kept for it")
	}
	params := url.Values{"name": {scope}, "hardwareAddress": {r.HardwareAddress}, "ipAddress": {r.Address}}
	if r.HostName != "" {
		params.Set("hostName", r.HostName)
	}
	if r.Comments != "" {
		params.Set("comments", r.Comments)
	}

	return c.write(ctx, "dhcp/scopes/addReservedLease", params, nil)
}

// RemoveReservation has a scope keep no address for a machine any more.
func (c *Client) RemoveReservation(ctx context.Context, scope, hardwareAddress string) error {
	if scope == "" || hardwareAddress == "" {
		return errors.New("dhcp/scopes/removeReservedLease: which reservation: it needs its scope and the machine's hardware address")
	}

	return c.write(ctx, "dhcp/scopes/removeReservedLease", url.Values{"name": {scope}, "hardwareAddress": {hardwareAddress}}, nil)
}

// RemoveLease has a scope forget the lease a machine holds. A lease that was
// reserved takes its reservation with it.
func (c *Client) RemoveLease(ctx context.Context, scope, hardwareAddress string) error {
	if scope == "" || hardwareAddress == "" {
		return errors.New("dhcp/leases/remove: which lease: it needs its scope and the machine's hardware address")
	}

	return c.write(ctx, "dhcp/leases/remove", url.Values{"name": {scope}, "hardwareAddress": {hardwareAddress}}, nil)
}

// A machine that sends a client identifier of its own is known to a scope
// by that and not by its hardware address, unless the scope is set to
// ignore identifiers: its lease is named by the identifier, as Lease gives
// it, for the three calls that take one lease.

// RemoveLeaseOfClient is RemoveLease for a lease named by its client
// identifier.
func (c *Client) RemoveLeaseOfClient(ctx context.Context, scope, clientIdentifier string) error {
	if scope == "" || clientIdentifier == "" {
		return errors.New("dhcp/leases/remove: which lease: it needs its scope and the machine's client identifier")
	}

	return c.write(ctx, "dhcp/leases/remove", url.Values{"name": {scope}, "clientIdentifier": {clientIdentifier}}, nil)
}

// ReserveLeaseOfClient is ReserveLease for a lease named by its client
// identifier.
func (c *Client) ReserveLeaseOfClient(ctx context.Context, scope, clientIdentifier string) error {
	if scope == "" || clientIdentifier == "" {
		return errors.New("dhcp/leases/convertToReserved: which lease: it needs its scope and the machine's client identifier")
	}

	return c.write(ctx, "dhcp/leases/convertToReserved", url.Values{"name": {scope}, "clientIdentifier": {clientIdentifier}}, nil)
}

// UnreserveLeaseOfClient is UnreserveLease for a lease named by its client
// identifier.
func (c *Client) UnreserveLeaseOfClient(ctx context.Context, scope, clientIdentifier string) error {
	if scope == "" || clientIdentifier == "" {
		return errors.New("dhcp/leases/convertToDynamic: which lease: it needs its scope and the machine's client identifier")
	}

	return c.write(ctx, "dhcp/leases/convertToDynamic", url.Values{"name": {scope}, "clientIdentifier": {clientIdentifier}}, nil)
}

// EnableScope switches a scope on, so that it leases.
func (c *Client) EnableScope(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("dhcp/scopes/enable: which scope")
	}

	return c.write(ctx, "dhcp/scopes/enable", url.Values{"name": {name}}, nil)
}

// DisableScope switches a scope off: it leases nothing, and keeps its
// reservations and what it has leased.
func (c *Client) DisableScope(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("dhcp/scopes/disable: which scope")
	}

	return c.write(ctx, "dhcp/scopes/disable", url.Values{"name": {name}}, nil)
}

// ReserveLease turns the lease a machine holds into a reservation: the
// address it has now is the one it keeps.
func (c *Client) ReserveLease(ctx context.Context, scope, hardwareAddress string) error {
	if scope == "" || hardwareAddress == "" {
		return errors.New("dhcp/leases/convertToReserved: which lease: it needs its scope and the machine's hardware address")
	}

	return c.write(ctx, "dhcp/leases/convertToReserved", url.Values{"name": {scope}, "hardwareAddress": {hardwareAddress}}, nil)
}

// UnreserveLease turns a reserved lease back into an ordinary one, which
// ends when its time is up; the reservation goes with it.
func (c *Client) UnreserveLease(ctx context.Context, scope, hardwareAddress string) error {
	if scope == "" || hardwareAddress == "" {
		return errors.New("dhcp/leases/convertToDynamic: which lease: it needs its scope and the machine's hardware address")
	}

	return c.write(ctx, "dhcp/leases/convertToDynamic", url.Values{"name": {scope}, "hardwareAddress": {hardwareAddress}}, nil)
}
