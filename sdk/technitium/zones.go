package technitium

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The zone types the server hosts.
const (
	ZonePrimary            = "Primary"
	ZoneSecondary          = "Secondary"
	ZoneStub               = "Stub"
	ZoneForwarder          = "Forwarder"
	ZoneSecondaryForwarder = "SecondaryForwarder"
	ZoneCatalog            = "Catalog"
	ZoneSecondaryCatalog   = "SecondaryCatalog"
)

// ZoneTypes are every type a zone can be, as the API spells them.
var ZoneTypes = []string{ZonePrimary, ZoneSecondary, ZoneStub, ZoneForwarder, ZoneSecondaryForwarder, ZoneCatalog, ZoneSecondaryCatalog}

// Zone is an authoritative zone as the server lists it.
type Zone struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Internal is a zone the server made for itself and keeps: localhost and
	// the reverse zones for loopback
	Internal     bool   `json:"internal"`
	Disabled     bool   `json:"disabled"`
	SOASerial    uint32 `json:"soaSerial"`
	DNSSECStatus string `json:"dnssecStatus"`
	// Catalog is the catalog zone this one is a member of, "" for none
	Catalog string `json:"catalog"`
	// LastModified is when a record in the zone last changed, in UTC
	LastModified string `json:"lastModified"`

	// Expiry, IsExpired and SyncFailed are a secondary's: when the copy
	// stops being served unless a transfer renews it, whether it has, and
	// whether the last transfer from the primary failed
	Expiry     string `json:"expiry"`
	IsExpired  bool   `json:"isExpired"`
	SyncFailed bool   `json:"syncFailed"`

	// NotifyFailed and NotifyFailedFor are a primary's: whether telling its
	// secondaries of a change failed, and for which of them
	NotifyFailed    bool     `json:"notifyFailed"`
	NotifyFailedFor []string `json:"notifyFailedFor"`
}

// Signed reports whether the zone is DNSSEC signed.
func (z *Zone) Signed() bool {
	return z.DNSSECStatus != "" && z.DNSSECStatus != "Unsigned"
}

// Modified is when a record in the zone last changed, and false when the
// server does not say.
func (z *Zone) Modified() (time.Time, bool) {
	return ParseTime(z.LastModified)
}

// ZoneFilter narrows a listing of zones on the server's side.
type ZoneFilter struct {
	// Name keeps the zones whose name matches, * standing for any run of
	// characters and ? for one
	Name string
	// Type keeps the zones of one type (see ZoneTypes)
	Type string
}

// Zones lists the authoritative zones the token's account may see, all of
// them in one answer.
func (c *Client) Zones(ctx context.Context, filter ZoneFilter) ([]Zone, error) {
	params := url.Values{}
	if filter.Name != "" {
		params.Set("filterName", filter.Name)
	}
	if filter.Type != "" {
		params.Set("filterType", filter.Type)
	}

	var out struct {
		Zones []Zone `json:"zones"`
	}
	if err := c.read(ctx, "zones/list", params, &out); err != nil {
		return nil, err
	}

	return out.Zones, nil
}

// ZonePage is one page of the zones a server holds, with how many there are
// in all.
type ZonePage struct {
	PageNumber int    `json:"pageNumber"`
	TotalPages int    `json:"totalPages"`
	TotalZones int    `json:"totalZones"`
	Zones      []Zone `json:"zones"`
}

// ZonesPage lists the zones a page at a time, for a server with more than
// are wanted in one answer: page counts from 1, and perPage 0 is the
// server's ten. Zones gives them all at once.
func (c *Client) ZonesPage(ctx context.Context, filter ZoneFilter, page, perPage int) (*ZonePage, error) {
	if page < 1 {
		return nil, errors.New("zones/list: which page: they count from 1")
	}
	params := url.Values{"pageNumber": {strconv.Itoa(page)}}
	set(params, map[string]string{"filterName": filter.Name, "filterType": filter.Type})
	if perPage > 0 {
		params.Set("zonesPerPage", strconv.Itoa(perPage))
	}

	var out ZonePage
	if err := c.read(ctx, "zones/list", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// NewZone is a zone to create.
type NewZone struct {
	// Name is the zone's domain name; an IP address or a network in CIDR
	// form makes the reverse zone for it
	Name string
	// Type is one of ZoneTypes
	Type string
	// PrimaryNameServerAddresses are where a secondary or a stub zone
	// transfers from
	PrimaryNameServerAddresses []string
	// Forwarder is, for a Forwarder zone, the address of the name server
	// queries for names in the zone are sent on to
	Forwarder string
	// Catalog is the catalog zone to make the new zone a member of: every
	// server holding that catalog as a secondary then makes itself a
	// secondary of the new zone, which is how a cluster's nodes come to
	// share one
	Catalog string
	// SerialByDate has a zone of the server's own number its changes by the
	// day, 2026101001, where the default counts up from 1
	SerialByDate bool

	// TransferProtocol is what a copy transfers over - Tcp, Tls or Quic -
	// and TSIGKeyName the key it signs its transfers with, by name
	TransferProtocol, TSIGKeyName string
	// ValidateZone has a Secondary check each transfer against the zone's
	// ZONEMD record, and switch itself off when one does not match
	ValidateZone bool

	// EmptyForwarder makes a Forwarder zone with no record in it, where the
	// default makes it with the one that sends its names on
	EmptyForwarder bool
	// ForwarderProtocol is how a Forwarder zone's name server is asked -
	// Udp, Tcp, Tls, Https or Quic - DNSSECValidation whether its answers
	// are validated, and Proxy what it is reached through
	ForwarderProtocol string
	DNSSECValidation  bool
	Proxy             *Proxy
}

// Proxy is what a forwarder is reached through.
type Proxy struct {
	// Type is NoProxy, DefaultProxy (the server's own, from its settings),
	// Http or Socks5
	Type     string
	Address  string
	Port     int
	Username string
	// Password is sent and never read back
	Password string
}

// params are a proxy as the calls that take one are sent it.
func (p *Proxy) params(into url.Values) {
	if p == nil {
		return
	}
	set(into, map[string]string{"proxyType": p.Type, "proxyAddress": p.Address, "proxyUsername": p.Username, "proxyPassword": p.Password})
	if p.Port > 0 {
		into.Set("proxyPort", strconv.Itoa(p.Port))
	}
}

// CreateZone creates an authoritative zone and returns the name the server
// gave it, which for a reverse zone made from an address is not the name
// asked for.
func (c *Client) CreateZone(ctx context.Context, zone NewZone) (string, error) {
	if zone.Name == "" || zone.Type == "" {
		return "", errors.New("zones/create: a zone needs a name and a type")
	}
	params := url.Values{"zone": {zone.Name}, "type": {zone.Type}}
	if len(zone.PrimaryNameServerAddresses) > 0 {
		params.Set("primaryNameServerAddresses", strings.Join(zone.PrimaryNameServerAddresses, ","))
	}
	if zone.Catalog != "" {
		params.Set("catalog", zone.Catalog)
	}
	set(params, map[string]string{"forwarder": zone.Forwarder, "zoneTransferProtocol": zone.TransferProtocol, "tsigKeyName": zone.TSIGKeyName, "protocol": zone.ForwarderProtocol})
	for param, on := range map[string]bool{"useSoaSerialDateScheme": zone.SerialByDate, "validateZone": zone.ValidateZone, "dnssecValidation": zone.DNSSECValidation} {
		if on {
			params.Set(param, yes)
		}
	}
	if zone.EmptyForwarder {
		params.Set("initializeForwarder", "false")
	}
	zone.Proxy.params(params)

	var out struct {
		Domain string `json:"domain"`
	}
	if err := c.write(ctx, "zones/create", params, &out); err != nil {
		return "", err
	}

	return out.Domain, nil
}

// DeleteZone deletes an authoritative zone and every record in it.
func (c *Client) DeleteZone(ctx context.Context, zone string) error {
	if zone == "" {
		return errors.New("zones/delete: which zone")
	}

	return c.write(ctx, "zones/delete", url.Values{"zone": {zone}}, nil)
}

// DeleteZones deletes several zones in one call, each with every record in
// it. The server stops at the first it cannot delete, with the ones before
// it gone.
func (c *Client) DeleteZones(ctx context.Context, zones []string) error {
	if len(zones) == 0 || slices.Contains(zones, "") {
		return errors.New("zones/delete: which zones")
	}

	return c.write(ctx, "zones/delete", url.Values{"zones": {strings.Join(zones, ",")}}, nil)
}

// ResyncZone has a copy of a zone - a Secondary or a Stub - transfer from its
// primary again now rather than when it is next due. It answers at once: the
// transfer is made after.
func (c *Client) ResyncZone(ctx context.Context, zone string) error {
	if zone == "" {
		return errors.New("zones/resync: which zone")
	}

	return c.write(ctx, "zones/resync", url.Values{"zone": {zone}}, nil)
}
