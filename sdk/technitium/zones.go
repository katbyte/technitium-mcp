package technitium

import (
	"context"
	"errors"
	"net/url"
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
	if zone.Forwarder != "" {
		params.Set("forwarder", zone.Forwarder)
	}

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

// ResyncZone has a copy of a zone - a Secondary or a Stub - transfer from its
// primary again now rather than when it is next due. It answers at once: the
// transfer is made after.
func (c *Client) ResyncZone(ctx context.Context, zone string) error {
	if zone == "" {
		return errors.New("zones/resync: which zone")
	}

	return c.write(ctx, "zones/resync", url.Values{"zone": {zone}}, nil)
}
