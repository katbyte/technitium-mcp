package technitium

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// The ways a zone's options say who may do something with it. Each of a
// zone's three policies - who may transfer it, who is told when it changes,
// who may update it - takes its own set of these.
const (
	// PolicyDeny is nobody, and PolicyAllow anybody
	PolicyDeny  = "Deny"
	PolicyAllow = "Allow"
	// NotifyNone is a zone telling nobody when it changes
	NotifyNone = "None"
)

// ZoneOptions is how one zone is served and copied: who may ask for its
// names, who may transfer it and with which keys, who is told when it
// changes, who may update it, and for a copy where its primary is.
type ZoneOptions struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Disabled bool   `json:"disabled"`
	// Catalog is the catalog zone this one is a member of
	Catalog      string `json:"catalog"`
	DNSSECStatus string `json:"dnssecStatus"`

	// QueryAccess is who may ask for the zone's names: Deny, Allow,
	// AllowOnlyPrivateNetworks, AllowOnlyZoneNameServers,
	// UseSpecifiedNetworkACL or AllowZoneNameServersAndUseSpecifiedNetworkACL
	QueryAccess           string   `json:"queryAccess"`
	QueryAccessNetworkACL []string `json:"queryAccessNetworkACL"`

	// ZoneTransfer is who may transfer the zone whole: Deny, Allow,
	// AllowOnlyZoneNameServers, UseSpecifiedNetworkACL or
	// AllowZoneNameServersAndUseSpecifiedNetworkACL
	ZoneTransfer             string   `json:"zoneTransfer"`
	ZoneTransferNetworkACL   []string `json:"zoneTransferNetworkACL"`
	ZoneTransferTSIGKeyNames []string `json:"zoneTransferTsigKeyNames"`

	// Notify is who is told when the zone changes: None, ZoneNameServers,
	// SpecifiedNameServers, BothZoneAndSpecifiedNameServers or
	// SeparateNameServersForCatalogAndMemberZones
	Notify            string   `json:"notify"`
	NotifyNameServers []string `json:"notifyNameServers"`
	NotifyFailed      bool     `json:"notifyFailed"`
	NotifyFailedFor   []string `json:"notifyFailedFor"`

	// Update is who may change the zone's records by a DNS update: Deny,
	// Allow, AllowOnlyZoneNameServers, UseSpecifiedNetworkACL or
	// AllowZoneNameServersAndUseSpecifiedNetworkACL
	Update           string   `json:"update"`
	UpdateNetworkACL []string `json:"updateNetworkACL"`
	// UpdateSecurityPolicies are the keys an update must be signed with,
	// each with the names and the types it may change
	UpdateSecurityPolicies []UpdatePolicy `json:"updateSecurityPolicies"`

	// a copy's: where its primary is, and how it is transferred from there
	PrimaryNameServerAddresses     []string `json:"primaryNameServerAddresses"`
	PrimaryZoneTransferProtocol    string   `json:"primaryZoneTransferProtocol"`
	PrimaryZoneTransferTSIGKeyName string   `json:"primaryZoneTransferTsigKeyName"`
	// ValidateZone is a Secondary checking each transfer against the zone's
	// ZONEMD record
	ValidateZone bool `json:"validateZone"`

	// a member of a catalog takes who may ask, who may transfer and who is
	// told from the catalog, unless it is set to keep its own
	OverrideCatalogQueryAccess  bool `json:"overrideCatalogQueryAccess"`
	OverrideCatalogZoneTransfer bool `json:"overrideCatalogZoneTransfer"`
	OverrideCatalogNotify       bool `json:"overrideCatalogNotify"`
	// NotifySecondaryCatalogsNameServers are, for a catalog zone told to
	// tell others than its members' servers, the addresses told of a change
	// to the catalog itself
	NotifySecondaryCatalogsNameServers []string `json:"notifySecondaryCatalogsNameServers"`

	// AvailableCatalogZoneNames are the catalogs the zone could be made a
	// member of, and AvailableTSIGKeyNames the keys the server has for a
	// transfer or an update to name
	AvailableCatalogZoneNames []string `json:"availableCatalogZoneNames"`
	AvailableTSIGKeyNames     []string `json:"availableTsigKeyNames"`
}

// UpdatePolicy is one key a dynamic update may be signed with, and what an
// update signed with it may change.
type UpdatePolicy struct {
	TSIGKeyName string `json:"tsigKeyName"`
	// Domain is the name it may change, or *.example.com for every name
	// under one
	Domain string `json:"domain"`
	// AllowedTypes are the record types it may change there; ANY is all
	AllowedTypes []string `json:"allowedTypes"`
}

// ZoneOptions reads how a zone is served and copied.
func (c *Client) ZoneOptions(ctx context.Context, zone string) (*ZoneOptions, error) {
	if zone == "" {
		return nil, errors.New("zones/options/get: which zone")
	}

	var out ZoneOptions
	if err := c.read(ctx, "zones/options/get", url.Values{"zone": {zone}, "includeAvailableCatalogZoneNames": {yes}, "includeAvailableTsigKeyNames": {yes}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ZoneChange is what to set of a zone's options: whatever is left as it
// is here stays as it is on the server.
type ZoneChange struct {
	// Disabled switches the zone off, or back on
	Disabled *bool
	// Catalog makes the zone a member of a catalog zone
	Catalog string

	// QueryAccess, ZoneTransfer, Notify and Update are the policies, as
	// ZoneOptions has them; "" leaves one as it is. A name the server does
	// not know it passes over without a word, so what was set is only known
	// by reading the options back
	QueryAccess, ZoneTransfer, Notify, Update string
	// the lists a policy by list reads: nil leaves one as it is, and an
	// empty one clears it
	QueryAccessNetworks, ZoneTransferNetworks, NotifyNameServers, UpdateNetworks []string

	// ZoneTransferTSIGKeyNames are the keys a transfer of the zone may be
	// signed with, by name; nil leaves them and an empty list clears them
	ZoneTransferTSIGKeyNames []string
	// UpdatePolicies are the keys a dynamic update must be signed with and
	// what each may change; nil leaves them and an empty list clears them
	UpdatePolicies []UpdatePolicy
	// NotifySecondaryCatalogsNameServers are the addresses a catalog zone
	// tells of a change to itself, under the notify policy for that
	NotifySecondaryCatalogsNameServers []string

	// a copy's: where its primary is (nil leaves it, and an empty list has
	// the server find the primary by resolving the zone's own records),
	// what it transfers over - Tcp, Tls or Quic - and the key it signs its
	// transfers with, where nil leaves the key and "" takes it off
	PrimaryNameServerAddresses     []string
	PrimaryZoneTransferProtocol    string
	PrimaryZoneTransferTSIGKeyName *string
	// ValidateZone has a Secondary check each transfer against the zone's
	// ZONEMD record
	ValidateZone *bool

	// a member of a catalog keeping its own setting where the catalog has
	// one for all its members
	OverrideCatalogQueryAccess, OverrideCatalogZoneTransfer, OverrideCatalogNotify *bool
}

// SetZoneOptions sets options of a zone, leaving every other as it is.
func (c *Client) SetZoneOptions(ctx context.Context, zone string, change ZoneChange) error {
	if zone == "" {
		return errors.New("zones/options/set: which zone")
	}
	params := url.Values{"zone": {zone}}
	if change.Disabled != nil {
		params.Set("disabled", strconv.FormatBool(*change.Disabled))
	}
	for param, value := range map[string]string{"catalog": change.Catalog, "queryAccess": change.QueryAccess, "zoneTransfer": change.ZoneTransfer, "notify": change.Notify, "update": change.Update} {
		if value != "" {
			params.Set(param, value)
		}
	}
	for param, list := range map[string][]string{"queryAccessNetworkACL": change.QueryAccessNetworks, "zoneTransferNetworkACL": change.ZoneTransferNetworks, "notifyNameServers": change.NotifyNameServers, "updateNetworkACL": change.UpdateNetworks, "zoneTransferTsigKeyNames": change.ZoneTransferTSIGKeyNames, "notifySecondaryCatalogsNameServers": change.NotifySecondaryCatalogsNameServers} {
		switch {
		case list == nil:
		case len(list) == 0:
			// the API's word for none
			params.Set(param, "false")
		default:
			params.Set(param, strings.Join(list, ","))
		}
	}
	if change.UpdatePolicies != nil {
		// a table with a bar between every cell, and between every row
		cells := make([]string, 0, 3*len(change.UpdatePolicies))
		for _, policy := range change.UpdatePolicies {
			if policy.TSIGKeyName == "" || policy.Domain == "" || len(policy.AllowedTypes) == 0 || strings.Contains(policy.TSIGKeyName+policy.Domain+strings.Join(policy.AllowedTypes, ""), "|") {
				return errors.New("zones/options/set: an update policy names a key, the name it may change and the record types it may change there")
			}
			cells = append(cells, policy.TSIGKeyName, policy.Domain, strings.Join(policy.AllowedTypes, ","))
		}
		params.Set("updateSecurityPolicies", "false")
		if len(cells) > 0 {
			params.Set("updateSecurityPolicies", strings.Join(cells, "|"))
		}
	}
	if change.PrimaryNameServerAddresses != nil {
		params.Set("primaryNameServerAddresses", strings.Join(change.PrimaryNameServerAddresses, ","))
	}
	if change.PrimaryZoneTransferTSIGKeyName != nil {
		params.Set("primaryZoneTransferTsigKeyName", *change.PrimaryZoneTransferTSIGKeyName)
	}
	set(params, map[string]string{"primaryZoneTransferProtocol": change.PrimaryZoneTransferProtocol, "validateZone": flag(change.ValidateZone), "overrideCatalogQueryAccess": flag(change.OverrideCatalogQueryAccess), "overrideCatalogZoneTransfer": flag(change.OverrideCatalogZoneTransfer), "overrideCatalogNotify": flag(change.OverrideCatalogNotify)})
	if len(params) == 1 {
		return errors.New("zones/options/set: which option: nothing was given to set")
	}

	return c.write(ctx, "zones/options/set", params, nil)
}

// ExportZone is a zone whole as a zone file: every record a line, with the
// comment a record has after a semicolon.
func (c *Client) ExportZone(ctx context.Context, zone string) (string, error) {
	if zone == "" {
		return "", errors.New("zones/export: which zone")
	}

	return c.readText(ctx, "zones/export", url.Values{"zone": {zone}})
}

// OpenSession is someone signed in to the server, or an API token made on
// it.
type OpenSession struct {
	Username string `json:"username"`
	// PartialToken is the start of the session's token, which is what the
	// server knows a session by when it is asked to end one. It is not
	// enough of the token to use
	PartialToken string `json:"partialToken"`
	// Type is Standard for someone signed in at the console, and ApiToken
	// for a token, which does not expire
	Type      string `json:"type"`
	TokenName string `json:"tokenName"`
	// IsCurrentSession is the session being the one that asked
	IsCurrentSession bool `json:"isCurrentSession"`
	// LastSeen is when the session last made a call, in UTC, and
	// LastSeenRemoteAddress where from
	LastSeen              string `json:"lastSeen"`
	LastSeenRemoteAddress string `json:"lastSeenRemoteAddress"`
	LastSeenUserAgent     string `json:"lastSeenUserAgent"`
}

// SessionAPIToken is the type of a session that is an API token.
const SessionAPIToken = "ApiToken"

// Sessions lists who is signed in to the server and the API tokens made on
// it, which only an administrator may read.
func (c *Client) Sessions(ctx context.Context) ([]OpenSession, error) {
	var out struct {
		Sessions []OpenSession `json:"sessions"`
	}
	if err := c.read(ctx, "admin/sessions/list", nil, &out); err != nil {
		return nil, err
	}

	return out.Sessions, nil
}
