package tools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The policies a zone's options take, each as the server writes it, by how
// it may be typed. The server passes over a name it does not know without a
// word, so one is refused here first.
var (
	queryPolicies    = canonical("Deny", "Allow", "AllowOnlyPrivateNetworks", "AllowOnlyZoneNameServers", "UseSpecifiedNetworkACL", "AllowZoneNameServersAndUseSpecifiedNetworkACL")
	transferPolicies = canonical("Deny", "Allow", "AllowOnlyZoneNameServers", "UseSpecifiedNetworkACL", "AllowZoneNameServersAndUseSpecifiedNetworkACL")
	notifyPolicies   = canonical("None", "ZoneNameServers", "SpecifiedNameServers", "BothZoneAndSpecifiedNameServers", "SeparateNameServersForCatalogAndMemberZones")
	zoneKinds        = canonical(technitium.ZoneTypes...)
)

// zoneNameOf reads the name a zone is to have: a domain name, or for a
// reverse zone the network it is for, which is written as its arpa name.
func zoneNameOf(text string) (string, error) {
	text = strings.TrimSpace(text)
	if prefix, err := netip.ParsePrefix(text); err == nil {
		if !prefix.Addr().Is4() || prefix.Bits() == 0 || prefix.Bits()%8 != 0 || prefix.Bits() > 24 {
			return "", fmt.Errorf("%s: a reverse zone is made for an IPv4 network of 8, 16 or 24 bits by its network, as 10.0.0.0/24; for any other, give the zone's own name under in-addr.arpa or ip6.arpa", text)
		}
		labels := strings.Split(reverseName(prefix.Masked().Addr()), ".")

		return strings.Join(labels[4-prefix.Bits()/8:], "."), nil
	}
	name := cleanName(text)
	switch {
	case name == "":
		return "", errors.New("which zone: give its name")
	case strings.ContainsAny(name, " \t/:@") || strings.HasPrefix(name, "*."):
		return "", fmt.Errorf("%q is no zone name: give a domain name, as example.com", text)
	default:
		return name, nil
	}
}

// given is a list an argument gave, with what is empty in it left out; nil
// for an argument that was not given.
func given(list *[]string) []string {
	if list == nil {
		return nil
	}
	out := []string{}
	for _, entry := range *list {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}

	return out
}

// tsigKeyOn is whether a server has a transfer key by a name. A server that
// cannot be asked is taken to have it, and says so itself when it does not.
func tsigKeyOn(ctx context.Context, srv *servers.Server, name string) bool {
	keys, err := srv.Client.TSIGKeyNames(ctx)

	return err != nil || slices.ContainsFunc(keys, func(held string) bool { return sameName(held, name) })
}

// withoutPorts is the addresses a server holds as they compare with the ones
// asked for: the server writes the port of the protocol after each address
// of a copy's primary, 10.0.0.2:853 for one transferred over TLS, and when
// what was asked for names no port that is the same address.
func withoutPorts(held, asked []string) []string {
	if slices.ContainsFunc(asked, hasPort) {
		return held
	}
	out := make([]string, 0, len(held))
	for _, h := range held {
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		out = append(out, h)
	}

	return out
}

// hasPort is whether an address is written with a port after it.
func hasPort(address string) bool {
	_, _, err := net.SplitHostPort(address)

	return err == nil
}

// updateKey is one key a DNS update may be signed with, and what an update
// signed with it may change.
type updateKey struct {
	Key   string   `json:"key"   jsonschema:"the name of a transfer key (TSIG) the server has"`
	Name  string   `json:"name"  jsonschema:"the name the key may change records at, or with a * every name under one, as *.example.com"`
	Types []string `json:"types" jsonschema:"the record types it may change there, as A and AAAA, or ANY for all"`
}

// transferProtocols are what a copy transfers a zone over, forwarderProtocols
// how a forwarder zone's name server is asked, proxyTypes what it is reached
// through, and catalogOverrides what a member of a catalog may keep its own
// setting for.
var (
	transferProtocols  = canonical("Tcp", "Tls", "Quic")
	forwarderProtocols = canonical("Udp", "Tcp", "Tls", "Https", "Quic")
	proxyTypes         = canonical("NoProxy", "DefaultProxy", "Http", "Socks5")
	catalogOverrides   = canonical("query", "transfer", "notify")
)

func registerZoneWriteTools(r *registry) {
	type zoneCreateIn struct {
		writeServerArg

		Zone              string   `json:"zone"                         jsonschema:"the zone's name, as example.com; for a reverse zone, the network it is for, as 10.0.0.0/24"`
		Type              string   `json:"type,omitempty"               jsonschema:"Primary (the default), a zone of the server's own; Secondary, a copy that transfers from its primary; Forwarder, which sends every query for a name in the zone on to the name server in forwarder; Stub, which keeps only the zone's name servers and asks them; Catalog, a zone that lists other zones for the servers that follow it; SecondaryCatalog, a copy of another server's catalog, which makes this server a secondary of every zone in it; SecondaryForwarder, a copy of another server's forwarder zone"`
		PrimaryAddresses  []string `json:"primary_addresses,omitempty"  jsonschema:"for a copy (Secondary, Stub, SecondaryCatalog, SecondaryForwarder): the addresses of the name server it copies from. A Secondary or a Stub given none finds its primary from the zone's own records"`
		PrimaryProtocol   string   `json:"primary_protocol,omitempty"   jsonschema:"for a copy: what it transfers over, Tcp (the default), Tls or Quic"`
		PrimaryKey        string   `json:"primary_key,omitempty"        jsonschema:"for a copy: the transfer key (TSIG) it signs its transfers with, by name"`
		ValidateZone      bool     `json:"validate_zone,omitempty"      jsonschema:"for a Secondary of a signed zone: check each transfer against the zone's ZONEMD record"`
		Forwarder         string   `json:"forwarder,omitempty"          jsonschema:"for a Forwarder: the address of the name server the zone's names are asked of, or this-server to have the server resolve them itself, so that records put in the zone override some names and the rest resolve as ever"`
		EmptyForwarder    bool     `json:"empty_forwarder,omitempty"    jsonschema:"for a Forwarder: make the zone with no record in it, which forwards nothing until a FWD record is put in it: for a zone that sends different names to different name servers"`
		ForwarderProtocol string   `json:"forwarder_protocol,omitempty" jsonschema:"for a Forwarder: how its name server is asked, Udp (the default), Tcp, Tls, Https or Quic"`
		DNSSECValidation  bool     `json:"dnssec_validation,omitempty"  jsonschema:"for a Forwarder: validate what its name server answers"`
		ProxyType         string   `json:"proxy_type,omitempty"         jsonschema:"for a Forwarder: what its name server is reached through, NoProxy, DefaultProxy (the server's own, the default), Http or Socks5; with one of the last two, proxy_address and proxy_port say where"`
		ProxyAddress      string   `json:"proxy_address,omitempty"`
		ProxyPort         int      `json:"proxy_port,omitempty"`
		ProxyUsername     string   `json:"proxy_username,omitempty"`
		ProxyPassword     string   `json:"proxy_password,omitempty"     jsonschema:"sent and never read back"`
		SerialByDate      bool     `json:"serial_by_date,omitempty"     jsonschema:"for a zone of the server's own: number its changes by the day, 2026101001, where the default counts up from 1"`
		Catalog           string   `json:"catalog,omitempty"            jsonschema:"make the zone a member of this catalog zone, which gives it to every server that follows the catalog: a cluster's own catalog is how its nodes come to share a zone"`
		DryRun            bool     `json:"dry_run,omitempty"            jsonschema:"change nothing, and answer with what would be done"`
	}
	type zoneCreateOut struct {
		Server  string     `json:"server"`
		Zone    string     `json:"zone"`
		Changed bool       `json:"changed"         jsonschema:"something was changed; with a dry run, something would be"`
		Changes []string   `json:"changes"         jsonschema:"each change made; with a dry run, each that would be. Empty when the zone was there already"`
		After   *zoneSetup `json:"after,omitempty" jsonschema:"the zone as the server holds it now, read back; absent from a dry run"`
		Note    string     `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "zone_create",
		Description: "Make a zone on one server: a primary of its own, a secondary that copies another server's, or a forwarder for the zone's names. A zone that is there already as asked is left alone, and one there as another type is refused. A new primary names the server as its only name server; with catalog it is made a member of a catalog zone, which in a cluster gives it to every node. The answer is the zone as the server holds it, read back, and says what else making it does: a zone made under one the server holds takes its names over from the zone above, and making a zone can empty the server's cache. dry_run changes nothing.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneCreateIn) (*mcp.CallToolResult, zoneCreateOut, error) {
		zone, err := zoneNameOf(in.Zone)
		if err != nil {
			return nil, zoneCreateOut{}, err
		}
		kind, err := oneOf("type", in.Type, zoneKinds)
		if err != nil {
			return nil, zoneCreateOut{}, err
		}
		if kind == "" {
			kind = technitium.ZonePrimary
		}
		primaries, forwarder := given(&in.PrimaryAddresses), strings.TrimSpace(in.Forwarder)
		made := technitium.NewZone{Name: zone, Type: kind, PrimaryNameServerAddresses: primaries, Forwarder: forwarder, TSIGKeyName: cleanName(in.PrimaryKey), ValidateZone: in.ValidateZone, DNSSECValidation: in.DNSSECValidation, SerialByDate: in.SerialByDate, EmptyForwarder: in.EmptyForwarder}
		if made.TransferProtocol, err = oneOf("primary_protocol", in.PrimaryProtocol, transferProtocols); err != nil {
			return nil, zoneCreateOut{}, err
		}
		if made.ForwarderProtocol, err = oneOf("forwarder_protocol", in.ForwarderProtocol, forwarderProtocols); err != nil {
			return nil, zoneCreateOut{}, err
		}
		proxy, err := oneOf("proxy_type", in.ProxyType, proxyTypes)
		if err != nil {
			return nil, zoneCreateOut{}, err
		}
		if proxy != "" || in.ProxyAddress != "" || in.ProxyPort != 0 || in.ProxyUsername != "" || in.ProxyPassword != "" {
			made.Proxy = &technitium.Proxy{Type: proxy, Address: strings.TrimSpace(in.ProxyAddress), Port: in.ProxyPort, Username: in.ProxyUsername, Password: in.ProxyPassword}
		}
		copies, own := isCopy(kind), kind == technitium.ZonePrimary || kind == technitium.ZoneForwarder || kind == technitium.ZoneCatalog
		switch {
		case kind == technitium.ZoneForwarder && forwarder == "" && !in.EmptyForwarder:
			return nil, zoneCreateOut{}, errors.New("a Forwarder sends the zone's names on: give the name server to ask in forwarder, or empty_forwarder for a zone to put FWD records in afterwards")
		case in.EmptyForwarder && (kind != technitium.ZoneForwarder || forwarder != ""):
			return nil, zoneCreateOut{}, errors.New("empty_forwarder is a Forwarder zone with no name server given: it is not for another type, nor for one given a forwarder")
		case (kind == technitium.ZoneSecondaryCatalog || kind == technitium.ZoneSecondaryForwarder) && len(primaries) == 0:
			return nil, zoneCreateOut{}, fmt.Errorf("a %s copies a zone from another server: give that server's address in primary_addresses", kind)
		case !copies && (len(primaries) > 0 || made.TransferProtocol != "" || made.TSIGKeyName != "" || made.ValidateZone):
			return nil, zoneCreateOut{}, fmt.Errorf("primary_addresses, primary_protocol, primary_key and validate_zone are for a copy of another server's zone: a %s takes none of them", kind)
		case kind != technitium.ZoneForwarder && (forwarder != "" || made.ForwarderProtocol != "" || made.DNSSECValidation || made.Proxy != nil):
			return nil, zoneCreateOut{}, fmt.Errorf("forwarder, forwarder_protocol, dnssec_validation and the proxy are for a Forwarder: a %s takes none of them", kind)
		case made.EmptyForwarder && (made.ForwarderProtocol != "" || made.DNSSECValidation || made.Proxy != nil):
			return nil, zoneCreateOut{}, errors.New("how a forwarder zone's name server is reached means nothing with no name server given: give forwarder, or leave the rest out and put a FWD record in the zone afterwards")
		case !own && made.SerialByDate:
			return nil, zoneCreateOut{}, fmt.Errorf("serial_by_date is for a zone of the server's own: a %s has its serial from its primary", kind)
		case in.Catalog != "" && (kind == technitium.ZoneCatalog || kind == technitium.ZoneSecondaryCatalog || kind == technitium.ZoneSecondaryForwarder):
			return nil, zoneCreateOut{}, fmt.Errorf("a %s zone cannot be a member of a catalog", kind)
		default:
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, zoneCreateOut{}, err
		}
		zones, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
		if err != nil {
			return nil, zoneCreateOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}

		out := zoneCreateOut{Server: srv.Name, Zone: zone, Changes: []string{}}
		var catalogs []string
		var above string
		for i := range zones {
			name := cleanName(zones[i].Name)
			switch {
			case name == zone && zones[i].Type == kind:
				if out.After, err = zoneSetupOf(ctx, srv, zone); err != nil {
					return nil, zoneCreateOut{}, err
				}

				return nil, out, nil
			case name == zone:
				return nil, zoneCreateOut{}, fmt.Errorf("%s holds %s already, as a %s zone: a zone's type is not changed by making it again. Nothing was changed", srv.Name, zone, zones[i].Type)
			case zones[i].Type == technitium.ZoneCatalog:
				catalogs = append(catalogs, name)
			case served(&zones[i]) && strings.HasSuffix(zone, "."+name) && len(name) > len(above):
				above = name
			default:
			}
		}
		catalog := cleanName(in.Catalog)
		switch {
		case catalog != "" && !slices.Contains(catalogs, catalog):
			return nil, zoneCreateOut{}, fmt.Errorf("%s holds no catalog zone named %s: it holds %s. Nothing was changed", srv.Name, catalog, orNone(catalogs))
		case made.TSIGKeyName != "" && !tsigKeyOn(ctx, srv, made.TSIGKeyName):
			return nil, zoneCreateOut{}, fmt.Errorf("%s has no transfer key named %s. Nothing was changed", srv.Name, made.TSIGKeyName)
		case catalog == "" && len(catalogs) > 0 && kind == technitium.ZonePrimary:
			out.Note = note(out.Note, fmt.Sprintf("the zone is on %s alone: made a member of the catalog %s, with catalog, it is given to every server that follows it", srv.Name, catalogs[0]))
		default:
		}
		if above != "" {
			out.Note = note(out.Note, fmt.Sprintf("%s holds %s above it: every name under %s is answered from the new zone from now on, and a record %s has at one of them is no longer served", srv.Name, above, zone, above))
		}
		// a reverse zone always does, and any other can
		if out.Note = note(out.Note, "making a zone can empty the server's cache: what it had resolved for clients is then resolved again as they ask"); strings.HasSuffix(zone, ".arpa") {
			out.Note = note(out.Note, "a reverse zone always does")
		}

		done := &changes{dry: in.DryRun}
		out.Changed = true
		if done.did("made %s on %s as a %s zone", zone, srv.Name, kind) {
			made.Catalog = catalog
			if _, err := srv.Client.CreateZone(ctx, made); err != nil {
				return nil, zoneCreateOut{}, fmt.Errorf("making %s: %w. Nothing was changed", zone, err)
			}
		}
		if out.Changes = done.said; in.DryRun {
			return nil, out, nil
		}
		switch out.After, err = zoneSetupOf(ctx, srv, zone); {
		case err != nil:
			return nil, zoneCreateOut{}, fmt.Errorf("the server said it made %s, and the zone could not be read back: %w", zone, err)
		case out.After == nil:
			return nil, zoneCreateOut{}, fmt.Errorf("the server said it made %s, and does not list it among its zones", zone)
		default:
		}

		return nil, out, nil
	})

	type zoneEditIn struct {
		writeServerArg

		Zone                 string       `json:"zone"                             jsonschema:"the zone's name, as zone_list gives it"`
		Disabled             *bool        `json:"disabled,omitempty"               jsonschema:"true switches the zone off, so the server answers nothing from it, and false back on"`
		Catalog              string       `json:"catalog,omitempty"                jsonschema:"make the zone a member of this catalog zone, which gives it to every server that follows the catalog"`
		Query                string       `json:"query,omitempty"                  jsonschema:"who may ask for the zone's names: Allow, Deny, AllowOnlyPrivateNetworks, AllowOnlyZoneNameServers, UseSpecifiedNetworkACL or AllowZoneNameServersAndUseSpecifiedNetworkACL"`
		QueryNetworks        *[]string    `json:"query_networks,omitempty"         jsonschema:"the networks a query policy by list allows, a ! before one it does not; an empty list clears it"`
		Transfer             string       `json:"transfer,omitempty"               jsonschema:"who may transfer the zone whole: Deny, Allow (anyone), AllowOnlyZoneNameServers, UseSpecifiedNetworkACL or AllowZoneNameServersAndUseSpecifiedNetworkACL"`
		TransferNetworks     *[]string    `json:"transfer_networks,omitempty"      jsonschema:"the addresses and networks a transfer policy by list allows; an empty list clears it"`
		Notify               string       `json:"notify,omitempty"                 jsonschema:"who is told when the zone changes: None, ZoneNameServers, SpecifiedNameServers or BothZoneAndSpecifiedNameServers"`
		NotifyServers        *[]string    `json:"notify_servers,omitempty"         jsonschema:"the addresses a notify policy by list tells; an empty list clears it"`
		Update               string       `json:"update,omitempty"                 jsonschema:"who may change the zone's records by a DNS update: Deny, Allow (anyone), AllowOnlyZoneNameServers, UseSpecifiedNetworkACL or AllowZoneNameServersAndUseSpecifiedNetworkACL"`
		UpdateNetworks       *[]string    `json:"update_networks,omitempty"        jsonschema:"the addresses and networks an update policy by list allows; an empty list clears it"`
		SOAPrimary           string       `json:"soa_primary,omitempty"            jsonschema:"the name server the zone's SOA record is to name as its primary: the server's own name, after it was renamed"`
		SOAResponsible       string       `json:"soa_responsible,omitempty"        jsonschema:"the mailbox its SOA record is to give, as hostadmin@example.com"`
		Refresh              int          `json:"refresh,omitempty"                jsonschema:"seconds between a copy's checks on its primary"`
		Retry                int          `json:"retry,omitempty"                  jsonschema:"seconds before a check that failed is made again"`
		Expire               int          `json:"expire,omitempty"                 jsonschema:"seconds a copy that cannot reach its primary goes on answering"`
		Minimum              int          `json:"minimum,omitempty"                jsonschema:"seconds the answer that a name does not exist may be kept"`
		SerialByDate         *bool        `json:"serial_by_date,omitempty"         jsonschema:"true has the zone number its changes by the day, 2026101001, and false count up from 1"`
		TransferKeys         *[]string    `json:"transfer_keys,omitempty"          jsonschema:"the transfer keys (TSIG) a transfer of the zone may be signed with, by name, in place of the ones it has. An empty list clears them"`
		UpdateKeys           *[]updateKey `json:"update_keys,omitempty"            jsonschema:"the keys a DNS update must be signed with and what each may change, in place of the ones the zone has: how another machine - a DHCP server, a certificate client - is let change some of the zone's records and nothing else. An empty list clears them"`
		PrimaryAddresses     *[]string    `json:"primary_addresses,omitempty"      jsonschema:"for a copy: the addresses of the primary it transfers from, in place of the ones it has. An empty list has the server find the primary from the zone's own records"`
		PrimaryProtocol      string       `json:"primary_protocol,omitempty"       jsonschema:"for a copy: what it transfers over, Tcp, Tls or Quic"`
		PrimaryKey           *string      `json:"primary_key,omitempty"            jsonschema:"for a copy: the transfer key it signs its transfers with, by name; an empty one takes the key off"`
		ValidateZone         *bool        `json:"validate_zone,omitempty"          jsonschema:"for a Secondary of a signed zone: check each transfer against the zone's ZONEMD record. The zone switches itself off when one does not match"`
		OverrideCatalog      *[]string    `json:"override_catalog,omitempty"       jsonschema:"for a member of a catalog: which of query, transfer and notify the zone keeps its own setting for, where the catalog has one for all its members. The ones not named follow the catalog"`
		NotifyCatalogServers *[]string    `json:"notify_catalog_servers,omitempty" jsonschema:"for a catalog zone whose notify policy is SeparateNameServersForCatalogAndMemberZones: the addresses told of a change to the catalog itself; an empty list clears it"`
		DryRun               bool         `json:"dry_run,omitempty"                jsonschema:"change nothing, and answer with what would be done"`
	}
	type zoneEditOut struct {
		Server  string     `json:"server"`
		Zone    string     `json:"zone"`
		Changed bool       `json:"changed"         jsonschema:"something was changed; with a dry run, something would be"`
		Changes []string   `json:"changes"         jsonschema:"each change made; with a dry run, each that would be. Empty when the zone was already as asked"`
		Before  zoneSetup  `json:"before"          jsonschema:"the zone as the server held it before"`
		After   *zoneSetup `json:"after,omitempty" jsonschema:"the zone as it holds it now, read back; absent from a dry run"`
		Note    string     `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "zone_edit",
		Description: "Change how one zone is served and copied, on one server: switch it off or on, make it a member of a catalog, set who may ask for its names, who may transfer it, who is told when it changes and who may update it, each with the list it reads; and for a zone of the server's own set what its SOA record says - the primary it names, the mailbox, and its times. Only what is given is changed. The answer is the zone before and after, read back: the server says ok to an option it does not take, so a change that did not hold is an error here. Opening a zone to anyone is said. The records in a zone are record_set's to change. dry_run changes nothing.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneEditIn) (*mcp.CallToolResult, zoneEditOut, error) {
		zone := cleanName(in.Zone)
		if zone == "" {
			return nil, zoneEditOut{}, errors.New("which zone: give its name, as zone_list gives it")
		}
		var change technitium.ZoneChange
		var err error
		if change.QueryAccess, err = oneOf("query", in.Query, queryPolicies); err != nil {
			return nil, zoneEditOut{}, err
		}
		if change.ZoneTransfer, err = oneOf("transfer", in.Transfer, transferPolicies); err != nil {
			return nil, zoneEditOut{}, err
		}
		if change.Notify, err = oneOf("notify", in.Notify, notifyPolicies); err != nil {
			return nil, zoneEditOut{}, err
		}
		if change.Update, err = oneOf("update", in.Update, transferPolicies); err != nil {
			return nil, zoneEditOut{}, err
		}
		if change.PrimaryZoneTransferProtocol, err = oneOf("primary_protocol", in.PrimaryProtocol, transferProtocols); err != nil {
			return nil, zoneEditOut{}, err
		}
		overrides := given(in.OverrideCatalog)
		for i, what := range overrides {
			if overrides[i], err = oneOf("override_catalog", what, catalogOverrides); err != nil {
				return nil, zoneEditOut{}, err
			}
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, zoneEditOut{}, err
		}
		before, err := zoneSetupOf(ctx, srv, zone)
		switch {
		case err != nil:
			return nil, zoneEditOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		case before == nil:
			return nil, zoneEditOut{}, fmt.Errorf("%s holds no zone named %s: zone_list names the zones it holds", srv.Name, zone)
		default:
		}

		// what is asked for, against what is there: only what differs is sent
		out := zoneEditOut{Server: srv.Name, Zone: zone, Before: *before, Changes: []string{}}
		done := &changes{dry: in.DryRun}
		policy := func(what, have string, want *string) {
			if *want == have {
				*want = ""
			}
			if *want != "" {
				done.did("set %s from %s to %s", what, have, *want)
			}
		}
		policy("who may ask for its names", before.Query, &change.QueryAccess)
		policy("who may transfer it", before.Transfer, &change.ZoneTransfer)
		policy("who is told when it changes", before.Notify, &change.Notify)
		policy("who may update it", before.Update, &change.Update)
		list := func(what string, have []string, asked *[]string) []string {
			want := given(asked)
			if want == nil || slices.Equal(want, have) {
				return nil
			}
			done.did("set %s from %s to %s", what, orNone(have), orNone(want))

			return want
		}
		change.QueryAccessNetworks = list("the networks that may ask", before.QueryNetworks, in.QueryNetworks)
		change.ZoneTransferNetworks = list("the networks that may transfer it", before.TransferNetworks, in.TransferNetworks)
		change.NotifyNameServers = list("the servers told of a change", before.NotifyServers, in.NotifyServers)
		change.UpdateNetworks = list("the networks that may update it", before.UpdateNetworks, in.UpdateNetworks)
		change.ZoneTransferTSIGKeyNames = list("the keys a transfer may be signed with", before.TransferKeys, in.TransferKeys)
		// a copy that transfers over TLS or QUIC is given its primary's addresses back with the port for it, which is not a difference from what was asked
		change.PrimaryNameServerAddresses = list("where it transfers from", withoutPorts(before.PrimaryAddresses, given(in.PrimaryAddresses)), in.PrimaryAddresses)
		change.NotifySecondaryCatalogsNameServers = list("the servers told of a change to the catalog", before.NotifyCatalogServers, in.NotifyCatalogServers)
		if change.PrimaryZoneTransferProtocol == before.PrimaryProtocol {
			change.PrimaryZoneTransferProtocol = ""
		}
		if change.PrimaryZoneTransferProtocol != "" {
			done.did("set what it transfers over from %s to %s", before.PrimaryProtocol, change.PrimaryZoneTransferProtocol)
		}
		if in.PrimaryKey != nil && !sameName(*in.PrimaryKey, before.PrimaryKey) {
			change.PrimaryZoneTransferTSIGKeyName = new(cleanName(*in.PrimaryKey))
			done.did("set the key it signs its transfers with from %s to %s", orNone([]string{before.PrimaryKey}[:min(len(before.PrimaryKey), 1)]), orNone([]string{cleanName(*in.PrimaryKey)}[:min(len(cleanName(*in.PrimaryKey)), 1)]))
		}
		if in.ValidateZone != nil && *in.ValidateZone != before.ValidateZone {
			change.ValidateZone = in.ValidateZone
			done.did("switched checking each transfer against the zone's ZONEMD record %s", map[bool]string{true: "on", false: "off"}[*in.ValidateZone])
		}
		if in.OverrideCatalog != nil && !slices.Equal(overrides, before.OverridesCatalog) {
			slices.Sort(overrides)
			if !slices.Equal(overrides, before.OverridesCatalog) {
				change.OverrideCatalogQueryAccess, change.OverrideCatalogZoneTransfer, change.OverrideCatalogNotify = new(slices.Contains(overrides, "query")), new(slices.Contains(overrides, "transfer")), new(slices.Contains(overrides, "notify"))
				done.did("set what it keeps its own setting for, where its catalog has one, from %s to %s", orNone(before.OverridesCatalog), orNone(overrides))
			}
		}
		if in.UpdateKeys != nil {
			policies, said := []technitium.UpdatePolicy{}, []string{}
			for _, k := range *in.UpdateKeys {
				policy := technitium.UpdatePolicy{TSIGKeyName: cleanName(k.Key), Domain: cleanName(k.Name)}
				for _, t := range k.Types {
					if t = strings.ToUpper(strings.TrimSpace(t)); t != "" {
						policy.AllowedTypes = append(policy.AllowedTypes, t)
					}
				}
				if policy.TSIGKeyName == "" || policy.Domain == "" || len(policy.AllowedTypes) == 0 {
					return nil, zoneEditOut{}, errors.New("each of update_keys names a key, the name it may change records at and the record types it may change there. Nothing was changed")
				}
				policies = append(policies, policy)
				said = append(said, policy.TSIGKeyName+" for "+policy.Domain+": "+strings.Join(policy.AllowedTypes, ", "))
			}
			if !slices.Equal(said, before.UpdateKeys) {
				change.UpdatePolicies = policies
				done.did("set the keys an update must be signed with from %s to %s", orNone(before.UpdateKeys), orNone(said))
			}
		}
		// a key a zone names must be one the server has: it takes a name it has no key for and the transfer or the update then fails
		named := slices.Clone(change.ZoneTransferTSIGKeyNames)
		for _, policy := range change.UpdatePolicies {
			named = append(named, policy.TSIGKeyName)
		}
		if change.PrimaryZoneTransferTSIGKeyName != nil && *change.PrimaryZoneTransferTSIGKeyName != "" {
			named = append(named, *change.PrimaryZoneTransferTSIGKeyName)
		}
		for _, key := range named {
			if !slices.ContainsFunc(before.keys, func(held string) bool { return sameName(held, key) }) {
				return nil, zoneEditOut{}, fmt.Errorf("%s has no transfer key named %s: it has %s. Nothing was changed", srv.Name, key, orNone(before.keys))
			}
		}

		// the switch has calls of its own, which ask only for the right to change the zone where setting its options asks for the right to delete it
		var switched *bool
		if in.Disabled != nil && *in.Disabled != before.Disabled {
			switched = in.Disabled
			done.did("switched the zone %s", map[bool]string{true: "off", false: "on"}[*in.Disabled])
		}
		if catalog := cleanName(in.Catalog); catalog != "" && catalog != cleanName(before.Catalog) {
			change.Catalog = catalog
			done.did("made the zone a member of the catalog %s", catalog)
		}
		options := len(done.said) > 1 || (len(done.said) == 1 && switched == nil)

		// its SOA, which is the zone's own only where the zone is
		var current *technitium.Record
		var soa technitium.SOA
		if in.SOAPrimary != "" || in.SOAResponsible != "" || in.Refresh > 0 || in.Retry > 0 || in.Expire > 0 || in.Minimum > 0 || in.SerialByDate != nil {
			if isCopy(before.Type) {
				return nil, zoneEditOut{}, fmt.Errorf("%s holds %s as a %s zone, a copy: its SOA record is its primary's, and is changed there. Nothing was changed", srv.Name, zone, before.Type)
			}
			at, readErr := srv.Client.RecordsAt(ctx, zone, zone)
			if readErr != nil {
				return nil, zoneEditOut{}, fmt.Errorf("%s: %w", srv.Name, readErr)
			}
			i := slices.IndexFunc(at.Records, func(rec technitium.Record) bool { return rec.Type == "SOA" })
			if i < 0 {
				return nil, zoneEditOut{}, fmt.Errorf("%s has no SOA record on %s to change", zone, srv.Name)
			}
			current = &at.Records[i]
			soa = current.SOA()
			text := func(what string, have *string, want string) {
				if want = strings.TrimSpace(want); want != "" && !strings.EqualFold(cleanName(want), cleanName(*have)) {
					done.did("set the SOA's %s from %s to %s", what, *have, want)
					*have = want
				}
			}
			number := func(what string, have *int, want int) {
				if want > 0 && want != *have {
					done.did("set the SOA's %s from %d to %d seconds", what, *have, want)
					*have = want
				}
			}
			text("primary name server", &soa.Primary, cleanName(in.SOAPrimary))
			text("mailbox", &soa.Responsible, in.SOAResponsible)
			number("refresh", &soa.Refresh, in.Refresh)
			number("retry", &soa.Retry, in.Retry)
			number("expire", &soa.Expire, in.Expire)
			number("minimum", &soa.Minimum, in.Minimum)
			if in.SerialByDate != nil && *in.SerialByDate != soa.SerialByDate {
				soa.SerialByDate = *in.SerialByDate
				done.did("set the zone to number its changes %s", map[bool]string{true: "by the day", false: "by counting up"}[soa.SerialByDate])
			}
		}
		changed := current != nil && soa != current.SOA()

		if change.ZoneTransfer == technitium.PolicyAllow {
			out.Note = note(out.Note, "anyone who can reach the server may now transfer the zone whole: every name in it, in one request")
		}
		if change.Update == technitium.PolicyAllow {
			out.Note = note(out.Note, "anyone who can reach the server may now change the zone's records by a DNS update, with no key asked for")
		}
		if out.Changes, out.Changed = done.said, len(done.said) > 0; in.DryRun || !out.Changed {
			if !out.Changed {
				out.After = before
			}

			return nil, out, nil
		}

		if switched != nil {
			flip := srv.Client.EnableZone
			if *switched {
				flip = srv.Client.DisableZone
			}
			if err := flip(ctx, zone); err != nil {
				return nil, zoneEditOut{}, fmt.Errorf("switching %s %s: %w. Nothing was changed", zone, map[bool]string{true: "off", false: "on"}[*switched], err)
			}
		}
		if options {
			if err := srv.Client.SetZoneOptions(ctx, zone, change); err != nil {
				return nil, zoneEditOut{}, fmt.Errorf("setting the options of %s: %w%s", zone, err, map[bool]string{true: ". The zone was switched, and nothing else was changed", false: ". Nothing was changed"}[switched != nil])
			}
		}
		if changed {
			if _, err := srv.Client.UpdateSOA(ctx, zone, current, soa); err != nil {
				return nil, zoneEditOut{}, fmt.Errorf("setting the SOA record of %s: %w%s", zone, err, map[bool]string{true: ". The rest of what was asked was set", false: ". Nothing was changed"}[options || switched != nil])
			}
		}
		after, err := zoneSetupOf(ctx, srv, zone)
		switch {
		case err != nil:
			return nil, zoneEditOut{}, fmt.Errorf("the change was made, and the zone could not be read back: %w", err)
		case after == nil:
			return nil, zoneEditOut{}, fmt.Errorf("the change was made, and %s no longer lists %s among its zones", srv.Name, zone)
		default:
		}
		out.After = after

		// the server says ok to what it does not take: each thing asked for is looked for
		var lost []string
		holds := func(what string, asked, now string) {
			if asked != "" && !strings.EqualFold(cleanName(asked), cleanName(now)) {
				lost = append(lost, what+" (still "+now+")")
			}
		}
		holds("query", change.QueryAccess, after.Query)
		holds("transfer", change.ZoneTransfer, after.Transfer)
		holds("notify", change.Notify, after.Notify)
		holds("update", change.Update, after.Update)
		holds("catalog", change.Catalog, after.Catalog)
		holds("primary_protocol", change.PrimaryZoneTransferProtocol, after.PrimaryProtocol)
		if change.PrimaryZoneTransferTSIGKeyName != nil && !sameName(*change.PrimaryZoneTransferTSIGKeyName, after.PrimaryKey) {
			lost = append(lost, "primary_key (still "+after.PrimaryKey+")")
		}
		if change.ValidateZone != nil && *change.ValidateZone != after.ValidateZone {
			lost = append(lost, "validate_zone (still "+strconv.FormatBool(after.ValidateZone)+")")
		}
		if change.OverrideCatalogQueryAccess != nil && !slices.Equal(overrides, after.OverridesCatalog) {
			lost = append(lost, "override_catalog (still "+orNone(after.OverridesCatalog)+")")
		}
		if change.UpdatePolicies != nil && len(change.UpdatePolicies) != len(after.policies) {
			lost = append(lost, "update_keys (still "+orNone(after.UpdateKeys)+")")
		}
		if changed && soa.SerialByDate != after.SerialByDate {
			lost = append(lost, "serial_by_date (still "+strconv.FormatBool(after.SerialByDate)+")")
		}
		for what, lists := range map[string][2][]string{"query_networks": {change.QueryAccessNetworks, after.QueryNetworks}, "transfer_networks": {change.ZoneTransferNetworks, after.TransferNetworks}, "notify_servers": {change.NotifyNameServers, after.NotifyServers}, "update_networks": {change.UpdateNetworks, after.UpdateNetworks}, "transfer_keys": {change.ZoneTransferTSIGKeyNames, after.TransferKeys}, "primary_addresses": {change.PrimaryNameServerAddresses, withoutPorts(after.PrimaryAddresses, change.PrimaryNameServerAddresses)}, "notify_catalog_servers": {change.NotifySecondaryCatalogsNameServers, after.NotifyCatalogServers}} {
			if lists[0] != nil && !slices.Equal(lists[0], lists[1]) && (len(lists[0]) > 0 || len(lists[1]) > 0) {
				lost = append(lost, what+" (still "+orNone(lists[1])+")")
			}
		}
		if switched != nil && *switched != after.Disabled {
			lost = append(lost, "disabled (still "+strconv.FormatBool(after.Disabled)+")")
		}
		if changed {
			holds("soa_primary", soa.Primary, after.SOAPrimary)
			holds("soa_responsible", soa.Responsible, after.Responsible)
			for what, times := range map[string][2]int{"refresh": {soa.Refresh, after.Refresh}, "retry": {soa.Retry, after.Retry}, "expire": {soa.Expire, after.Expire}, "minimum": {soa.Minimum, after.Minimum}} {
				if times[0] != times[1] {
					lost = append(lost, fmt.Sprintf("%s (still %d)", what, times[1]))
				}
			}
		}
		if len(lost) > 0 {
			slices.Sort(lost)

			return nil, zoneEditOut{}, fmt.Errorf("the server said ok and %s on %s does not have what was asked for: %s. A %s zone does not take every option, and the rest of what was asked was set", zone, srv.Name, strings.Join(lost, ", "), after.Type)
		}

		return nil, out, nil
	})

	type zoneResyncIn struct {
		writeServerArg

		Zone   string `json:"zone"              jsonschema:"the zone's name, as zone_list gives it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"ask for nothing, and answer with what would be"`
	}
	type zoneResyncOut struct {
		Server     string   `json:"server"`
		Zone       string   `json:"zone"`
		Changes    []string `json:"changes"               jsonschema:"what was asked of the server; with a dry run, what would be"`
		Type       string   `json:"type"`
		Serial     uint32   `json:"serial"                jsonschema:"the copy's serial when the server was asked: zone_list gives it again once the transfer is made"`
		SyncFailed bool     `json:"sync_failed,omitempty" jsonschema:"the copy's last transfer before this had failed"`
		Note       string   `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "zone_resync",
		Description: "Have a server transfer its copy of a zone from the primary again now, rather than when its refresh time next comes: for a copy that is behind, or whose last transfer failed, once what stopped it is put right. Only a copy is resynced - a Secondary or a Stub - on the server that holds it; a zone of the server's own is refused. The server is asked and answers at once, and makes the transfer after: zone_list shows the copy's serial and whether the transfer failed.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneResyncIn) (*mcp.CallToolResult, zoneResyncOut, error) {
		zone := cleanName(in.Zone)
		if zone == "" {
			return nil, zoneResyncOut{}, errors.New("which zone: give its name, as zone_list gives it")
		}
		srv, held, err := r.zoneOn(ctx, in.Server, zone)
		if err != nil {
			return nil, zoneResyncOut{}, err
		}
		if !isCopy(held.Type) {
			return nil, zoneResyncOut{}, fmt.Errorf("%s holds %s as a %s zone, which is no copy: there is no primary for it to transfer from. A copy is resynced on the server that holds it as one, which zone_list names", srv.Name, zone, held.Type)
		}

		out := zoneResyncOut{Server: srv.Name, Zone: zone, Type: held.Type, Serial: held.SOASerial, SyncFailed: held.SyncFailed, Note: "the server makes the transfer after it answers: zone_list shows the copy's serial, and whether the transfer failed"}
		done := &changes{dry: in.DryRun}
		if done.did("asked %s to transfer its copy of %s from the primary again", srv.Name, zone) {
			if err := srv.Client.ResyncZone(ctx, held.Name); err != nil {
				return nil, zoneResyncOut{}, fmt.Errorf("resyncing %s: %w", zone, err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})
}

// zoneOn is a zone as the one server a change is made on holds it.
func (r *registry) zoneOn(ctx context.Context, server, zone string) (*servers.Server, *technitium.Zone, error) {
	srv, err := r.servers.One(server)
	if err != nil {
		return nil, nil, err
	}
	zones, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", srv.Name, err)
	}
	i := slices.IndexFunc(zones, func(z technitium.Zone) bool { return sameName(z.Name, zone) })
	if i < 0 {
		return nil, nil, fmt.Errorf("%s holds no zone named %s: zone_list names the zones it holds", srv.Name, zone)
	}

	return srv, &zones[i], nil
}
