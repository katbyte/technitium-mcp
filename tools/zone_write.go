package tools

import (
	"context"
	"errors"
	"fmt"
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
	notifyPolicies   = canonical("None", "ZoneNameServers", "SpecifiedNameServers", "BothZoneAndSpecifiedNameServers")
	zoneKinds        = canonical(technitium.ZonePrimary, technitium.ZoneSecondary, technitium.ZoneForwarder)
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

func registerZoneWriteTools(r *registry) {
	type zoneCreateIn struct {
		writeServerArg

		Zone             string   `json:"zone"                        jsonschema:"the zone's name, as example.com; for a reverse zone, the network it is for, as 10.0.0.0/24"`
		Type             string   `json:"type,omitempty"              jsonschema:"Primary (the default), a zone of the server's own; Secondary, a copy that transfers from the primary in primary_addresses; or Forwarder, which sends every query for a name in the zone on to the name servers in forwarder"`
		PrimaryAddresses []string `json:"primary_addresses,omitempty" jsonschema:"for a Secondary: the addresses of the name server it copies the zone from"`
		Forwarder        string   `json:"forwarder,omitempty"         jsonschema:"for a Forwarder: the address of the name server the zone's names are asked of, or several with commas between"`
		Catalog          string   `json:"catalog,omitempty"           jsonschema:"make the zone a member of this catalog zone, which gives it to every server that follows the catalog: a cluster's own catalog is how its nodes come to share a zone"`
		DryRun           bool     `json:"dry_run,omitempty"           jsonschema:"change nothing, and answer with what would be done"`
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
		switch {
		case kind == technitium.ZoneSecondary && len(primaries) == 0:
			return nil, zoneCreateOut{}, errors.New("a Secondary copies a zone from its primary: give the primary's address in primary_addresses")
		case kind == technitium.ZoneForwarder && forwarder == "":
			return nil, zoneCreateOut{}, errors.New("a Forwarder sends the zone's names on: give the name server to ask in forwarder")
		case (kind != technitium.ZoneSecondary && len(primaries) > 0) || (kind != technitium.ZoneForwarder && forwarder != ""):
			return nil, zoneCreateOut{}, fmt.Errorf("primary_addresses is for a Secondary and forwarder for a Forwarder: a %s takes neither", kind)
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
			if _, err := srv.Client.CreateZone(ctx, technitium.NewZone{Name: zone, Type: kind, PrimaryNameServerAddresses: primaries, Forwarder: forwarder, Catalog: catalog}); err != nil {
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

		Zone             string    `json:"zone"                        jsonschema:"the zone's name, as zone_list gives it"`
		Disabled         *bool     `json:"disabled,omitempty"          jsonschema:"true switches the zone off, so the server answers nothing from it, and false back on"`
		Catalog          string    `json:"catalog,omitempty"           jsonschema:"make the zone a member of this catalog zone, which gives it to every server that follows the catalog"`
		Query            string    `json:"query,omitempty"             jsonschema:"who may ask for the zone's names: Allow, Deny, AllowOnlyPrivateNetworks, AllowOnlyZoneNameServers, UseSpecifiedNetworkACL or AllowZoneNameServersAndUseSpecifiedNetworkACL"`
		QueryNetworks    *[]string `json:"query_networks,omitempty"    jsonschema:"the networks a query policy by list allows, a ! before one it does not; an empty list clears it"`
		Transfer         string    `json:"transfer,omitempty"          jsonschema:"who may transfer the zone whole: Deny, Allow (anyone), AllowOnlyZoneNameServers, UseSpecifiedNetworkACL or AllowZoneNameServersAndUseSpecifiedNetworkACL"`
		TransferNetworks *[]string `json:"transfer_networks,omitempty" jsonschema:"the addresses and networks a transfer policy by list allows; an empty list clears it"`
		Notify           string    `json:"notify,omitempty"            jsonschema:"who is told when the zone changes: None, ZoneNameServers, SpecifiedNameServers or BothZoneAndSpecifiedNameServers"`
		NotifyServers    *[]string `json:"notify_servers,omitempty"    jsonschema:"the addresses a notify policy by list tells; an empty list clears it"`
		Update           string    `json:"update,omitempty"            jsonschema:"who may change the zone's records by a DNS update: Deny, Allow (anyone), AllowOnlyZoneNameServers, UseSpecifiedNetworkACL or AllowZoneNameServersAndUseSpecifiedNetworkACL"`
		UpdateNetworks   *[]string `json:"update_networks,omitempty"   jsonschema:"the addresses and networks an update policy by list allows; an empty list clears it"`
		SOAPrimary       string    `json:"soa_primary,omitempty"       jsonschema:"the name server the zone's SOA record is to name as its primary: the server's own name, after it was renamed"`
		SOAResponsible   string    `json:"soa_responsible,omitempty"   jsonschema:"the mailbox its SOA record is to give, as hostadmin@example.com"`
		Refresh          int       `json:"refresh,omitempty"           jsonschema:"seconds between a copy's checks on its primary"`
		Retry            int       `json:"retry,omitempty"             jsonschema:"seconds before a check that failed is made again"`
		Expire           int       `json:"expire,omitempty"            jsonschema:"seconds a copy that cannot reach its primary goes on answering"`
		Minimum          int       `json:"minimum,omitempty"           jsonschema:"seconds the answer that a name does not exist may be kept"`
		DryRun           bool      `json:"dry_run,omitempty"           jsonschema:"change nothing, and answer with what would be done"`
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
		if in.Disabled != nil && *in.Disabled != before.Disabled {
			change.Disabled = in.Disabled
			done.did("switched the zone %s", map[bool]string{true: "off", false: "on"}[*in.Disabled])
		}
		if catalog := cleanName(in.Catalog); catalog != "" && catalog != cleanName(before.Catalog) {
			change.Catalog = catalog
			done.did("made the zone a member of the catalog %s", catalog)
		}
		options := len(done.said) > 0

		// its SOA, which is the zone's own only where the zone is
		var current *technitium.Record
		var soa technitium.SOA
		if in.SOAPrimary != "" || in.SOAResponsible != "" || in.Refresh > 0 || in.Retry > 0 || in.Expire > 0 || in.Minimum > 0 {
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

		if options {
			if err := srv.Client.SetZoneOptions(ctx, zone, change); err != nil {
				return nil, zoneEditOut{}, fmt.Errorf("setting the options of %s: %w. Nothing was changed", zone, err)
			}
		}
		if changed {
			if _, err := srv.Client.UpdateSOA(ctx, zone, current, soa); err != nil {
				return nil, zoneEditOut{}, fmt.Errorf("setting the SOA record of %s: %w%s", zone, err, map[bool]string{true: ". Its options were set", false: ". Nothing was changed"}[options])
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
		for what, lists := range map[string][2][]string{"query_networks": {change.QueryAccessNetworks, after.QueryNetworks}, "transfer_networks": {change.ZoneTransferNetworks, after.TransferNetworks}, "notify_servers": {change.NotifyNameServers, after.NotifyServers}, "update_networks": {change.UpdateNetworks, after.UpdateNetworks}} {
			if lists[0] != nil && !slices.Equal(lists[0], lists[1]) && (len(lists[0]) > 0 || len(lists[1]) > 0) {
				lost = append(lost, what+" (still "+orNone(lists[1])+")")
			}
		}
		if change.Disabled != nil && *change.Disabled != after.Disabled {
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
