package tools

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// exportDefault is how many lines of a zone file zone_export gives when no
// limit is asked for.
const exportDefault = 500

// zoneSetup is how one server serves and copies a zone, as zone_get answers.
type zoneSetup struct {
	Server   string `json:"server"`
	Error    string `json:"error,omitempty"    jsonschema:"why this server's copy could not be read; the rest of its row is then empty"`
	Type     string `json:"type,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	Catalog  string `json:"catalog,omitempty"  jsonschema:"the catalog zone this one is a member of: a cluster gives its member zones to every node"`
	DNSSEC   string `json:"dnssec,omitempty"   jsonschema:"how the zone is signed; absent for one that is not"`

	Serial      uint32   `json:"serial,omitempty"`
	SOAPrimary  string   `json:"soa_primary,omitempty"     jsonschema:"the name server the zone's SOA record names as its primary"`
	Responsible string   `json:"soa_responsible,omitempty" jsonschema:"the mailbox its SOA record gives for whoever runs it"`
	Refresh     int      `json:"refresh,omitempty"         jsonschema:"seconds between a copy's checks on its primary"`
	Retry       int      `json:"retry,omitempty"           jsonschema:"seconds before a check that failed is made again"`
	Expire      int      `json:"expire,omitempty"          jsonschema:"seconds a copy that cannot reach its primary goes on answering"`
	Minimum     int      `json:"minimum,omitempty"         jsonschema:"seconds the answer that a name does not exist may be kept"`
	NameServers []string `json:"name_servers,omitempty"    jsonschema:"the name servers the zone's own NS records name: the ones a transfer or a notify limited to the zone's name servers is for"`

	Query            string   `json:"query,omitempty"             jsonschema:"who may ask for the zone's names: Allow, Deny, AllowOnlyPrivateNetworks, AllowOnlyZoneNameServers, or by the networks in query_networks"`
	QueryNetworks    []string `json:"query_networks,omitempty"`
	Transfer         string   `json:"transfer,omitempty"          jsonschema:"who may transfer the zone whole: Deny, Allow (anyone), AllowOnlyZoneNameServers, or by the networks in transfer_networks"`
	TransferNetworks []string `json:"transfer_networks,omitempty"`
	TransferKeys     []string `json:"transfer_keys,omitempty"     jsonschema:"the keys a transfer must be signed with, by name"`
	Notify           string   `json:"notify,omitempty"            jsonschema:"who is told when the zone changes: None, ZoneNameServers, or the servers in notify_servers"`
	NotifyServers    []string `json:"notify_servers,omitempty"`
	NotifyFailedFor  []string `json:"notify_failed_for,omitempty" jsonschema:"the servers its last notify did not reach"`
	Update           string   `json:"update,omitempty"            jsonschema:"who may change its records by a DNS update: Deny, Allow (anyone), AllowOnlyZoneNameServers, or by the networks in update_networks"`
	UpdateNetworks   []string `json:"update_networks,omitempty"`
	UpdateKeys       []string `json:"update_keys,omitempty"       jsonschema:"the keys an update must be signed with, each as its name, the names it may change and the types"`

	PrimaryAddresses []string `json:"primary_addresses,omitempty" jsonschema:"for a copy: where it transfers from"`
	PrimaryProtocol  string   `json:"primary_protocol,omitempty"  jsonschema:"for a copy: how it transfers, Tcp, Tls or Quic"`
	PrimaryKey       string   `json:"primary_key,omitempty"       jsonschema:"for a copy: the key it signs its transfers with, by name"`
}

// zoneSetupOf reads how a server serves a zone it holds: the zone's options,
// and the SOA and NS records at its own name. held is nil for a server that
// does not hold the zone.
func zoneSetupOf(ctx context.Context, srv *servers.Server, zone string) (*zoneSetup, error) {
	zones, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(zones, func(z technitium.Zone) bool { return sameName(z.Name, zone) })
	if i < 0 {
		return nil, nil //nolint:nilnil // a server that does not hold the zone has no setup of it, and that is no error
	}
	row := &zoneSetup{Server: srv.Name, Type: zones[i].Type, Disabled: zones[i].Disabled, Catalog: zones[i].Catalog, Serial: zones[i].SOASerial}

	o, err := srv.Client.ZoneOptions(ctx, zones[i].Name)
	if err != nil {
		return nil, err
	}
	row.Query, row.QueryNetworks, row.Transfer, row.TransferNetworks, row.TransferKeys = o.QueryAccess, o.QueryAccessNetworkACL, o.ZoneTransfer, o.ZoneTransferNetworkACL, o.ZoneTransferTSIGKeyNames
	row.Notify, row.NotifyServers, row.NotifyFailedFor, row.Update, row.UpdateNetworks = o.Notify, o.NotifyNameServers, o.NotifyFailedFor, o.Update, o.UpdateNetworkACL
	row.PrimaryAddresses, row.PrimaryProtocol, row.PrimaryKey = o.PrimaryNameServerAddresses, o.PrimaryZoneTransferProtocol, o.PrimaryZoneTransferTSIGKeyName
	if o.DNSSECStatus != "" && o.DNSSECStatus != "Unsigned" {
		row.DNSSEC = o.DNSSECStatus
	}
	for _, policy := range o.UpdateSecurityPolicies {
		row.UpdateKeys = append(row.UpdateKeys, policy.TSIGKeyName+" for "+policy.Domain+": "+strings.Join(policy.AllowedTypes, ", "))
	}

	at, err := srv.Client.RecordsAt(ctx, zones[i].Name, zones[i].Name)
	if err != nil {
		return nil, err
	}
	for j := range at.Records {
		switch rec := &at.Records[j]; rec.Type {
		case "NS":
			row.NameServers = append(row.NameServers, cleanName(rec.Target()))
		case "SOA":
			soa := rec.SOA()
			row.SOAPrimary, row.Responsible, row.Refresh, row.Retry, row.Expire, row.Minimum = cleanName(soa.Primary), soa.Responsible, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum
		default:
		}
	}
	slices.Sort(row.NameServers)

	return row, nil
}

func registerZoneSetupTools(r *registry) {
	type zoneGetIn struct {
		serverArg

		Zone string `json:"zone" jsonschema:"the zone's name, as zone_list gives it"`
	}
	type zoneGetOut struct {
		Zone      string      `json:"zone"`
		Servers   []zoneSetup `json:"servers"              jsonschema:"each server holding the zone, with how it serves and copies it"`
		MissingOn []string    `json:"missing_on,omitempty" jsonschema:"the servers asked that do not hold the zone"`
		Differ    []string    `json:"differ,omitempty"     jsonschema:"what the servers holding it do not have alike, by the name each has in a row. A primary and its copy differ in type, and in transfer and notify, which a copy has no use for"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "zone_get",
		Description: "How one zone is served and copied on each server holding it, side by side: its type and catalog, the primary and the times its SOA record gives, the name servers its NS records name, who may ask for its names, who may transfer it and with which keys, who is told when it changes and whom the last notify did not reach, who may change it by a DNS update, and for a copy where it transfers from. For why a copy is behind, why a transfer is refused, and whether a zone is open to anyone. A key is given by its name: no secret is read.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneGetIn) (*mcp.CallToolResult, zoneGetOut, error) {
		zone := cleanName(in.Zone)
		if zone == "" {
			return nil, zoneGetOut{}, errors.New("which zone: give its name, as zone_list gives it")
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, zoneGetOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (*zoneSetup, error) {
			return zoneSetupOf(ctx, srv, zone)
		})
		if _, err := failures(answers); err != nil {
			return nil, zoneGetOut{}, err
		}

		out := zoneGetOut{Zone: zone, Servers: []zoneSetup{}}
		var held []*zoneSetup
		for _, a := range answers {
			switch {
			case a.Err != nil:
				out.Servers = append(out.Servers, zoneSetup{Server: a.Server.Name, Error: a.Err.Error()})
			case a.Value == nil:
				out.MissingOn = append(out.MissingOn, a.Server.Name)
			default:
				out.Servers = append(out.Servers, *a.Value)
				held = append(held, a.Value)
			}
		}
		if len(held) == 0 && len(out.MissingOn) == len(answers) {
			return nil, zoneGetOut{}, fmt.Errorf("no server asked holds a zone named %s: zone_list names the zones each holds", zone)
		}

		for _, field := range []struct {
			name string
			of   func(s *zoneSetup) string
		}{
			{"type", func(s *zoneSetup) string { return s.Type }},
			{"catalog", func(s *zoneSetup) string { return s.Catalog }},
			{"serial", func(s *zoneSetup) string { return strconv.FormatUint(uint64(s.Serial), 10) }},
			{"soa_primary", func(s *zoneSetup) string { return s.SOAPrimary }},
			{"name_servers", func(s *zoneSetup) string { return strings.Join(s.NameServers, " ") }},
			{"query", func(s *zoneSetup) string { return s.Query + " " + strings.Join(s.QueryNetworks, " ") }},
			{"transfer", func(s *zoneSetup) string {
				return s.Transfer + " " + strings.Join(s.TransferNetworks, " ") + " " + strings.Join(s.TransferKeys, " ")
			}},
			{"notify", func(s *zoneSetup) string { return s.Notify + " " + strings.Join(s.NotifyServers, " ") }},
			{"update", func(s *zoneSetup) string {
				return s.Update + " " + strings.Join(s.UpdateNetworks, " ") + " " + strings.Join(s.UpdateKeys, " ")
			}},
		} {
			if slices.ContainsFunc(held, func(s *zoneSetup) bool { return field.of(s) != field.of(held[0]) }) {
				out.Differ = append(out.Differ, field.name)
			}
		}

		return nil, out, nil
	})

	type zoneExportIn struct {
		Server string `json:"server,omitempty" jsonschema:"the configured server to export from: a name server_info lists. Left out, the one that holds the zone as its own, or the only one that holds it"`
		Zone   string `json:"zone"             jsonschema:"the zone's name, as zone_list gives it"`
		Limit  int    `json:"limit,omitempty"  jsonschema:"the most lines to give (default 500)"`
		Offset int    `json:"offset,omitempty" jsonschema:"how many lines to pass over first, to read on from a limit"`
	}
	type zoneExportOut struct {
		Zone   string `json:"zone"`
		Server string `json:"server"         jsonschema:"the server the zone was exported from"`
		Text   string `json:"text"           jsonschema:"the zone as a zone file: a record a line, each record's comment after a semicolon"`
		Lines  int    `json:"lines"          jsonschema:"how many lines the whole file has"`
		Note   string `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "zone_export",
		Description: "One zone whole as a zone file, from one server: every record a line in the form every name server reads, its comment after a semicolon. For keeping a copy before a change, for setting two copies against each other, and for taking a zone elsewhere. A copy's file has no comments, a copy not being given them: the server that holds the zone as its own is exported from unless another is named. zone_records gives the same records as a table to search.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneExportIn) (*mcp.CallToolResult, zoneExportOut, error) {
		zone := cleanName(in.Zone)
		if zone == "" {
			return nil, zoneExportOut{}, errors.New("which zone: give its name, as zone_list gives it")
		}
		srv, err := r.holderOf(ctx, in.Server, zone)
		if err != nil {
			return nil, zoneExportOut{}, err
		}
		text, err := srv.Client.ExportZone(ctx, zone)
		if err != nil {
			return nil, zoneExportOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}

		lines := strings.Split(strings.TrimRight(text, "\r\n"), "\n")
		out := zoneExportOut{Zone: zone, Server: srv.Name, Lines: len(lines)}
		offset, limit := min(max(in.Offset, 0), len(lines)), in.Limit
		if limit <= 0 {
			limit = exportDefault
		}
		lines = lines[offset:]
		if len(lines) > limit {
			lines = lines[:limit]
			out.Note = fmt.Sprintf("the file has %d lines and %d are given, starting at the %s: read on with offset %d", out.Lines, limit, ordinal(offset+1), offset+limit)
		}
		out.Text = strings.Join(lines, "\n")

		return nil, out, nil
	})
}

// holderOf is the server a zone is read whole from: the one named; or with
// none named, the one that holds the zone as its own, or the only one that
// holds it at all.
func (r *registry) holderOf(ctx context.Context, server, zone string) (*servers.Server, error) {
	if strings.TrimSpace(server) != "" || r.servers.Len() == 1 {
		return r.servers.One(server)
	}

	var own, copies []*servers.Server
	var failed []string
	for _, a := range ask(ctx, r.servers.Every(), func(ctx context.Context, srv *servers.Server) ([]technitium.Zone, error) {
		return srv.Client.Zones(ctx, technitium.ZoneFilter{})
	}) {
		if a.Err != nil {
			failed = append(failed, a.Server.Name+": "+a.Err.Error())

			continue
		}
		if i := slices.IndexFunc(a.Value, func(z technitium.Zone) bool { return sameName(z.Name, zone) }); i >= 0 && isCopy(a.Value[i].Type) {
			copies = append(copies, a.Server)
		} else if i >= 0 {
			own = append(own, a.Server)
		}
	}
	names := func(list []*servers.Server) string {
		out := make([]string, 0, len(list))
		for _, srv := range list {
			out = append(out, srv.Name)
		}

		return strings.Join(out, " and ")
	}
	switch {
	case len(own) == 1:
		return own[0], nil
	case len(own) > 1:
		return nil, fmt.Errorf("%s each hold %s as a zone of their own: say which to export from with server", names(own), zone)
	case len(copies) == 1:
		return copies[0], nil
	case len(copies) > 1:
		return nil, fmt.Errorf("%s each hold %s as a copy, and no server here holds it as its own: say which to export from with server", names(copies), zone)
	case len(failed) > 0:
		return nil, fmt.Errorf("no server that could be asked holds a zone named %s, and some could not be asked: %s", zone, strings.Join(failed, "; "))
	default:
		return nil, fmt.Errorf("no server holds a zone named %s: zone_list names the zones each holds", zone)
	}
}
