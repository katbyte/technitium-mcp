package tools

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerImportTool(r *registry) {
	type importIn struct {
		writeServerArg

		Name   string `json:"name"              jsonschema:"the domain name whose records to copy in"`
		Type   string `json:"type,omitempty"    jsonschema:"the record type to copy: A (the default), AAAA, MX, TXT, ..."`
		From   string `json:"from,omitempty"    jsonschema:"the name server to ask: the address of the server that holds the records now, or of a public resolver; left out, the server resolves the name from the root past its own zones"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"change nothing: ask, and answer with the records that would be copied in and where"`
	}
	type importOut struct {
		Server  string      `json:"server"`
		Zone    string      `json:"zone,omitempty"  jsonschema:"the zone the records were written into; with a dry run, the one they would be"`
		Changed bool        `json:"changed"`
		Changes []string    `json:"changes"`
		Asked   string      `json:"asked"           jsonschema:"the name server that answered"`
		Records []string    `json:"records"         jsonschema:"the records of the answer, each as name, type and value"`
		After   []recordRow `json:"after,omitempty" jsonschema:"the records of the type at the name on the server now, read back; absent from a dry run"`
		Note    string      `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "dns_import",
		Description: "Copy a name's records in from another name server: the server asks for the name and type, and writes the records of the answer into the zone it holds for the name, in place of the ones of that type it had there. It is how a zone held somewhere else is brought over a name at a time, with nothing typed by hand; zone_import takes a whole zone file at once. The zone must be a primary or a forwarder of the server's own. A server that holds no zone for the name makes a new primary zone named for it, which the answer says first with dry_run. Nothing is copied when the answer is that there is no such record.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in importIn) (*mcp.CallToolResult, importOut, error) {
		name, recordType := cleanName(in.Name), strings.ToUpper(strings.TrimSpace(in.Type))
		if name == "" {
			return nil, importOut{}, errors.New("which name: give the domain name whose records to copy in")
		}
		if recordType == "" {
			recordType = "A"
		}
		from := strings.TrimSpace(in.From)
		if _, isAddr := parseAddr(from); from != "" && !isAddr {
			return nil, importOut{}, fmt.Errorf("from %q is not an address: give the address of the name server to ask, or leave it out to resolve from the root", in.From)
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, importOut{}, err
		}
		q := technitium.ResolveQuery{Name: name, Type: recordType, Via: from}
		if from == "" {
			q.Via = technitium.ResolveRecursively
		}

		// asked first without writing anything: what would come in, and whether there is anything to bring
		res, err := srv.Client.Resolve(ctx, q)
		if err != nil {
			return nil, importOut{}, fmt.Errorf("asking for %s %s: %w", recordType, name, err)
		}
		out := importOut{Server: srv.Name, Changes: []string{}, Asked: res.Metadata.NameServer, Records: []string{}}
		for i := range res.Answer {
			if rec := &res.Answer[i]; rec.Type != "RRSIG" {
				out.Records = append(out.Records, rec.Name+" "+rec.Type+" "+rec.Value())
			}
		}
		if len(out.Records) == 0 {
			out.Note = fmt.Sprintf("the answer was %s with no %s record for %s: there is nothing to copy in", res.RCode, recordType, name)

			return nil, out, nil
		}

		// the zone the records go into: the closest the server holds for the name, which it makes when it holds none
		zones, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
		if err != nil {
			return nil, importOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		var held *technitium.Zone
		for i := range zones {
			if zone := cleanName(zones[i].Name); (name == zone || strings.HasSuffix(name, "."+zone)) && (held == nil || len(zone) > len(held.Name)) {
				held = &zones[i]
			}
		}
		done := &changes{dry: in.DryRun}
		switch {
		case held == nil:
			out.Zone = name
			out.Note = fmt.Sprintf("%s holds no zone for %s: a new primary zone named %s is made for the records", srv.Name, name, name)
			done.did("made the zone %s on %s and copied %d records into it", name, srv.Name, len(out.Records))
		case held.Type != technitium.ZonePrimary && held.Type != technitium.ZoneForwarder:
			return nil, importOut{}, fmt.Errorf("%s holds %s as a %s zone, and records are copied into a primary or a forwarder of the server's own. Nothing was changed", srv.Name, held.Name, held.Type)
		default:
			out.Zone = held.Name
			done.did("copied %d records for %s %s into %s on %s, in place of the ones of that type it had there", len(out.Records), recordType, name, held.Name, srv.Name)
		}
		out.Changed, out.Changes = true, done.said
		if in.DryRun {
			return nil, out, nil
		}

		if _, err := srv.Client.ImportResolved(ctx, q); err != nil {
			return nil, importOut{}, fmt.Errorf("copying the records in: %w", err)
		}
		at, err := srv.Client.RecordsAt(ctx, name, out.Zone)
		if err != nil {
			return nil, importOut{}, fmt.Errorf("the records were copied in and could not be read back: %w", err)
		}
		out.After = rowsAt(at.Records, recordType)
		if !slices.ContainsFunc(at.Records, func(rec technitium.Record) bool { return rec.Type == recordType }) && recordType != "ANY" {
			return nil, importOut{}, fmt.Errorf("the server said ok and %s has no %s record at %s", srv.Name, recordType, name)
		}

		return nil, out, nil
	})
}
