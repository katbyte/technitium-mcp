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

// zoneChangeOut is what the tools that make, turn or take away a whole zone
// answer with.
type zoneChangeOut struct {
	Server  string     `json:"server"`
	Zone    string     `json:"zone"`
	Changed bool       `json:"changed"         jsonschema:"something was changed; with a dry run, something would be"`
	Changes []string   `json:"changes"         jsonschema:"each change made; with a dry run, each that would be"`
	After   *zoneSetup `json:"after,omitempty" jsonschema:"the zone as the server holds it now, read back; absent from a dry run and once the zone is deleted"`
	Note    string     `json:"note,omitempty"`
}

// cacheNote is what every tool that makes or deletes a zone says of the
// server's cache.
const cacheNote = "making or deleting a zone can empty the server's whole cache, which fills again as names are asked for"

// recordLines counts the records a zone file holds: its lines that are
// neither blank, a comment nor a directive.
func recordLines(zoneFile string) int {
	n := 0
	for line := range strings.SplitSeq(zoneFile, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, ";") && !strings.HasPrefix(line, "$") {
			n++
		}
	}

	return n
}

func registerZoneMoreTools(r *registry) {
	type zoneDeleteIn struct {
		writeServerArg

		Zone   string `json:"zone"              jsonschema:"the zone's name, as zone_list gives it"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"delete nothing, and answer with what would be"`
	}
	type zoneDeleteOut struct {
		zoneChangeOut

		Type    string `json:"type"    jsonschema:"what the zone was: Primary, Secondary, Forwarder and so on"`
		Records int    `json:"records" jsonschema:"how many records the zone held when it was deleted"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "zone_delete",
		Description: "Delete a whole zone from one server, with every record in it. There is no undo: export the zone as a file first, which zone_import can put back into a new zone. A zone the server made for itself is refused. Deleting a primary does not delete the copies other servers hold of it, which go on answering until they expire; a member of a cluster's catalog is deleted on the primary and goes from every node. With dry_run it deletes nothing and says what the zone holds.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneDeleteIn) (*mcp.CallToolResult, zoneDeleteOut, error) {
		zone := cleanName(in.Zone)
		if zone == "" {
			return nil, zoneDeleteOut{}, errors.New("which zone: give its name, as zone_list gives it")
		}
		srv, held, err := r.zoneOn(ctx, in.Server, zone)
		if err != nil {
			return nil, zoneDeleteOut{}, err
		}
		if held.Internal {
			return nil, zoneDeleteOut{}, fmt.Errorf("%s is a zone %s made for itself and keeps: it is not deleted", held.Name, srv.Name)
		}
		records, err := srv.Client.ZoneRecords(ctx, held.Name)
		if err != nil {
			return nil, zoneDeleteOut{}, fmt.Errorf("reading %s before deleting it: %w", zone, err)
		}

		out := zoneDeleteOut{Server: srv.Name, Zone: held.Name, Changed: true, Note: cacheNote, Type: held.Type, Records: len(records.Records)}
		done := &changes{dry: in.DryRun}
		if done.did("deleted the %s zone %s on %s with its %d records", held.Type, held.Name, srv.Name, len(records.Records)) {
			if err := srv.Client.DeleteZone(ctx, held.Name); err != nil {
				return nil, zoneDeleteOut{}, fmt.Errorf("deleting %s: %w", zone, err)
			}
			if _, still, err := r.zoneOn(ctx, srv.Name, zone); err == nil && still != nil {
				return nil, zoneDeleteOut{}, fmt.Errorf("the server said ok and %s still holds %s", srv.Name, zone)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type zoneCloneIn struct {
		writeServerArg

		Zone   string `json:"zone"              jsonschema:"the name of the zone to make"`
		Source string `json:"source"            jsonschema:"the zone to copy, as zone_list gives it, on the same server"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"make nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "zone_clone",
		Description: "Make a zone that is another's copy at the time, on the same server: every record the source has, under the new zone's name, with the source's options. The two are not tied together afterwards. It is how a zone is made from a template, and how one is renamed: clone it under the new name, check the clone, then zone_delete the old. A zone that is there already is refused.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneCloneIn) (*mcp.CallToolResult, zoneChangeOut, error) {
		zone, err := zoneNameOf(in.Zone)
		if err != nil {
			return nil, zoneChangeOut{}, err
		}
		srv, source, err := r.zoneOn(ctx, in.Server, cleanName(in.Source))
		if err != nil {
			return nil, zoneChangeOut{}, fmt.Errorf("the zone to copy: %w", err)
		}
		if _, there, err := r.zoneOn(ctx, srv.Name, zone); err == nil && there != nil {
			return nil, zoneChangeOut{}, fmt.Errorf("%s holds %s already, as a %s zone: a clone is made under a name nothing has", srv.Name, zone, there.Type)
		}

		out := zoneChangeOut{Server: srv.Name, Zone: zone, Changed: true, Note: cacheNote}
		done := &changes{dry: in.DryRun}
		if done.did("made %s on %s as a copy of %s", zone, srv.Name, source.Name) {
			if err := srv.Client.CloneZone(ctx, zone, source.Name); err != nil {
				return nil, zoneChangeOut{}, fmt.Errorf("cloning %s as %s: %w", source.Name, zone, err)
			}
			if out.After, err = zoneSetupOf(ctx, srv, zone); err != nil {
				return nil, zoneChangeOut{}, fmt.Errorf("the clone was made and could not be read back: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})

	type zoneConvertIn struct {
		writeServerArg

		Zone   string `json:"zone"              jsonschema:"the zone's name, as zone_list gives it"`
		Type   string `json:"type"              jsonschema:"what the zone is to be: Primary, Secondary, Forwarder, SecondaryForwarder, Catalog or SecondaryCatalog. The server allows some conversions and refuses the rest, saying which"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "zone_convert",
		Description: "Turn a zone into another type where it stands, keeping its records: a secondary into a primary, when the server it copied from is gone and this one is to take over; a primary into a forwarder and back. What a type has no use for is dropped in the turning - a primary made a forwarder loses its SOA's part in the world, and a copy made a primary stops following anything - so read the zone back (it is in the answer) before relying on it. A zone already of the type asked for is left alone.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneConvertIn) (*mcp.CallToolResult, zoneChangeOut, error) {
		zone := cleanName(in.Zone)
		if zone == "" {
			return nil, zoneChangeOut{}, errors.New("which zone: give its name, as zone_list gives it")
		}
		i := slices.IndexFunc(technitium.ZoneTypes, func(known string) bool { return strings.EqualFold(known, strings.TrimSpace(in.Type)) })
		if i < 0 {
			return nil, zoneChangeOut{}, fmt.Errorf("type %q: a zone is one of %s", in.Type, strings.Join(technitium.ZoneTypes, ", "))
		}
		want := technitium.ZoneTypes[i]
		srv, held, err := r.zoneOn(ctx, in.Server, zone)
		if err != nil {
			return nil, zoneChangeOut{}, err
		}

		out := zoneChangeOut{Server: srv.Name, Zone: held.Name}
		done := &changes{dry: in.DryRun}
		if held.Type != want {
			out.Changed = true
			if done.did("turned %s on %s from a %s zone into a %s zone", held.Name, srv.Name, held.Type, want) {
				if err := srv.Client.ConvertZone(ctx, held.Name, want); err != nil {
					return nil, zoneChangeOut{}, fmt.Errorf("converting %s: %w", zone, err)
				}
			}
		}
		if !in.DryRun {
			if out.After, err = zoneSetupOf(ctx, srv, held.Name); err != nil {
				return nil, zoneChangeOut{}, fmt.Errorf("the zone could not be read back: %w", err)
			}
			if out.After.Type != want {
				return nil, zoneChangeOut{}, fmt.Errorf("the server said ok and %s on %s is still a %s zone", zone, srv.Name, out.After.Type)
			}
		}
		out.Changes = done.said
		if out.Changes == nil {
			out.Changes = []string{}
		}

		return nil, out, nil
	})

	type zoneImportIn struct {
		writeServerArg

		Zone               string `json:"zone"                           jsonschema:"the zone to add the records to, as zone_list gives it: it must be there already (zone_create makes one)"`
		ZoneFile           string `json:"zone_file"                      jsonschema:"the records as a zone file: what an export of a zone gives, or any file in the standard format. Names in it are under the zone, so a file exported from another zone has that zone's name put in place of this one's first"`
		KeepExisting       bool   `json:"keep_existing,omitempty"        jsonschema:"where the zone already has records of a type at a name the file has too, add the file's beside them; the default replaces them with the file's"`
		ReplaceZone        bool   `json:"replace_zone,omitempty"         jsonschema:"delete every record the zone has before the file's are added, so the zone ends as the file and nothing more"`
		OverwriteSOASerial bool   `json:"overwrite_soa_serial,omitempty" jsonschema:"take the SOA serial the file gives. A serial lower than the zone's own stops its copies on other servers from following it"`
		DryRun             bool   `json:"dry_run,omitempty"              jsonschema:"change nothing, and answer with what would be"`
	}
	type zoneImportOut struct {
		zoneChangeOut

		InFile  int `json:"in_file"           jsonschema:"how many records the file holds"`
		Before  int `json:"before"            jsonschema:"how many records the zone held before"`
		Records int `json:"records,omitempty" jsonschema:"how many records the zone holds now; absent from a dry run"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "zone_import",
		Description: "Add the records of a zone file to a zone a server holds: many records in one call, or a zone moved in from somewhere else. By default a name's records of a type are replaced by the file's and everything else in the zone is left; keep_existing adds beside them, and replace_zone empties the zone first. The zone must be a primary or a forwarder of the server's own. With dry_run it changes nothing and counts what the file holds. zone_records reads the result.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneImportIn) (*mcp.CallToolResult, zoneImportOut, error) {
		zone := cleanName(in.Zone)
		if zone == "" {
			return nil, zoneImportOut{}, errors.New("which zone: give its name, as zone_list gives it")
		}
		inFile := recordLines(in.ZoneFile)
		if inFile == 0 {
			return nil, zoneImportOut{}, errors.New("the zone file holds no records: give it as an export of a zone gives one, a record a line")
		}
		if in.KeepExisting && in.ReplaceZone {
			return nil, zoneImportOut{}, errors.New("keep_existing and replace_zone ask for opposite things: one keeps what the zone has, the other deletes it first")
		}
		srv, held, err := r.zoneOn(ctx, in.Server, zone)
		if err != nil {
			return nil, zoneImportOut{}, err
		}
		if isCopy(held.Type) {
			return nil, zoneImportOut{}, fmt.Errorf("%s holds %s as a %s zone, a copy: its records are its primary's, and are imported there", srv.Name, zone, held.Type)
		}
		before, err := srv.Client.ZoneRecords(ctx, held.Name)
		if err != nil {
			return nil, zoneImportOut{}, fmt.Errorf("reading %s: %w", zone, err)
		}

		out := zoneImportOut{Server: srv.Name, Zone: held.Name, Changed: true, InFile: inFile, Before: len(before.Records)}
		how := "replacing the records it has at the same names and types"
		switch {
		case in.ReplaceZone:
			how = fmt.Sprintf("in place of the %d records it had", len(before.Records))
		case in.KeepExisting:
			how = "beside the records it has"
		default:
		}
		done := &changes{dry: in.DryRun}
		if done.did("imported the file's %d records into %s on %s, %s", inFile, held.Name, srv.Name, how) {
			if err := srv.Client.ImportZone(ctx, held.Name, in.ZoneFile, technitium.ZoneImport{KeepExisting: in.KeepExisting, ReplaceZone: in.ReplaceZone, OverwriteSOASerial: in.OverwriteSOASerial}); err != nil {
				return nil, zoneImportOut{}, fmt.Errorf("importing into %s: %w", zone, err)
			}
			after, err := srv.Client.ZoneRecords(ctx, held.Name)
			if err != nil {
				return nil, zoneImportOut{}, fmt.Errorf("the file was imported and %s could not be read back: %w", zone, err)
			}
			out.Records = len(after.Records)
		}
		out.Changes = done.said

		return nil, out, nil
	})
}
