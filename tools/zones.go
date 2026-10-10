package tools

import (
	"cmp"
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

// nameOrder is a domain name as a key that sorts the way a zone reads: by
// its labels from the right, so a zone's own name comes first and every name
// under a subdomain sits together.
func nameOrder(name string) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	slices.Reverse(labels)

	return strings.Join(labels, ".")
}

// sameName reports whether two domain names are one: DNS ignores case and a
// trailing dot.
func sameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// zoneOn is a zone as one server holds it.
type zoneOn struct {
	Server       string   `json:"server"`
	Type         string   `json:"type"                    jsonschema:"Primary, Secondary, Stub, Forwarder, SecondaryForwarder, Catalog or SecondaryCatalog"`
	Serial       uint32   `json:"serial"                  jsonschema:"the zone's SOA serial on this server"`
	Disabled     bool     `json:"disabled,omitempty"`
	Internal     bool     `json:"internal,omitempty"      jsonschema:"a zone the server made for itself and keeps"`
	DNSSEC       string   `json:"dnssec,omitempty"        jsonschema:"how the zone is signed; absent for an unsigned zone"`
	Catalog      string   `json:"catalog,omitempty"       jsonschema:"the catalog zone this one is a member of"`
	Modified     string   `json:"modified,omitempty"      jsonschema:"when a record in the zone last changed on this server, in UTC"`
	Records      *int     `json:"records,omitempty"       jsonschema:"how many records the zone holds on this server; only with counts"`
	Expiry       string   `json:"expiry,omitempty"        jsonschema:"a secondary's: when this copy stops being served unless a transfer renews it, in UTC"`
	Expired      bool     `json:"expired,omitempty"       jsonschema:"a secondary's: the copy has expired and is no longer served"`
	SyncFailed   bool     `json:"sync_failed,omitempty"   jsonschema:"a secondary's: the last transfer from its primary failed"`
	NotifyFailed []string `json:"notify_failed,omitempty" jsonschema:"a primary's: the secondaries it could not tell of its last change"`
	Error        string   `json:"error,omitempty"         jsonschema:"why the zone's records could not be counted on this server"`
}

func zoneOnOf(server string, z *technitium.Zone) zoneOn {
	on := zoneOn{Server: server, Type: z.Type, Serial: z.SOASerial, Disabled: z.Disabled, Internal: z.Internal, Catalog: z.Catalog, Modified: utc(z.LastModified), Expiry: utc(z.Expiry), Expired: z.IsExpired, SyncFailed: z.SyncFailed}
	if z.Signed() {
		on.DNSSEC = z.DNSSECStatus
	}
	if z.NotifyFailed {
		on.NotifyFailed = append([]string{}, z.NotifyFailedFor...)
	}

	return on
}

// zoneRow is one zone name and every server asked that holds it.
type zoneRow struct {
	Zone      string    `json:"zone"`
	On        []zoneOn  `json:"on"                   jsonschema:"the zone as each server that holds it has it"`
	MissingOn []string  `json:"missing_on,omitempty" jsonschema:"the servers that were asked, answered, and do not hold this zone"`
	Differs   []string  `json:"differs,omitempty"    jsonschema:"what is not the same on every server holding the zone: type, serial, disabled, dnssec, records. A primary and its secondary differ in type by design; a serial that differs is a copy that is behind"`
	ChangeOn  *[]string `json:"change_on,omitempty"  jsonschema:"the servers the zone's records can be changed on, when that is not every server holding it: a secondary or a stub is a copy that takes its records from its primary and refuses a change. An empty list is every copy asked being such a copy, so the primary is a server not configured here"`
}

// isCopy reports whether a zone of this type takes its records from another
// server and refuses a change of its own.
func isCopy(zoneType string) bool {
	switch zoneType {
	case technitium.ZoneSecondary, technitium.ZoneSecondaryForwarder, technitium.ZoneSecondaryCatalog, technitium.ZoneStub:
		return true
	default:
		return false
	}
}

// changeOn is the servers a zone's records can be changed on, and whether
// that needs saying: it does when some server holds only a copy.
func changeOn(on []zoneOn) (where []string, say bool) {
	where = []string{}
	for i := range on {
		if isCopy(on[i].Type) {
			say = true

			continue
		}
		where = append(where, on[i].Server)
	}

	return where, say
}

// zoneDiffers names what is not the same in every copy of a zone.
func zoneDiffers(on []zoneOn) []string {
	var out []string
	differ := func(what string, same func(a, b *zoneOn) bool) {
		for i := 1; i < len(on); i++ {
			if !same(&on[0], &on[i]) {
				out = append(out, what)

				return
			}
		}
	}
	differ("type", func(a, b *zoneOn) bool { return a.Type == b.Type })
	differ("serial", func(a, b *zoneOn) bool { return a.Serial == b.Serial })
	differ("disabled", func(a, b *zoneOn) bool { return a.Disabled == b.Disabled })
	differ("dnssec", func(a, b *zoneOn) bool { return a.DNSSEC == b.DNSSEC })
	differ("records", func(a, b *zoneOn) bool { return a.Records == nil || b.Records == nil || *a.Records == *b.Records })

	return out
}

// recordKey is what makes two servers' records one record held alike: where
// it is, what it says and how it is served.
type recordKey struct {
	name, recordType, value, comment string
	// options is what the record has beside its value, written as one line
	options     string
	ttl, expiry int
	disabled    bool
}

// recordSeen is one server's own facts about a record it holds.
type recordSeen struct {
	Server   string `json:"server"`
	LastUsed string `json:"last_used,omitempty" jsonschema:"when the record last answered a query on this server, in UTC; absent for one that never has"`
	Modified string `json:"modified,omitempty"  jsonschema:"when the record was last changed on this server, in UTC"`
}

// recordRow is one record, and which of the servers read hold it so.
type recordRow struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	TTL      int               `json:"ttl"                  jsonschema:"seconds"`
	Value    string            `json:"value"                jsonschema:"the record's data as a zone file writes it: an address, a name, or for an MX its preference then its exchange"`
	Comment  string            `json:"comment,omitempty"`
	Disabled bool              `json:"disabled,omitempty"`
	Expiry   int               `json:"expiry_ttl,omitempty" jsonschema:"seconds after its last change at which the server deletes the record by itself"`
	Options  map[string]string `json:"options,omitempty"    jsonschema:"what the record has beside its value, by the API's names for them: an NS record's glue, how a FWD record's name server is reached, what an APP record tells its app (recordData)"`
	OnlyOn   []string          `json:"only_on,omitempty"    jsonschema:"the servers holding this record exactly so, when not every server read does: a record on one server and not another, or held with another TTL or comment, shows as rows that differ here"`
	On       []recordSeen      `json:"on,omitempty"         jsonschema:"each server's own facts about the record; only with details"`
}

// optionsOf is what a record has beside its value, as a row gives it: only
// what is set to something. An option that is off, a forwarder with no
// priority of its own and one that goes through the server's own proxy are
// what every record has, and say nothing.
func optionsOf(rec *technitium.Record) map[string]string {
	set := rec.Options()
	for option, value := range set {
		if value == "false" || (option == "forwarderPriority" && value == "0") || (option == "proxyType" && value == "DefaultProxy") {
			delete(set, option)
		}
	}
	if len(set) == 0 {
		return nil
	}

	return set
}

// typeCount is how many records of one type matched.
type typeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// zoneFound is a zone on one server, or that the server does not hold it.
type zoneFound struct {
	held bool
	// copied is the server holding the zone as a copy of another's: a
	// secondary or a stub
	copied  bool
	records []technitium.Record
	// near are the zones the server does hold that the name asked for lies
	// under, for an answer to a host name given where a zone's belongs
	near []string
}

// readZone reads a zone's records from one server, having first asked
// whether it holds the zone at all: the API's own answer for a zone it lacks
// is an error in words, which could not be told from any other.
func readZone(ctx context.Context, srv *servers.Server, zone string) (zoneFound, error) {
	zones, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
	if err != nil {
		return zoneFound{}, err
	}

	var found zoneFound
	for i := range zones {
		switch {
		case sameName(zones[i].Name, zone):
			found.held, found.copied = true, isCopy(zones[i].Type)
		case strings.HasSuffix(strings.ToLower(zone), "."+strings.ToLower(zones[i].Name)):
			found.near = append(found.near, zones[i].Name)
		default:
		}
	}
	if !found.held {
		return found, nil
	}

	read, err := srv.Client.ZoneRecords(ctx, zone)
	if err != nil {
		return zoneFound{}, err
	}
	found.records = read.Records

	return found, nil
}

func registerZoneTools(r *registry) {
	type zoneListIn struct {
		serverArg

		Name     string `json:"name,omitempty"     jsonschema:"keep the zones whose name matches: with a * (any run of characters) or a ? (any one) the whole name must match, as in *.arpa; without either the text may be anywhere in the name"`
		Type     string `json:"type,omitempty"     jsonschema:"keep the zones of one type on at least one server: Primary, Secondary, Stub, Forwarder, SecondaryForwarder, Catalog or SecondaryCatalog"`
		Internal bool   `json:"internal,omitempty" jsonschema:"also list the zones a server makes for itself (localhost and the loopback reverse zones), left out by default"`
		Counts   bool   `json:"counts,omitempty"   jsonschema:"also count each zone's records on each server, which reads every zone listed whole"`
		Limit    int    `json:"limit,omitempty"    jsonschema:"the most zones to list (default 200)"`
	}
	type zoneListOut struct {
		Zones  []zoneRow       `json:"zones"            jsonschema:"one row a zone name, with the zone as each server holds it"`
		Total  int             `json:"total"            jsonschema:"how many zones matched, before the limit"`
		Asked  []string        `json:"asked"            jsonschema:"the servers that answered"`
		Failed []serverFailure `json:"failed,omitempty" jsonschema:"the servers that could not be asked, and why; their zones are not in this answer, and a zone is not called missing on them"`
		Note   string          `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "zone_list",
		Description: "List the authoritative zones on the configured servers, one row a zone name with the zone as each server holds it side by side. Each copy gives its type (primary, secondary, forwarder, ...), SOA serial, whether it is disabled or DNSSEC signed, when it last changed, and for a secondary whether its last transfer failed or the copy has expired. Each row says which servers lack the zone, what differs between the ones that hold it, and where its records can be changed when some hold only a copy. counts adds how many records each holds. Read a zone's records with zone_records.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneListIn) (*mcp.CallToolResult, zoneListOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, zoneListOut{}, err
		}
		wantType := strings.TrimSpace(in.Type)
		if wantType != "" && !slices.ContainsFunc(technitium.ZoneTypes, func(t string) bool { return strings.EqualFold(t, wantType) }) {
			return nil, zoneListOut{}, fmt.Errorf("type %q is no zone type: it is one of %s", in.Type, strings.Join(technitium.ZoneTypes, ", "))
		}

		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) ([]technitium.Zone, error) {
			return srv.Client.Zones(ctx, technitium.ZoneFilter{})
		})
		failed, err := failures(answers)
		if err != nil {
			return nil, zoneListOut{}, err
		}

		out := zoneListOut{Failed: failed}
		byName := map[string]*zoneRow{}
		name := newPattern(in.Name)
		for _, a := range answers {
			if a.Err != nil {
				continue
			}
			out.Asked = append(out.Asked, a.Server.Name)
			for i := range a.Value {
				z := &a.Value[i]
				if (z.Internal && !in.Internal) || !name.matches(z.Name) {
					continue
				}
				key := strings.ToLower(z.Name)
				if byName[key] == nil {
					byName[key] = &zoneRow{Zone: z.Name}
				}
				byName[key].On = append(byName[key].On, zoneOnOf(a.Server.Name, z))
			}
		}

		rows := make([]*zoneRow, 0, len(byName))
		for _, row := range byName {
			if wantType != "" && !slices.ContainsFunc(row.On, func(on zoneOn) bool { return strings.EqualFold(on.Type, wantType) }) {
				continue
			}
			rows = append(rows, row)
		}
		slices.SortFunc(rows, func(a, b *zoneRow) int { return cmp.Compare(nameOrder(a.Zone), nameOrder(b.Zone)) })
		out.Total = len(rows)
		if limit := limitOr(in.Limit); len(rows) > limit {
			rows = rows[:limit]
			out.Note = fmt.Sprintf("%d zones matched and the first %d are listed: narrow it with name or type, or raise limit", out.Total, limit)
		}

		if in.Counts {
			countRecords(ctx, r.servers, rows)
		}
		for _, row := range rows {
			for _, server := range out.Asked {
				if !slices.ContainsFunc(row.On, func(on zoneOn) bool { return on.Server == server }) {
					row.MissingOn = append(row.MissingOn, server)
				}
			}
			row.Differs = zoneDiffers(row.On)
			if where, say := changeOn(row.On); say {
				row.ChangeOn = &where
			}
			out.Zones = append(out.Zones, *row)
		}

		return nil, out, nil
	})

	type zoneRecordsIn struct {
		serverArg

		Zone     string   `json:"zone"               jsonschema:"the zone's name, as zone_list gives it"`
		Types    []string `json:"types,omitempty"    jsonschema:"keep the records of these types, e.g. A, CNAME; none is every type"`
		Name     string   `json:"name,omitempty"     jsonschema:"keep the records whose name matches: with a * or a ? the whole name must match, as in *.van.example.com; without either the text may be anywhere in the name"`
		Value    string   `json:"value,omitempty"    jsonschema:"keep the records whose value matches, the same way: 10.0.0.4 finds what points at that address, and also 10.0.0.40"`
		Comment  string   `json:"comment,omitempty"  jsonschema:"keep the records whose comment matches, the same way; * alone keeps every record that has a comment"`
		Disabled *bool    `json:"disabled,omitempty" jsonschema:"true keeps only the disabled records, false only the enabled; left out keeps both"`
		Summary  bool     `json:"summary,omitempty"  jsonschema:"answer with the counts alone and no records"`
		Details  bool     `json:"details,omitempty"  jsonschema:"add each server's own facts about each record: when it last answered a query and when it was last changed"`
		Limit    int      `json:"limit,omitempty"    jsonschema:"the most records to give (default 200)"`
		Offset   int      `json:"offset,omitempty"   jsonschema:"how many matching records to pass over first, to read on from a limit"`
	}
	type zoneRecordsOut struct {
		Zone      string          `json:"zone"`
		Read      []string        `json:"read"                 jsonschema:"the servers the zone's records were read from"`
		MissingOn []string        `json:"missing_on,omitempty" jsonschema:"the servers that were asked and do not hold this zone"`
		Failed    []serverFailure `json:"failed,omitempty"     jsonschema:"the servers that could not be asked, and why"`
		Total     int             `json:"total"                jsonschema:"how many records matched, before the limit; a record two servers hold alike is one"`
		ByType    []typeCount     `json:"by_type"              jsonschema:"the matching records counted by type, most first"`
		Records   []recordRow     `json:"records"              jsonschema:"the matching records in the zone's own order: the zone's name first, then each name under it with its subdomains together"`
		Note      string          `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "zone_records",
		Description: "Read the records of one authoritative zone from the configured servers as one table. A record two servers hold alike is one row, and a record only some hold - or hold with another TTL, comment or state - is a row naming them in only_on, so where the servers disagree shows without comparing by hand. Filter by type, name, value, comment and whether disabled; summary gives the counts alone; limit and offset page through a large zone. Every record of the zone is read before any is left out, so a filter never misses one.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in zoneRecordsIn) (*mcp.CallToolResult, zoneRecordsOut, error) {
		zone := strings.TrimSuffix(strings.TrimSpace(in.Zone), ".")
		if zone == "" {
			return nil, zoneRecordsOut{}, errors.New("which zone: zone_list names them")
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, zoneRecordsOut{}, err
		}

		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (zoneFound, error) {
			return readZone(ctx, srv, zone)
		})
		failed, err := failures(answers)
		if err != nil {
			return nil, zoneRecordsOut{}, err
		}

		out := zoneRecordsOut{Zone: zone, Failed: failed}
		var near []string
		for _, a := range answers {
			switch {
			case a.Err != nil:
			case a.Value.held:
				out.Read = append(out.Read, a.Server.Name)
			default:
				out.MissingOn = append(out.MissingOn, a.Server.Name)
				near = append(near, a.Value.near...)
			}
		}
		if len(out.Read) == 0 {
			if len(near) > 0 {
				slices.SortFunc(near, func(a, b string) int { return cmp.Compare(len(b), len(a)) })

				return nil, zoneRecordsOut{}, fmt.Errorf("no server asked holds a zone named %s: it is a name inside the zone %s, so read that zone with name set to %s", zone, near[0], zone)
			}

			return nil, zoneRecordsOut{}, fmt.Errorf("no server asked (%s) holds a zone named %s: zone_list names the zones there are", strings.Join(out.MissingOn, ", "), zone)
		}

		filter := recordFilter{types: in.Types, name: newPattern(in.Name), value: newPattern(in.Value), comment: newPattern(in.Comment), hasComment: strings.TrimSpace(in.Comment) != "", disabled: in.Disabled}
		held := make([]zoneCopy, 0, len(out.Read))
		for _, a := range answers {
			if a.Err == nil && a.Value.held {
				held = append(held, zoneCopy{server: a.Server.Name, copied: a.Value.copied, records: a.Value.records})
			}
		}
		found, copies := mergeRecords(held, filter, in.Details)
		rows := rowsOf(found)
		out.Total = len(rows)
		if len(copies) > 0 && len(out.Read) > 1 {
			out.Note = strings.Join(copies, ", ") + " holds a copy of this zone, and a copy carries no comment and no expiry: a record held alike but for those is one row, with the comment and expiry of the server that has them"
		}

		counts := map[string]int{}
		for i := range rows {
			counts[rows[i].Type]++
		}
		for recordType, n := range counts {
			out.ByType = append(out.ByType, typeCount{Type: recordType, Count: n})
		}
		slices.SortFunc(out.ByType, func(a, b typeCount) int { return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Type, b.Type)) })

		if in.Summary {
			return nil, out, nil
		}
		offset := min(max(in.Offset, 0), len(rows))
		rows = rows[offset:]
		if limit := limitOr(in.Limit); len(rows) > limit {
			rows = rows[:limit]
			out.Note = note(out.Note, fmt.Sprintf("%d records matched and %d are given, starting at the %s: read on with offset %d, narrow it with types, name or value, or ask for summary", out.Total, limit, ordinal(offset+1), offset+limit))
		}
		out.Records = rows

		return nil, out, nil
	})
}

// recordFilter is what zone_records keeps.
type recordFilter struct {
	types       []string
	name, value pattern
	comment     pattern
	hasComment  bool
	disabled    *bool
}

func (f *recordFilter) keeps(rec *technitium.Record) bool {
	if len(f.types) > 0 && !slices.ContainsFunc(f.types, func(t string) bool { return strings.EqualFold(strings.TrimSpace(t), rec.Type) }) {
		return false
	}
	if f.disabled != nil && *f.disabled != rec.Disabled {
		return false
	}

	return f.name.matches(rec.Name) && f.value.matches(rec.Value())
}

// keepsComment is the filter on a record's comment, which is asked of the
// merged row and not of each server's record: a copy has no comment of its
// own, and its record is still the commented one.
func (f *recordFilter) keepsComment(comment string) bool {
	return !f.hasComment || (comment != "" && f.comment.matches(comment))
}

// zoneCopy is one server's copy of a zone, with its records.
type zoneCopy struct {
	server string
	// copied is the server holding the zone as a copy of another's: a
	// secondary or a stub
	copied  bool
	records []technitium.Record
	// zone is the zone as the server lists it, when it was read from a
	// listing
	zone technitium.Zone
}

// merged is one record as the servers read hold it: the row a tool gives,
// and the record itself as the first server holding it has it, for what a
// row does not carry.
type merged struct {
	recordRow

	record *technitium.Record
	// servers are every server holding the record so, which the row's
	// only_on says only when it is not all of them
	servers []string
}

// mergeRecords is the records every server read holds, as one table in the
// zone's own order: a record held alike on several servers is one row, and a
// row not every server holds names the ones that do. It also returns the
// servers that hold the zone as a copy.
//
// A copy is what a zone transfer carries, which is the records and nothing
// the server keeps beside them: a secondary has no comment for any record and
// no expiry. So when a copy is among the servers read, a record is the same
// record whatever its comment and expiry, and the row gives the ones a server
// has - every commented record of a cluster's zone would otherwise be two
// rows that differ in nothing a secondary can hold.
func mergeRecords(held []zoneCopy, filter recordFilter, details bool) (out []merged, copies []string) {
	for i := range held {
		if held[i].copied {
			copies = append(copies, held[i].server)
		}
	}

	rows := map[recordKey]*merged{}
	for i := range held {
		server := held[i].server
		for j := range held[i].records {
			rec := &held[i].records[j]
			if !filter.keeps(rec) {
				continue
			}
			set := optionsOf(rec)
			key := recordKey{name: strings.ToLower(rec.Name), recordType: rec.Type, value: rec.Value(), comment: rec.Comments, ttl: rec.TTL, expiry: rec.ExpiryTTL, disabled: rec.Disabled, options: fmt.Sprint(set)}
			if len(copies) > 0 {
				key.comment, key.expiry = "", 0
			}
			row := rows[key]
			if row == nil {
				row = &merged{Name: rec.Name, Type: rec.Type, TTL: rec.TTL, Value: key.value, Disabled: rec.Disabled, Options: set, record: rec}
				rows[key] = row
			}
			if row.Comment == "" {
				row.Comment = rec.Comments
			}
			if row.Expiry == 0 {
				row.Expiry = rec.ExpiryTTL
			}
			// a server holding the same record twice is one row still
			if !slices.Contains(row.servers, server) {
				row.servers = append(row.servers, server)
				row.On = append(row.On, recordSeen{Server: server, LastUsed: utc(rec.LastUsedOn), Modified: utc(rec.LastModified)})
			}
		}
	}

	out = make([]merged, 0, len(rows))
	for _, row := range rows {
		if !filter.keepsComment(row.Comment) {
			continue
		}
		if len(row.servers) != len(held) {
			row.OnlyOn = row.servers
		}
		if !details {
			row.On = nil
		}
		out = append(out, *row)
	}
	slices.SortFunc(out, func(a, b merged) int {
		return cmp.Or(cmp.Compare(nameOrder(a.Name), nameOrder(b.Name)), cmp.Compare(a.Type, b.Type), cmp.Compare(a.Value, b.Value), cmp.Compare(a.TTL, b.TTL), cmp.Compare(strings.Join(a.servers, ","), strings.Join(b.servers, ",")))
	})

	return out, copies
}

// rowsOf is the rows of merged records, as a tool gives them.
func rowsOf(records []merged) []recordRow {
	rows := make([]recordRow, 0, len(records))
	for i := range records {
		rows = append(rows, records[i].recordRow)
	}

	return rows
}

// countRecords fills in how many records each zone listed holds on each
// server that holds it, reading each server's zones one after another and
// the servers at once.
func countRecords(ctx context.Context, set *servers.Set, rows []*zoneRow) {
	ask(ctx, set.Every(), func(ctx context.Context, srv *servers.Server) (struct{}, error) {
		for _, row := range rows {
			for i := range row.On {
				on := &row.On[i]
				if on.Server != srv.Name {
					continue
				}
				read, err := srv.Client.ZoneRecords(ctx, row.Zone)
				if err != nil {
					on.Error = err.Error()

					continue
				}
				on.Records = new(len(read.Records))
			}
		}

		return struct{}{}, nil
	})
}

// ordinal is a position in words a note can carry: 1st, 2nd, 201st.
func ordinal(n int) string {
	suffix := "th"
	if n%100 < 11 || n%100 > 13 {
		switch n % 10 {
		case 1:
			suffix = "st"
		case 2:
			suffix = "nd"
		case 3:
			suffix = "rd"
		default:
		}
	}

	return strconv.Itoa(n) + suffix
}
