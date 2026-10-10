package tools

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// writeServerArg is the argument every change takes to say which server it is
// made on.
type writeServerArg struct {
	Server string `json:"server,omitempty" jsonschema:"the configured server to make the change on: a name server_info lists. It can be left out only when one server is configured: a change is made on one server at a time, and in a cluster on the server that holds the zone as a primary, which zone_list names in change_on"`
}

// place is where a change to a name is made: the server, and the zone on it
// that holds the name.
type place struct {
	srv  *servers.Server
	zone string
}

// placeFor finds where a change to a name is made on the server asked for:
// the zone named, or the closest zone the server holds for the name. A zone
// the server holds only as a copy takes no changes, and the refusal names the
// configured server that holds it as its own, when one does.
func (r *registry) placeFor(ctx context.Context, server, zoneArg, name string) (place, error) {
	srv, err := r.servers.One(server)
	if err != nil {
		return place{}, err
	}
	zones, err := srv.Client.Zones(ctx, technitium.ZoneFilter{})
	if err != nil {
		return place{}, fmt.Errorf("%s: %w", srv.Name, err)
	}

	var held *technitium.Zone
	want := cleanName(zoneArg)
	for i := range zones {
		z := &zones[i]
		zone := cleanName(z.Name)
		switch {
		case want != "" && zone != want:
		case name != zone && !strings.HasSuffix(name, "."+zone):
		case held == nil || len(zone) > len(held.Name):
			held = z
		default:
		}
	}
	switch {
	case held == nil && want != "":
		return place{}, fmt.Errorf("%s holds no zone named %s that %s is in: zone_list names the zones it holds", srv.Name, want, name)
	case held == nil:
		return place{}, fmt.Errorf("%s holds no zone that %s is in: zone_list names the zones it holds", srv.Name, name)
	case !isCopy(held.Type):
		return place{srv: srv, zone: held.Name}, nil
	default:
	}

	// a copy: say where its records can be changed, if a server here holds it so
	var own []string
	others := slices.DeleteFunc(r.servers.Every(), func(o *servers.Server) bool { return o.Name == srv.Name })
	for _, a := range ask(ctx, others, func(ctx context.Context, o *servers.Server) ([]technitium.Zone, error) {
		return o.Client.Zones(ctx, technitium.ZoneFilter{})
	}) {
		if a.Err == nil && slices.ContainsFunc(a.Value, func(z technitium.Zone) bool { return sameName(z.Name, held.Name) && !isCopy(z.Type) }) {
			own = append(own, a.Server.Name)
		}
	}
	where := "on the server it is a copy of, which is not one configured here"
	if len(own) > 0 {
		where = "on " + strings.Join(own, " or ") + ", which holds the zone as its own"
	}

	return place{}, fmt.Errorf("%s holds %s as a %s zone, a copy that takes no changes: make the change %s. Nothing was changed", srv.Name, held.Name, held.Type, where)
}

// recordAt is a record a change is about, as the tools name one in words.
func recordAt(rec *technitium.Record) string {
	return rec.Type + " " + rec.Value() + " at " + rec.Name
}

// sameValue reports whether two values of one type are the same record's:
// names in them compare without case, as DNS compares them.
func sameValue(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// rowOf is a record as a tool gives one.
func rowOf(rec *technitium.Record) recordRow {
	return recordRow{Name: rec.Name, Type: rec.Type, TTL: rec.TTL, Value: rec.Value(), Comment: rec.Comments, Disabled: rec.Disabled, Expiry: rec.ExpiryTTL}
}

// rowsAt are the records of a type among a name's, as a tool gives them.
func rowsAt(records []technitium.Record, recordType string) []recordRow {
	rows := []recordRow{}
	for i := range records {
		if records[i].Type == recordType {
			rows = append(rows, rowOf(&records[i]))
		}
	}
	slices.SortFunc(rows, func(a, b recordRow) int { return strings.Compare(a.Value, b.Value) })

	return rows
}

// ptrPlan is what setting or removing an address's PTR for a name comes to
// on a server: the reverse zone, the PTR's own name, and what is there.
type ptrPlan struct {
	zone, name string
	// held are the PTR records at the name now
	held []technitium.Record
}

// planPTR finds where the PTR for an address belongs on a server. It is an
// error for the server to hold no reverse zone for the address, or to hold
// one only as a copy: there is then nowhere here to set one.
func (r *registry) planPTR(ctx context.Context, srv *servers.Server, addr netip.Addr) (ptrPlan, error) {
	name := reverseName(addr)
	where, err := r.placeFor(ctx, srv.Name, "", name)
	if err != nil {
		return ptrPlan{}, fmt.Errorf("the PTR for %s belongs at %s: %w", addr, name, err)
	}
	at, err := srv.Client.RecordsAt(ctx, name, where.zone)
	if err != nil {
		return ptrPlan{}, err
	}
	plan := ptrPlan{zone: where.zone, name: name}
	for i := range at.Records {
		if at.Records[i].Type == "PTR" {
			plan.held = append(plan.held, at.Records[i])
		}
	}

	return plan, nil
}

// changes is what a write did, or with a dry run would do, in words and in
// order.
type changes struct {
	dry  bool
	said []string
}

// did records one change, and reports whether it is to be made: with a dry
// run it is said and not made.
func (c *changes) did(format string, args ...any) bool {
	text := fmt.Sprintf(format, args...)
	if c.dry {
		text = "would have " + text
	}
	c.said = append(c.said, text)

	return !c.dry
}

// setPTR makes the PTR for an address name a host, adding it or changing the
// one that names another.
func setPTR(ctx context.Context, srv *servers.Server, plan ptrPlan, host string, ttl int, done *changes) error {
	if slices.ContainsFunc(plan.held, func(rec technitium.Record) bool { return sameValue(rec.Target(), host) }) {
		return nil
	}
	if len(plan.held) > 0 {
		old := &plan.held[0]
		want := technitium.UpdateOf(old)
		want.Data["ptrName"] = host
		if done.did("changed the PTR at %s from %s to %s", plan.name, old.Target(), host) {
			if _, err := srv.Client.UpdateRecord(ctx, plan.zone, old, want); err != nil {
				return fmt.Errorf("changing the PTR at %s: %w", plan.name, err)
			}
		}

		return nil
	}
	if done.did("added PTR %s at %s", host, plan.name) {
		if _, err := srv.Client.AddRecord(ctx, technitium.NewRecord{Zone: plan.zone, Name: plan.name, Type: "PTR", TTL: ttl, Data: technitium.RData{"ptrName": host}}); err != nil {
			return fmt.Errorf("adding the PTR at %s: %w", plan.name, err)
		}
	}

	return nil
}

// dropPTR removes the PTR for an address that names a host, leaving one that
// names another.
func dropPTR(ctx context.Context, srv *servers.Server, plan ptrPlan, host string, done *changes) error {
	for i := range plan.held {
		old := &plan.held[i]
		if !sameValue(old.Target(), host) {
			continue
		}
		if done.did("removed PTR %s at %s", old.Target(), plan.name) {
			if err := srv.Client.DeleteRecord(ctx, plan.zone, old); err != nil {
				return fmt.Errorf("removing the PTR at %s: %w", plan.name, err)
			}
		}
	}

	return nil
}

// keepOthers puts back what the server drops from the other records of a
// type at a name when a write changes the TTL they share: it rewrites every
// one of them at the new TTL, and their comments, their disabled state and
// their expiry do not survive it. others are those records as they were;
// each is read again and, where it has lost something, given it back.
//
// With a dry run nothing can be read back, so what the server is known to
// drop - when the TTL changes - is said of each record that has it.
func keepOthers(ctx context.Context, srv *servers.Server, zone, name string, others []*technitium.Record, ttl int, done *changes) error {
	if len(others) == 0 {
		return nil
	}
	if done.dry {
		for _, was := range others {
			if ttl != was.TTL && (was.Comments != "" || was.Disabled || was.ExpiryTTL != 0) {
				done.did("kept the comment and state of %s, which the server drops when the TTL its records share changes", recordAt(was))
			}
		}

		return nil
	}

	now, err := srv.Client.RecordsAt(ctx, name, zone)
	if err != nil {
		return fmt.Errorf("the record was set, and the others at %s could not be read back to see what they kept: %w", name, err)
	}
	for _, was := range others {
		for i := range now.Records {
			is := &now.Records[i]
			if is.Type != was.Type || !sameValue(is.Value(), was.Value()) || (is.Comments == was.Comments && is.Disabled == was.Disabled && is.ExpiryTTL == was.ExpiryTTL) {
				continue
			}
			want := technitium.UpdateOf(is)
			want.Comments, want.Disabled, want.ExpiryTTL = was.Comments, was.Disabled, was.ExpiryTTL
			done.did("kept the comment and state of %s, which the server drops when the TTL its records share changes", recordAt(was))
			if _, err := srv.Client.UpdateRecord(ctx, zone, is, want); err != nil {
				return fmt.Errorf("the record was set, and %s lost its comment or state to it and could not be given them back: %w", recordAt(was), err)
			}
		}
	}

	return nil
}

func registerRecordWriteTools(r *registry) {
	type recordSetIn struct {
		writeServerArg

		Name     string  `json:"name"               jsonschema:"the record's full domain name"`
		Type     string  `json:"type"               jsonschema:"the record's type: A, AAAA, CNAME, MX, TXT, PTR, NS, SRV, CAA, ANAME or DNAME"`
		Value    string  `json:"value"              jsonschema:"the record's value as zone_records gives one: an address for an A, a name for a CNAME, the preference and the exchange for an MX (10 mail.example.com), the whole text for a TXT"`
		Zone     string  `json:"zone,omitempty"     jsonschema:"the zone the record goes in; left out, the closest zone the server holds for the name"`
		TTL      int     `json:"ttl,omitempty"      jsonschema:"seconds; left out, a record that is there keeps its own and a new one takes the server's default"`
		Comment  *string `json:"comment,omitempty"  jsonschema:"the record's comment; left out, a record that is there keeps its own; an empty one clears it"`
		Disabled *bool   `json:"disabled,omitempty" jsonschema:"true disables the record, so the server stops answering with it, and false enables it; left out keeps it as it is"`
		Replaces string  `json:"replaces,omitempty" jsonschema:"the value of the record of this type at the name to change into this one, keeping its TTL and comment: 10.0.0.4 to move a name from that address to value's"`
		Only     bool    `json:"only,omitempty"     jsonschema:"make this the only record of its type at the name: every other is removed. Without it a record is added beside the ones there, as two A records at one name are"`
		PTR      bool    `json:"ptr,omitempty"      jsonschema:"for an A or an AAAA: also make the PTR record for the address name this name, in the reverse zone the server holds for it, and with replaces remove the old address's"`
		DryRun   bool    `json:"dry_run,omitempty"  jsonschema:"change nothing, and answer with what would be done"`
	}
	type recordSetOut struct {
		Server  string      `json:"server"`
		Zone    string      `json:"zone"`
		Changed bool        `json:"changed"         jsonschema:"something was changed; with a dry run, something would be"`
		Changes []string    `json:"changes"         jsonschema:"each change made, in order; with a dry run, each that would be. Empty when the record was already as asked"`
		Before  []recordRow `json:"before"          jsonschema:"the records of this type at the name before"`
		After   []recordRow `json:"after,omitempty" jsonschema:"the records of this type at the name now, read back from the server; absent from a dry run"`
		Note    string      `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "record_set",
		Description: "Make a record be there with the value given, on one server: added when the name has none like it, changed in place when replaces names the one to change or when only its TTL, comment or state differ, and left alone when it is already so. A record changed keeps its TTL and comment unless new ones are given. Records of one type at a name share one TTL: a record added beside others takes theirs unless given one, a TTL given is set on them all, and their comments, which the server drops when that happens, are put back. only makes it the single record of its type at the name; ptr sets the address's PTR as well. A CNAME is refused beside other records at its name, and anything else beside a CNAME. dry_run answers with what would be done and changes nothing; otherwise the answer is the records before and after, read back. A zone the server holds as a copy is refused, saying where to make the change.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in recordSetIn) (*mcp.CallToolResult, recordSetOut, error) {
		name, recordType := cleanName(in.Name), strings.ToUpper(strings.TrimSpace(in.Type))
		if name == "" || recordType == "" {
			return nil, recordSetOut{}, errors.New("a record needs a name, a type and a value")
		}
		data, err := technitium.ParseValue(recordType, in.Value)
		if err != nil {
			return nil, recordSetOut{}, err
		}
		addr, isAddr := (&technitium.Record{Type: recordType, Data: data}).Address()
		if (recordType == "A" || recordType == "AAAA") && (!isAddr || addr.Is4() != (recordType == "A")) {
			return nil, recordSetOut{}, fmt.Errorf("%q is not an address an %s record holds", in.Value, recordType)
		}
		if in.PTR && !isAddr {
			return nil, recordSetOut{}, fmt.Errorf("ptr is for an A or an AAAA record: a %s has no address to name", recordType)
		}
		value := (&technitium.Record{Type: recordType, Data: data}).Value()

		where, err := r.placeFor(ctx, in.Server, in.Zone, name)
		if err != nil {
			return nil, recordSetOut{}, err
		}
		srv := where.srv
		at, err := srv.Client.RecordsAt(ctx, name, where.zone)
		if err != nil {
			return nil, recordSetOut{}, err
		}
		out := recordSetOut{Server: srv.Name, Zone: where.zone, Before: rowsAt(at.Records, recordType)}

		// a CNAME is the only record at its name, which the server enforces
		// too: said here first, so a dry run says it and a refusal names what
		// is in the way
		var sameType []*technitium.Record
		for i := range at.Records {
			rec := &at.Records[i]
			switch {
			case rec.Type == recordType:
				sameType = append(sameType, rec)
			case signing(rec.Type):
			case recordType == "CNAME":
				return nil, recordSetOut{}, fmt.Errorf("%s has other records (%s), and a CNAME stands alone at its name: remove them first, or use another name. Nothing was changed", name, recordAt(rec))
			case rec.Type == "CNAME":
				return nil, recordSetOut{}, fmt.Errorf("%s is a CNAME to %s, and a CNAME stands alone at its name: no %s record can be added beside it. Nothing was changed", name, rec.Target(), recordType)
			default:
			}
		}

		var target, replaced *technitium.Record
		for _, rec := range sameType {
			if sameValue(rec.Value(), value) {
				target = rec
			}
			if in.Replaces != "" && sameValue(rec.Value(), in.Replaces) {
				replaced = rec
			}
		}
		if in.Replaces != "" && replaced == nil && target == nil {
			have := make([]string, 0, len(sameType))
			for _, rec := range sameType {
				have = append(have, rec.Value())
			}

			return nil, recordSetOut{}, fmt.Errorf("%s has no %s record with the value %s to replace (it has: %s). Nothing was changed", name, recordType, in.Replaces, strings.Join(have, ", "))
		}
		// a name holds one CNAME, or DNAME: setting another is changing it
		if target == nil && replaced == nil && len(sameType) == 1 && (recordType == "CNAME" || recordType == "DNAME") {
			replaced = sameType[0]
		}

		// where the PTRs involved belong is found before anything is changed
		var newPTR, oldPTR ptrPlan
		if in.PTR {
			if newPTR, err = r.planPTR(ctx, srv, addr); err != nil {
				return nil, recordSetOut{}, fmt.Errorf("%w. Nothing was changed: leave ptr out, or make the reverse zone first", err)
			}
			if replaced != nil {
				if was, ok := replaced.Address(); ok && was != addr {
					// an old address in no reverse zone here has no PTR to remove
					oldPTR, _ = r.planPTR(ctx, srv, was)
				}
			}
		}

		// the other records of the type at the name, which share its TTL
		var others []*technitium.Record
		for _, rec := range sameType {
			if rec != target && rec != replaced {
				others = append(others, rec)
			}
		}

		done := &changes{dry: in.DryRun}
		ttl := in.TTL
		switch {
		case target != nil || replaced != nil:
			current := target
			if current == nil {
				current = replaced
			}
			want := technitium.UpdateOf(current)
			want.Data = data
			if in.TTL > 0 {
				want.TTL = in.TTL
			}
			if in.Comment != nil {
				want.Comments = *in.Comment
			}
			if in.Disabled != nil {
				want.Disabled = *in.Disabled
			}
			ttl = want.TTL

			var what []string
			if !sameValue(current.Value(), value) {
				what = append(what, "its value from "+current.Value()+" to "+value)
			}
			if want.TTL != current.TTL {
				what = append(what, fmt.Sprintf("its TTL from %d to %d", current.TTL, want.TTL))
				if len(others) > 0 && !in.Only {
					what = append(what, fmt.Sprintf("and with it the TTL of the other %d %s records at the name, which share one", len(others), recordType))
				}
			}
			if want.Comments != current.Comments {
				what = append(what, fmt.Sprintf("its comment from %q to %q", current.Comments, want.Comments))
			}
			if want.Disabled != current.Disabled {
				what = append(what, map[bool]string{true: "it to disabled", false: "it to enabled"}[want.Disabled])
			}
			if len(what) > 0 && done.did("changed the %s record at %s: %s", recordType, name, strings.Join(what, ", ")) {
				if _, err := srv.Client.UpdateRecord(ctx, where.zone, current, want); err != nil {
					return nil, recordSetOut{}, err
				}
			}
			// the value was there already, beside the one it was to replace:
			// that one goes
			if target != nil && replaced != nil && replaced != target && done.did("removed %s, which %s replaces", recordAt(replaced), value) {
				if err := srv.Client.DeleteRecord(ctx, where.zone, replaced); err != nil {
					return nil, recordSetOut{}, fmt.Errorf("removing %s: %w", recordAt(replaced), err)
				}
			}
		case in.Only && len(sameType) > 0:
			if done.did("replaced the %d %s records at %s with %s", len(sameType), recordType, name, value) {
				if _, err := srv.Client.AddRecord(ctx, technitium.NewRecord{Zone: where.zone, Name: name, Type: recordType, TTL: in.TTL, Comments: deref(in.Comment), Data: data, Overwrite: true}); err != nil {
					return nil, recordSetOut{}, err
				}
			}
			sameType, others = nil, nil
		default:
			// beside records of its type it takes their TTL unless given one:
			// they share one, and the server's default would be set on them all
			if ttl == 0 && len(others) > 0 {
				ttl = others[0].TTL
			}
			added := fmt.Sprintf("added %s %s at %s", recordType, value, name)
			if len(others) > 0 && ttl != others[0].TTL {
				added += fmt.Sprintf(", and set the TTL of the other %d %s records there from %d to %d, which share one", len(others), recordType, others[0].TTL, ttl)
			}
			if done.did("%s", added) {
				if _, err := srv.Client.AddRecord(ctx, technitium.NewRecord{Zone: where.zone, Name: name, Type: recordType, TTL: ttl, Comments: deref(in.Comment), Data: data}); err != nil {
					return nil, recordSetOut{}, err
				}
			}
		}
		if !in.Only {
			if err := keepOthers(ctx, srv, where.zone, name, others, ttl, done); err != nil {
				return nil, recordSetOut{}, err
			}
		}

		// the single record of its type: the others go
		if in.Only {
			for _, rec := range sameType {
				if rec == target || rec == replaced {
					continue
				}
				if done.did("removed %s", recordAt(rec)) {
					if err := srv.Client.DeleteRecord(ctx, where.zone, rec); err != nil {
						return nil, recordSetOut{}, fmt.Errorf("the record was set, and removing %s failed: %w", recordAt(rec), err)
					}
				}
			}
		}
		// a record added disabled is added and then disabled: the API adds none so
		if in.Disabled != nil && *in.Disabled && target == nil && replaced == nil {
			added := &technitium.Record{Name: name, Type: recordType, TTL: ttl, Comments: deref(in.Comment), Data: data}
			if done.did("disabled it") {
				now, readErr := srv.Client.RecordsAt(ctx, name, where.zone)
				if readErr != nil {
					return nil, recordSetOut{}, fmt.Errorf("the record was added, and could not be read back to disable it: %w", readErr)
				}
				for i := range now.Records {
					if now.Records[i].Type == recordType && sameValue(now.Records[i].Value(), value) {
						added = &now.Records[i]
					}
				}
				want := technitium.UpdateOf(added)
				want.Disabled = true
				if _, err := srv.Client.UpdateRecord(ctx, where.zone, added, want); err != nil {
					return nil, recordSetOut{}, fmt.Errorf("the record was added, and disabling it failed: %w", err)
				}
			}
		}

		if in.PTR {
			if err := setPTR(ctx, srv, newPTR, name, ttl, done); err != nil {
				return nil, recordSetOut{}, fmt.Errorf("the record was set, and its PTR was not: %w", err)
			}
			if oldPTR.name != "" {
				if err := dropPTR(ctx, srv, oldPTR, name, done); err != nil {
					return nil, recordSetOut{}, fmt.Errorf("the record was set, and the old address's PTR was not removed: %w", err)
				}
			}
		}

		out.Changes, out.Changed = append([]string{}, done.said...), len(done.said) > 0
		if in.DryRun {
			out.Note = "a dry run: nothing was changed"

			return nil, out, nil
		}
		after, err := srv.Client.RecordsAt(ctx, name, where.zone)
		if err != nil {
			return nil, recordSetOut{}, fmt.Errorf("the change was made, and the records could not be read back: %w", err)
		}
		out.After = rowsAt(after.Records, recordType)
		if !slices.ContainsFunc(out.After, func(row recordRow) bool { return sameValue(row.Value, value) }) {
			return nil, recordSetOut{}, fmt.Errorf("the server took the change and does not hold %s %s at %s: it holds %v", recordType, value, name, out.After)
		}

		return nil, out, nil
	})

	type recordDeleteIn struct {
		writeServerArg

		Name   string `json:"name"              jsonschema:"the record's full domain name"`
		Type   string `json:"type"              jsonschema:"the record's type"`
		Value  string `json:"value,omitempty"   jsonschema:"the value of the record to delete, as zone_records gives it. It can be left out when the name has one record of the type; with several it says which, and all deletes them all"`
		All    bool   `json:"all,omitempty"     jsonschema:"delete every record of the type at the name"`
		Zone   string `json:"zone,omitempty"    jsonschema:"the zone the record is in; left out, the closest zone the server holds for the name"`
		PTR    bool   `json:"ptr,omitempty"     jsonschema:"for an A or an AAAA: make sure the PTR record for the address that names this name goes too. The server takes it away with the address by itself where it holds the reverse zone, and the answer says so; this removes one it left"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"delete nothing, and answer with what would be deleted"`
	}
	type recordDeleteOut struct {
		Server  string      `json:"server"`
		Zone    string      `json:"zone"`
		Deleted []recordRow `json:"deleted"        jsonschema:"the records deleted, as they were: what to give record_set to put one back. With a dry run, the ones that would be"`
		Changes []string    `json:"changes"        jsonschema:"each change made, in order; with a dry run, each that would be"`
		Left    []recordRow `json:"left"           jsonschema:"the records of this type still at the name, read back from the server; with a dry run, the ones there now"`
		Note    string      `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "record_delete",
		Description: "Delete a record from a zone on one server: the one at the name with the type and value given, or with all every record of the type there. The answer gives each record deleted as it was - its value, TTL and comment - which is what record_set needs to put it back, and the records of the type still at the name. The server removes an address's PTR with it, which the answer says when it happens. dry_run deletes nothing and says what would go. A zone the server holds as a copy is refused, saying where to make the change.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in recordDeleteIn) (*mcp.CallToolResult, recordDeleteOut, error) {
		name, recordType := cleanName(in.Name), strings.ToUpper(strings.TrimSpace(in.Type))
		if name == "" || recordType == "" {
			return nil, recordDeleteOut{}, errors.New("which record: it needs a name and a type")
		}
		if in.All && strings.TrimSpace(in.Value) != "" {
			return nil, recordDeleteOut{}, errors.New("give a value to delete one record, or all to delete every one of the type: not both")
		}
		where, err := r.placeFor(ctx, in.Server, in.Zone, name)
		if err != nil {
			return nil, recordDeleteOut{}, err
		}
		srv := where.srv
		at, err := srv.Client.RecordsAt(ctx, name, where.zone)
		if err != nil {
			return nil, recordDeleteOut{}, err
		}

		var sameType, going []*technitium.Record
		for i := range at.Records {
			if at.Records[i].Type == recordType {
				sameType = append(sameType, &at.Records[i])
			}
		}
		have := make([]string, 0, len(sameType))
		for _, rec := range sameType {
			have = append(have, rec.Value())
			if in.All || strings.TrimSpace(in.Value) == "" || sameValue(rec.Value(), in.Value) {
				going = append(going, rec)
			}
		}
		switch {
		case len(sameType) == 0:
			return nil, recordDeleteOut{}, fmt.Errorf("%s has no %s record in %s on %s: there is nothing to delete", name, recordType, where.zone, srv.Name)
		case len(going) == 0:
			return nil, recordDeleteOut{}, fmt.Errorf("%s has no %s record with the value %s (it has: %s). Nothing was deleted", name, recordType, in.Value, strings.Join(have, ", "))
		case len(going) > 1 && !in.All:
			return nil, recordDeleteOut{}, fmt.Errorf("%s has %d %s records (%s): say which with value, or all to delete every one. Nothing was deleted", name, len(going), recordType, strings.Join(have, ", "))
		default:
		}

		out := recordDeleteOut{Server: srv.Name, Zone: where.zone, Deleted: []recordRow{}}
		done := &changes{dry: in.DryRun}
		for _, rec := range going {
			if _, isAddr := rec.Address(); in.PTR && !isAddr {
				return nil, recordDeleteOut{}, fmt.Errorf("ptr is for an A or an AAAA record: a %s has no address. Nothing was deleted", recordType)
			}
		}
		for _, rec := range going {
			// the PTR naming this name at the address, when the server holds
			// the reverse zone for it: the server takes it away with the
			// address by itself, which is a change this answer owes
			var ptr ptrPlan
			if addr, isAddr := rec.Address(); isAddr {
				if plan, err := r.planPTR(ctx, srv, addr); err == nil && slices.ContainsFunc(plan.held, func(held technitium.Record) bool { return sameValue(held.Target(), name) }) {
					ptr = plan
				}
			}

			if done.did("deleted %s", recordAt(rec)) {
				if err := srv.Client.DeleteRecord(ctx, where.zone, rec); err != nil {
					return nil, recordDeleteOut{}, fmt.Errorf("deleting %s: %w (deleted before it: %d)", recordAt(rec), err, len(out.Deleted))
				}
			}
			out.Deleted = append(out.Deleted, rowOf(rec))
			if ptr.name == "" {
				continue
			}
			if in.DryRun {
				done.did("removed PTR %s at %s, which the server takes away with the address", name, ptr.name)

				continue
			}
			addr, _ := rec.Address()
			after, planErr := r.planPTR(ctx, srv, addr)
			if planErr != nil {
				return nil, recordDeleteOut{}, fmt.Errorf("the record was deleted, and whether its PTR went with it could not be read: %w", planErr)
			}
			if !slices.ContainsFunc(after.held, func(held technitium.Record) bool { return sameValue(held.Target(), name) }) {
				done.did("removed PTR %s at %s, which the server takes away with the address", name, ptr.name)

				continue
			}
			if !in.PTR {
				out.Note = note(out.Note, "the PTR at "+ptr.name+" still names "+name+": ptr removes it too")

				continue
			}
			if err := dropPTR(ctx, srv, after, name, done); err != nil {
				return nil, recordDeleteOut{}, fmt.Errorf("the record was deleted, and its PTR was not: %w", err)
			}
		}
		out.Changes = append([]string{}, done.said...)

		left, err := srv.Client.RecordsAt(ctx, name, where.zone)
		switch {
		case err == nil:
			out.Left = rowsAt(left.Records, recordType)
		case in.DryRun:
			return nil, recordDeleteOut{}, err
		default:
			// the last record at a name takes the name with it, and the
			// server then has nothing to read there
			out.Left = []recordRow{}
		}
		if in.DryRun {
			out.Note = note(out.Note, "a dry run: nothing was deleted")
		}

		return nil, out, nil
	})
}

// deref is a text that may not have been given, "" when it was not.
func deref(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
