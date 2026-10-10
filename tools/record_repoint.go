package tools

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// repointed is one record moved from one address to another.
type repointed struct {
	Zone    string `json:"zone"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
	Comment string `json:"comment,omitempty"`
}

// skippedRecord is a record holding the old address that was not moved.
type skippedRecord struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
	Why  string `json:"why"`
}

func registerRepointTool(r *registry) {
	type repointIn struct {
		writeServerArg

		From   string `json:"from"              jsonschema:"the address to move records off"`
		To     string `json:"to"                jsonschema:"the address to move them to, of the same kind: IPv4 for IPv4"`
		Zone   string `json:"zone,omitempty"    jsonschema:"move only the records in the zones whose name matches: with a * or a ? the whole name must match, without either the text may be anywhere in it; left out is every zone"`
		Share  bool   `json:"share,omitempty"   jsonschema:"go ahead although the address moved to is already held by another name's record. Without it that is refused: two hosts on one address is usually a mistake, and two names for one host is not, so say which this is"`
		NoPTR  bool   `json:"no_ptr,omitempty"  jsonschema:"leave the PTR records alone. Without it the PTRs at the old address are moved to the new one's name, where the server holds the reverse zones"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with every change that would be made"`
	}
	type repointOut struct {
		Server    string          `json:"server"`
		From      string          `json:"from"`
		To        string          `json:"to"`
		Repointed []repointed     `json:"repointed"            jsonschema:"each record moved to the new address, with the TTL and comment it kept; with a dry run, each that would be"`
		Changes   []string        `json:"changes"              jsonschema:"each change made, in order, the PTRs included; with a dry run, each that would be"`
		Skipped   []skippedRecord `json:"skipped,omitempty"    jsonschema:"records holding the old address that were not moved, and why: in a zone this server holds only a copy of, which is changed on its primary"`
		AlreadyAt []string        `json:"already_at,omitempty" jsonschema:"the names that held the new address before, which now share it with what was moved"`
		Problems  []zoneProblem   `json:"problems,omitempty"   jsonschema:"zones the server lists and would not give the records of: what holds the old address there was not moved"`
		Note      string          `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "record_repoint",
		Description: "Move every A or AAAA record holding one address to another, on one server, across all its zones: for a host that changes address. Each record keeps its name, TTL, comment and state, and the PTR records at the old address move to the new one's name. Names that reach the address through a CNAME need no change and are not touched. It is refused when the new address is already held by another name, unless share says that is meant. dry_run lists every change and makes none: run it first. Records in a zone the server holds only a copy of are listed as skipped, to be moved on the zone's primary.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in repointIn) (*mcp.CallToolResult, repointOut, error) {
		from, okFrom := parseAddr(in.From)
		to, okTo := parseAddr(in.To)
		switch {
		case !okFrom || !okTo:
			return nil, repointOut{}, errors.New("from and to are each an IPv4 or IPv6 address: the one to move records off, and the one to move them to")
		case from.Unmap() == to.Unmap():
			return nil, repointOut{}, fmt.Errorf("from and to are both %s: there is nothing to move", from)
		case from.Unmap().Is4() != to.Unmap().Is4():
			return nil, repointOut{}, fmt.Errorf("%s and %s are not the same kind of address: an A record holds IPv4 and an AAAA IPv6, and a record cannot change type", from, to)
		default:
		}
		from, to = from.Unmap(), to.Unmap()
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, repointOut{}, err
		}

		zones := newPattern(in.Zone)
		inv, err := readInventory(ctx, []*servers.Server{srv}, func(z *technitium.Zone) bool { return served(z) && zones.matches(z.Name) })
		if err != nil {
			return nil, repointOut{}, err
		}
		out := repointOut{Server: srv.Name, From: from.String(), To: to.String(), Repointed: []repointed{}, Problems: inv.problems}

		type holding struct {
			zone string
			rec  *technitium.Record
		}
		var moving []holding
		for _, zone := range inv.zones {
			held := &zone.copies[0]
			for i := range held.records {
				rec := &held.records[i]
				addr, ok := rec.Address()
				switch {
				case !ok:
				case addr.Unmap() == to && !slices.Contains(out.AlreadyAt, cleanName(rec.Name)):
					out.AlreadyAt = append(out.AlreadyAt, cleanName(rec.Name))
				case addr.Unmap() != from:
				case held.copied:
					out.Skipped = append(out.Skipped, skippedRecord{Zone: zone.name, Name: rec.Name, Why: srv.Name + " holds " + zone.name + " as a copy, which takes no changes: move it on the zone's primary, and this copy follows"})
				default:
					moving = append(moving, holding{zone: zone.name, rec: rec})
				}
			}
		}
		slices.Sort(out.AlreadyAt)

		// a name that holds both addresses is no other host
		var others []string
		for _, name := range out.AlreadyAt {
			if !slices.ContainsFunc(moving, func(h holding) bool { return cleanName(h.rec.Name) == name }) {
				others = append(others, name)
			}
		}
		if len(others) > 0 && len(moving) > 0 && !in.Share {
			return nil, repointOut{}, fmt.Errorf("%s is already held by %s: moving %d records onto it would put them on one address with it. If that is meant, say so with share. Nothing was changed", to, strings.Join(others, ", "), len(moving))
		}

		// where the PTRs are and go is found before anything is changed
		var oldPTR, newPTR ptrPlan
		movePTR := false
		if !in.NoPTR && len(moving) > 0 {
			if plan, err := r.planPTR(ctx, srv, from); err == nil && len(plan.held) > 0 {
				oldPTR, movePTR = plan, true
				if newPTR, err = r.planPTR(ctx, srv, to); err != nil {
					out.Note = note(out.Note, "the PTR records at "+oldPTR.name+" were left where they are: "+err.Error())
					movePTR = false
				}
			}
		}

		done := &changes{dry: in.DryRun}
		for _, h := range moving {
			want := technitium.UpdateOf(h.rec)
			want.Data["ipAddress"] = to.String()
			// a name that already holds the new address keeps that record, and
			// the old one goes: one name cannot hold an address twice
			if slices.Contains(out.AlreadyAt, cleanName(h.rec.Name)) {
				if done.did("removed %s, which already holds %s", recordAt(h.rec), to) {
					if err := srv.Client.DeleteRecord(ctx, h.zone, h.rec); err != nil {
						return nil, repointOut{}, fmt.Errorf("removing %s: %w (%d changes were made before it: %s)", recordAt(h.rec), err, len(done.said)-1, strings.Join(done.said[:len(done.said)-1], "; "))
					}
				}

				continue
			}
			if done.did("moved %s %s from %s to %s", h.rec.Type, h.rec.Name, from, to) {
				if _, err := srv.Client.UpdateRecord(ctx, h.zone, h.rec, want); err != nil {
					return nil, repointOut{}, fmt.Errorf("moving %s: %w (%d changes were made before it: %s)", recordAt(h.rec), err, len(done.said)-1, strings.Join(done.said[:len(done.said)-1], "; "))
				}
			}
			out.Repointed = append(out.Repointed, repointed{Zone: h.zone, Name: h.rec.Name, Type: h.rec.Type, TTL: h.rec.TTL, Comment: h.rec.Comments})
		}

		// the PTRs at the old address, each to the new one's name. The server
		// takes a PTR away itself with an address that was deleted above, so
		// what is still there is read again before any is removed
		if movePTR {
			still := oldPTR.held
			if !in.DryRun {
				now, err := r.planPTR(ctx, srv, from)
				if err != nil {
					return nil, repointOut{}, fmt.Errorf("the records were moved, and the PTRs at %s could not be read again: %w", oldPTR.name, err)
				}
				still = now.held
			}
			for i := range oldPTR.held {
				old := &oldPTR.held[i]
				if !slices.ContainsFunc(newPTR.held, func(rec technitium.Record) bool { return sameValue(rec.Target(), old.Target()) }) && done.did("added PTR %s at %s", old.Target(), newPTR.name) {
					if _, err := srv.Client.AddRecord(ctx, technitium.NewRecord{Zone: newPTR.zone, Name: newPTR.name, Type: "PTR", TTL: old.TTL, Comments: old.Comments, Data: technitium.RData{"ptrName": old.Target()}}); err != nil {
						return nil, repointOut{}, fmt.Errorf("the records were moved, and adding the PTR at %s failed: %w", newPTR.name, err)
					}
				}
				there := slices.ContainsFunc(still, func(rec technitium.Record) bool { return sameValue(rec.Target(), old.Target()) })
				if done.did("removed PTR %s at %s", old.Target(), oldPTR.name) && there {
					if err := srv.Client.DeleteRecord(ctx, oldPTR.zone, old); err != nil {
						return nil, repointOut{}, fmt.Errorf("the records were moved, and removing the PTR at %s failed: %w", oldPTR.name, err)
					}
				}
			}
		}

		out.Changes = append([]string{}, done.said...)
		switch {
		case len(moving) == 0 && len(out.Skipped) == 0:
			out.Note = note(out.Note, "no record on "+srv.Name+" holds "+from.String()+": there was nothing to move")
		case in.DryRun:
			out.Note = note(out.Note, "a dry run: nothing was changed")
		default:
		}
		if len(others) == 0 {
			out.AlreadyAt = nil
		} else {
			out.AlreadyAt = others
		}

		return nil, out, nil
	})
}
