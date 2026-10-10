package tools

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

const (
	// listsLate is how long past the time they were due a server's block
	// lists may be before they are said not to be fetched
	listsLate = time.Hour
	// entriesMost is how many entries a finding about many names by name
	entriesMost = 5
)

// selfAnswered are the domains a server answers for itself, as ones that do
// not exist, before any list is looked at: an entry under one does nothing.
var selfAnswered = []string{"test", "invalid", "home.arpa"}

// blockingRead is one server's blocking as the audit reads it: its lists,
// and how many names the lists it fetches hold, when its dashboard says.
type blockingRead struct {
	held blockingHeld
	// listNames is how many names the fetched lists hold, -1 when the
	// dashboard would not say
	listNames int
}

// readBlocking reads the blocking of every server asked, for the audit of
// it. A server whose blocking will not be read is said beside the findings:
// nothing of it was audited.
func (a *audited) readBlocking(ctx context.Context, picked []*servers.Server) {
	a.blocking = map[string]*blockingRead{}
	for _, answer := range ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (blockingRead, error) {
		held, err := readLists(ctx, srv)
		if err != nil {
			return blockingRead{}, err
		}
		// its zones are read already
		for _, zone := range a.inv.zones {
			for i := range zone.copies {
				if zone.copies[i].server == srv.Name {
					held.zones = append(held.zones, zone.copies[i].zone)
				}
			}
		}
		out := blockingRead{held: held, listNames: -1}
		if stats, err := srv.Client.Stats(ctx, technitium.StatsWindow{}); err == nil {
			out.listNames = stats.Totals.BlockListZones
		}

		return out, nil
	}) {
		switch {
		case !slices.Contains(a.inv.asked, answer.Server.Name):
		case answer.Err != nil:
			a.blockingFailed = append(a.blockingFailed, serverFailure{Server: answer.Server.Name, Error: answer.Err.Error()})
		default:
			a.blocking[answer.Server.Name] = &answer.Value
		}
	}
}

// some is the first few of a list of names in words, with how many more.
func some(names []string) string {
	if len(names) <= entriesMost {
		return strings.Join(names, ", ")
	}

	return fmt.Sprintf("%s and %d more", strings.Join(names[:entriesMost], ", "), len(names)-entriesMost)
}

// auditBlocking finds what is wrong with what the servers block: blocking
// that is off, lists that are not fetched, entries that do nothing, and
// servers that do not block the same.
func auditBlocking(a *audited) []finding {
	// each server's own, said once with the servers it is so on: a cluster's nodes share their lists, and what is wrong with one's is wrong with them all
	found := a.perServer(func(v *view) []finding {
		b := a.blocking[v.server]
		if b == nil {
			return nil
		}
		var found []finding
		h, s := &b.held, b.held.settings
		var fetched []string
		for _, list := range s.BlockListURLs {
			if !strings.HasPrefix(list, "!") {
				fetched = append(fetched, list)
			}
		}

		switch state, until := h.state(); state {
		case blockingPaused:
			found = append(found, finding{Problem: "blocking_paused", Detail: fmt.Sprintf("blocking is paused until %s: nothing is blocked till then", until), Fix: "it comes back on by itself; switching blocking on in the server's settings ends the pause now"})
		case blockingOff:
			if len(fetched) > 0 || len(h.blocked) > 0 {
				found = append(found, finding{Problem: "blocking_off", Detail: fmt.Sprintf("blocking is switched off, with %d lists to fetch and %d names on the blocked list: none of it is blocked", len(fetched), len(h.blocked)), Fix: "switch blocking on in the server's settings, or clear the lists if nothing is meant to be blocked"})
			}
		default:
			// lists not fetched since they were set are due at the server's "never" and their interval, which is no time
			switch due, ok := technitium.ParseTime(s.BlockListNextUpdatedOn); {
			case len(s.BlockListURLs) == 0:
			case !ok:
				found = append(found, finding{Problem: "lists_not_fetched", Detail: "the block lists have not been fetched since they were set, or since a fetch was last asked for: until they are, they block nothing new", Fix: "a fetch takes a moment, so look again; lists that stay so cannot be reached, and the server's log says why"})
			case time.Since(due) > listsLate:
				found = append(found, finding{Problem: "lists_not_fetched", Detail: fmt.Sprintf("the block lists were due to be fetched at %s and have not been: what they block is as old as the last time they were", utc(s.BlockListNextUpdatedOn)), Fix: "see that the server can reach the lists' addresses, and its log for why the fetch fails"})
			default:
			}
			if len(fetched) > 0 && b.listNames == 0 {
				found = append(found, finding{Problem: "lists_empty", Detail: fmt.Sprintf("the %d block lists fetched hold no names between them: none has loaded, so nothing of theirs is blocked. The lists: %s", len(fetched), some(fetched)), Fix: "see that the addresses are right and that the server can reach them; its log says why a fetch failed"})
			}
		}

		for _, entry := range h.blocked {
			above := covering(slices.DeleteFunc(slices.Clone(h.blocked), func(o string) bool { return o == entry }), entry)
			zone := h.ownZone(entry)
			switch {
			case zone != "":
				found = append(found, finding{Problem: "entry_never_applies", Zone: zone, Name: entry, Detail: fmt.Sprintf("%s is on the blocked list, and the zone %s, held here, answers for the name before any list is looked at: the entry blocks nothing", entry, zone), Fix: "take the entry off the list; to stop the name resolving, remove or disable its records in " + zone})
			case covering(selfAnswered, entry) != "":
				found = append(found, finding{Problem: "entry_never_applies", Name: entry, Detail: fmt.Sprintf("%s is on the blocked list, and the server answers for every name under .%s itself, as one that does not exist, before any list is looked at: the entry blocks nothing", entry, covering(selfAnswered, entry)), Fix: "take the entry off the list"})
			case covering(h.allowed, entry) != "":
				found = append(found, finding{Problem: "entry_overridden", Name: entry, Detail: fmt.Sprintf("%s is on the blocked list and %s on the allowed list, which wins: the name is not blocked", entry, covering(h.allowed, entry)), Fix: "take it off whichever list it is not meant to be on"})
			case above != "":
				found = append(found, finding{Problem: "entry_redundant", Name: entry, Detail: fmt.Sprintf("%s is on the blocked list with %s above it, which stands for every name under it", entry, above), Fix: "take the lower entry off the list, unless the upper one is to go"})
			default:
			}
		}
		for _, entry := range h.allowed {
			if above := covering(slices.DeleteFunc(slices.Clone(h.allowed), func(o string) bool { return o == entry }), entry); above != "" {
				found = append(found, finding{Problem: "entry_redundant", Name: entry, Detail: fmt.Sprintf("%s is on the allowed list with %s above it, which stands for every name under it", entry, above), Fix: "take the lower entry off the list, unless the upper one is to go"})
			}
		}

		return found
	})

	var read []string
	for _, v := range a.views {
		if a.blocking[v.server] != nil {
			read = append(read, v.server)
		}
	}
	if len(read) < 2 {
		return found
	}

	// the servers against each other: a name one blocks and another resolves depends on which a client asks
	first := &a.blocking[read[0]].held
	firstState, _ := first.state()
	for _, server := range read[1:] {
		h := &a.blocking[server].held
		if state, _ := h.state(); state != firstState {
			found = append(found, finding{Problem: "blocking_differs", Servers: []string{read[0], server}, Detail: fmt.Sprintf("%s has blocking %s and %s has it %s: a name one refuses the other resolves", read[0], firstState, server, state), Fix: "set the two alike; a cluster's nodes take this from its primary"})
		}
		if !slices.Equal(h.settings.BlockListURLs, first.settings.BlockListURLs) {
			found = append(found, finding{Problem: "blocking_differs", Servers: []string{read[0], server}, Detail: fmt.Sprintf("%s fetches %d block lists and %s %d, and they are not the same lists: %s against %s", read[0], len(first.settings.BlockListURLs), server, len(h.settings.BlockListURLs), cmpOrNone(some(first.settings.BlockListURLs)), cmpOrNone(some(h.settings.BlockListURLs))), Fix: "give the two the same lists; a cluster's nodes take them from its primary"})
		}
		for _, list := range []string{listBlocked, listAllowed} {
			var only []string
			for _, entry := range first.list(list) {
				if !slices.Contains(h.list(list), entry) {
					only = append(only, entry+" ("+read[0]+" alone)")
				}
			}
			for _, entry := range h.list(list) {
				if !slices.Contains(first.list(list), entry) {
					only = append(only, entry+" ("+server+" alone)")
				}
			}
			if len(only) > 0 {
				found = append(found, finding{Problem: "blocking_differs", Servers: []string{read[0], server}, Detail: fmt.Sprintf("%d names are on the %s list of one of %s and %s and not the other: %s", len(only), list, read[0], server, some(only)), Fix: "put each on both or take it off both; servers on their own each keep their own lists"})
			}
		}
	}

	return found
}

// cmpOrNone is a list in words, or "none" for an empty one.
func cmpOrNone(text string) string {
	if text == "" {
		return "none"
	}

	return text
}
