package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// listBlocked and listAllowed are a server's own two lists, as the tools
	// name them
	listBlocked = "blocked"
	listAllowed = "allowed"

	// blockingOn, blockingOff and blockingPaused are how a server's blocking
	// stands
	blockingOn     = "on"
	blockingOff    = "off"
	blockingPaused = "paused"

	// byOwnList and byBlockList are what blocks a name: an entry on the
	// server's own list, or one on a list it fetches
	byOwnList   = "own_list"
	byBlockList = "block_list"

	// checkMost is how many names block_check takes at once
	checkMost = 50

	// settlePatience is how long a change to the lists made on a cluster's
	// secondary node is waited for: the node sends it to the primary, which
	// has it at once, and copies it back about ten seconds later
	settlePatience = 40 * time.Second
	settleEvery    = time.Second
)

// blockingHeld is one server's blocking: how it is set, its own two lists,
// and the zones it holds, which answer before any list is looked at.
type blockingHeld struct {
	settings         *technitium.Settings
	blocked, allowed []string
	zones            []technitium.Zone
}

// readBlocking reads a server's blocking whole: its lists, and the zones it
// holds.
func readBlocking(ctx context.Context, srv *servers.Server) (blockingHeld, error) {
	out, err := readLists(ctx, srv)
	if err != nil {
		return blockingHeld{}, err
	}
	if out.zones, err = srv.Client.Zones(ctx, technitium.ZoneFilter{}); err != nil {
		return blockingHeld{}, err
	}

	return out, nil
}

// readLists reads how a server's blocking is set and its own two lists,
// for a caller that has its zones already.
func readLists(ctx context.Context, srv *servers.Server) (blockingHeld, error) {
	var out blockingHeld
	var err error
	if out.settings, err = srv.Client.Settings(ctx); err != nil {
		return blockingHeld{}, err
	}
	if out.blocked, err = srv.Client.BlockedNames(ctx); err != nil {
		return blockingHeld{}, err
	}
	if out.allowed, err = srv.Client.AllowedNames(ctx); err != nil {
		return blockingHeld{}, err
	}
	for _, list := range [][]string{out.blocked, out.allowed} {
		for i := range list {
			list[i] = cleanName(list[i])
		}
		slices.SortFunc(list, func(a, b string) int { return cmp.Compare(nameOrder(a), nameOrder(b)) })
	}

	return out, nil
}

// listsAfter reads a server's lists after a change to them, until they show
// it. A server on its own shows a change at once. A cluster's secondary node
// shows it only once it has copied it back from the primary, so there the
// lists are read again for a while: shown reports whether they came to show
// it, and secondary that the server is such a node.
func listsAfter(ctx context.Context, srv *servers.Server, has func(h *blockingHeld) bool) (held blockingHeld, shown, secondary bool, err error) {
	if held, err = readBlocking(ctx, srv); err != nil || has(&held) {
		return held, err == nil, false, err
	}
	if !secondaryNode(ctx, srv) {
		return held, false, false, nil
	}

	deadline := time.Now().Add(settlePatience)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return held, false, true, ctx.Err()
		case <-time.After(settleEvery):
		}
		if held, err = readBlocking(ctx, srv); err != nil || has(&held) {
			return held, err == nil, true, err
		}
	}

	return held, false, true, nil
}

// secondaryNode reports whether a server is a secondary node of a cluster.
// One that will not say how it stands is taken to be on its own.
func secondaryNode(ctx context.Context, srv *servers.Server) bool {
	state, err := srv.Client.ClusterState(ctx)

	return err == nil && state.Self() != nil && state.Self().Type == technitium.NodeSecondary
}

// viaPrimary is what a change's answer says when it was made on a cluster's
// secondary node: where it went, and whether it has come back.
func viaPrimary(server string, back bool) string {
	if back {
		return server + " is a secondary node of a cluster: the change went to the cluster's primary, and " + server + " has copied it back"
	}

	return server + " is a secondary node of a cluster: the change went to the cluster's primary, which has it, and " + server + " has not copied it back yet. It does within the minute, and block_list shows when"
}

// state is how the server's blocking stands - on, off, or paused - and for
// paused when it comes back on.
func (h *blockingHeld) state() (state, until string) {
	if till, ok := technitium.ParseTime(h.settings.TemporaryDisableBlockingTill); ok && till.After(time.Now()) {
		return blockingPaused, utc(h.settings.TemporaryDisableBlockingTill)
	}
	if h.settings.EnableBlocking {
		return blockingOn, ""
	}

	return blockingOff, ""
}

// list is one of the server's own two lists by its name.
func (h *blockingHeld) list(name string) []string {
	if name == listAllowed {
		return h.allowed
	}

	return h.blocked
}

// covering is the entry of a list that a name is on or under: the closest
// one, "" when it is under none. An entry stands for every name under it.
func covering(entries []string, name string) string {
	var closest string
	for _, entry := range entries {
		if (name == entry || strings.HasSuffix(name, "."+entry)) && len(entry) > len(closest) {
			closest = entry
		}
	}

	return closest
}

// under are the entries of a list that are under a name.
func under(entries []string, name string) []string {
	var out []string
	for _, entry := range entries {
		if strings.HasSuffix(entry, "."+name) {
			out = append(out, entry)
		}
	}

	return out
}

// ownZone is the zone of the server's own that answers for a name: the
// closest it holds as a primary or a copy, "" when it holds none.
func (h *blockingHeld) ownZone(name string) string {
	var closest string
	for i := range h.zones {
		z := &h.zones[i]
		zone := cleanName(z.Name)
		if z.Disabled || (z.Type != technitium.ZonePrimary && !isCopy(z.Type)) || !served(z) {
			continue
		}
		if (name == zone || strings.HasSuffix(name, "."+zone)) && len(zone) > len(closest) {
			closest = zone
		}
	}

	return closest
}

// blockedBy is why a name server blocked a name, in the words an answer
// gives it in.
func blockedBy(b *technitium.Block) string {
	switch b.Source {
	case technitium.BlockedZone:
		return "by its own list of blocked names: the entry " + b.Entry
	case technitium.BlockList:
		return "by the block list " + b.List + ": the entry " + b.Entry
	default:
		return b.Text
	}
}

// blockVerdict is whether one server blocks one name, and why or why not.
type blockVerdict struct {
	Server  string `json:"server"`
	Name    string `json:"name"`
	Blocked bool   `json:"blocked"           jsonschema:"the server refuses the name: a client asking for it is told it does not exist, or given the address the server gives for a blocked name"`
	By      string `json:"by,omitempty"      jsonschema:"what blocks it: own_list, an entry on the server's own list of blocked names; block_list, an entry on a list the server fetches; or what an app said of it"`
	Entry   string `json:"entry,omitempty"   jsonschema:"the entry that blocks it: the name itself, or the name above it that stands for it"`
	List    string `json:"list,omitempty"    jsonschema:"the address of the block list the entry is on"`
	Allowed string `json:"allowed,omitempty" jsonschema:"the entry on the server's allowed list the name is on or under: such a name is never blocked, whatever list it is on"`
	Listed  string `json:"listed,omitempty"  jsonschema:"an entry on the server's own blocked list the name is on or under that does not block it, for the reason in why"`
	Why     string `json:"why,omitempty"     jsonschema:"why an entry that is there does not block the name"`
	Answer  string `json:"answer"            jsonschema:"what the server answers a client that asks for the name's address"`
	Error   string `json:"error,omitempty"   jsonschema:"why the server could not be asked for the name"`
}

// verdictOf weighs a server's answer for a name against its lists.
func (h *blockingHeld) verdictOf(server, name string, res *technitium.Resolution) blockVerdict {
	v := blockVerdict{Server: server, Name: name, Answer: res.RCode, Allowed: covering(h.allowed, name)}
	for i := range res.Answer {
		v.Answer += " " + res.Answer[i].Value()
	}
	if b := res.Blocked(); b != nil {
		v.Blocked, v.Entry, v.List = true, b.Entry, b.List
		switch b.Source {
		case technitium.BlockedZone:
			v.By = byOwnList
		case technitium.BlockList:
			v.By = byBlockList
		default:
			v.By = b.Text
		}

		return v
	}

	if v.Listed = covering(h.blocked, name); v.Listed == "" {
		return v
	}
	state, until := h.state()
	zone := h.ownZone(name)
	switch {
	case state == blockingOff:
		v.Why = "blocking is switched off on " + server
	case state == blockingPaused:
		v.Why = "blocking is paused on " + server + " until " + until
	case v.Allowed != "":
		v.Why = "the allowed entry " + v.Allowed + " wins over it"
	case zone != "":
		v.Why = server + " answers the name from its own zone " + zone + ", and no list is looked at for a name a zone here holds"
	case res.Authoritative:
		v.Why = server + " answers for this name itself before any list is looked at, as it does for every name under .test, .invalid and home.arpa"
	default:
		v.Why = "the server did not block it and nothing here says why: its lists may have been changed a moment ago"
	}

	return v
}

// blockingRow is how one server's blocking stands, as block_list answers.
type blockingRow struct {
	Server      string   `json:"server"`
	Error       string   `json:"error,omitempty"        jsonschema:"why this server's blocking could not be read; the rest of its row is then empty"`
	Blocking    string   `json:"blocking,omitempty"     jsonschema:"on, off, or paused: switched off for a while, until paused_until"`
	PausedUntil string   `json:"paused_until,omitempty" jsonschema:"when paused blocking comes back on, in UTC"`
	Answers     string   `json:"answers,omitempty"      jsonschema:"how a blocked name is answered: NxDomain, no such name; AnyAddress, the address 0.0.0.0; or CustomAddress, with the addresses given"`
	Lists       []string `json:"lists,omitempty"        jsonschema:"the lists the server fetches, by address; one written with a ! before it is a list of names to allow"`
	ListsEvery  string   `json:"lists_every,omitempty"  jsonschema:"how often the lists are fetched"`
	ListsNext   string   `json:"lists_next,omitempty"   jsonschema:"when they are next fetched, in UTC; absent for lists not fetched yet, which the note says"`
	ListNames   *int     `json:"list_names,omitempty"   jsonschema:"how many names the fetched lists block between them; 0 with lists set is lists that did not load"`
	Blocked     int      `json:"blocked"                jsonschema:"how many names are on the server's own list of blocked names"`
	Allowed     int      `json:"allowed"                jsonschema:"how many are on its list of allowed names"`
	Bypass      []string `json:"bypass,omitempty"       jsonschema:"the clients nothing is blocked for, as addresses and networks"`
	Note        string   `json:"note,omitempty"`
}

// blockingRowOf is a server's blocking as block_list gives it. How many
// names its lists hold is the dashboard's to say, which a token may not read.
func blockingRowOf(ctx context.Context, srv *servers.Server, h *blockingHeld) blockingRow {
	s := h.settings
	row := blockingRow{Server: srv.Name, Answers: s.BlockingType, Lists: s.BlockListURLs, Blocked: len(h.blocked), Allowed: len(h.allowed), Bypass: s.BlockingBypassList}
	row.Blocking, row.PausedUntil = h.state()
	if s.BlockingType == "CustomAddress" {
		row.Answers += " " + strings.Join(s.CustomBlockingAddresses, ", ")
	}
	if len(s.BlockListURLs) == 0 {
		return row
	}

	// a list not fetched yet is due at the server's "never" and its interval, which is no time
	if row.ListsEvery, row.ListsNext = fmt.Sprintf("%dh", s.BlockListUpdateIntervalHours), utc(s.BlockListNextUpdatedOn); row.ListsNext == "" {
		row.Note = "the lists have not been fetched since they were set, or since a fetch was last asked for: they are due now"
	}
	stats, err := srv.Client.Stats(ctx, technitium.StatsWindow{})
	if err != nil {
		row.Note = note(row.Note, "how many names the lists hold could not be read: "+err.Error())

		return row
	}
	row.ListNames = &stats.Totals.BlockListZones

	return row
}

// blockEntry is one name on a server's own blocked or allowed list.
type blockEntry struct {
	Name   string   `json:"name"`
	List   string   `json:"list"              jsonschema:"blocked or allowed"`
	OnlyOn []string `json:"only_on,omitempty" jsonschema:"the servers with this entry, when not every server read has it"`
}

// blockServerArg is the argument a change to a server's lists takes to say
// which server it is made on.
type blockServerArg struct {
	Server string `json:"server,omitempty" jsonschema:"the configured server whose list to change: a name server_info lists. It can be left out only when one server is configured. Servers on their own each keep their own lists, so a name is blocked on each; a cluster's nodes share them"`
}

// entryName reads the name an entry is for.
func entryName(text string) (string, error) {
	name := cleanName(text)
	switch {
	case name == "":
		return "", errors.New("which name: give the domain name the entry is for")
	case strings.HasPrefix(name, "*."):
		return "", fmt.Errorf("an entry stands for its name and every name under it, so it takes no wildcard: give %s", strings.TrimPrefix(name, "*."))
	case strings.ContainsAny(name, " \t/:@"):
		return "", fmt.Errorf("%q is no domain name: give the name alone, as ads.example.com, with no address around it", text)
	default:
		return name, nil
	}
}

// listName reads which of the two lists a change is to.
func listName(text string) (string, error) {
	switch list := strings.ToLower(strings.TrimSpace(text)); list {
	case "", listBlocked:
		return listBlocked, nil
	case listAllowed:
		return listAllowed, nil
	default:
		return "", fmt.Errorf("list %q: it takes blocked (the default) or allowed", text)
	}
}

func registerBlockingTools(r *registry) {
	type blockCheckIn struct {
		serverArg

		Names []string `json:"names" jsonschema:"the domain names to check, up to 50"`
	}
	type blockCheckOut struct {
		Checks []blockVerdict  `json:"checks"           jsonschema:"each name on each server, name by name"`
		Failed []serverFailure `json:"failed,omitempty" jsonschema:"the servers that could not be asked, and why"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "block_check",
		Description: "Say whether each server blocks a name, and what makes it so: the server is asked for the name as a client would ask, and its answer says when it was blocked and by which entry - one on the server's own list of blocked names, or one on a block list it fetches, named by its address. A name on or under an entry of the allowed list is never blocked, and that entry is given. An entry that is there and does not block the name is given with why: blocking off or paused, an allowed entry over it, or the name being one a zone on the server answers for, which no list is looked at for. Why does this name not resolve, and why is that one not blocked.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blockCheckIn) (*mcp.CallToolResult, blockCheckOut, error) {
		var names []string
		for _, text := range in.Names {
			if name := cleanName(text); name != "" && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
		switch {
		case len(names) == 0:
			return nil, blockCheckOut{}, errors.New("which names: give the domain names to check")
		case len(names) > checkMost:
			return nil, blockCheckOut{}, fmt.Errorf("%d names: block_check takes %d at a time", len(names), checkMost)
		default:
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, blockCheckOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) ([]blockVerdict, error) {
			held, readErr := readBlocking(ctx, srv)
			if readErr != nil {
				return nil, readErr
			}
			verdicts := make([]blockVerdict, 0, len(names))
			for _, name := range names {
				res, askErr := srv.Client.Resolve(ctx, technitium.ResolveQuery{Name: name})
				if askErr != nil {
					verdicts = append(verdicts, blockVerdict{Server: srv.Name, Name: name, Error: askErr.Error()})

					continue
				}
				verdicts = append(verdicts, held.verdictOf(srv.Name, name, res))
			}

			return verdicts, nil
		})
		failed, err := failures(answers)
		if err != nil {
			return nil, blockCheckOut{}, err
		}

		out := blockCheckOut{Checks: []blockVerdict{}, Failed: failed}
		for i := range names {
			for _, a := range answers {
				if a.Err == nil {
					out.Checks = append(out.Checks, a.Value[i])
				}
			}
		}

		return nil, out, nil
	})

	type blockListIn struct {
		serverArg

		Find   string `json:"find,omitempty"   jsonschema:"only the entries whose name matches: with a * or a ? the whole name must match, without either the text may be anywhere in it"`
		List   string `json:"list,omitempty"   jsonschema:"only the entries of the blocked list, or of the allowed"`
		Limit  int    `json:"limit,omitempty"  jsonschema:"the most entries to give (default 200)"`
		Offset int    `json:"offset,omitempty" jsonschema:"how many entries to pass over first, to read on from a limit"`
	}
	type blockListOut struct {
		Servers []blockingRow `json:"servers"          jsonschema:"how each server's blocking stands, in the order configured"`
		Entries []blockEntry  `json:"entries"          jsonschema:"the names on the servers' own blocked and allowed lists, as one table: an entry every server has is one row, and one only some have names them"`
		Total   int           `json:"total"            jsonschema:"how many entries matched, before the limit"`
		Differ  []string      `json:"differ,omitempty" jsonschema:"what the servers do not have alike: blocking (on, off or paused), answers, lists (the lists fetched), blocked and allowed (their own entries). Where they differ, one server blocks a name the other resolves"`
		Note    string        `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "block_list",
		Description: "How each server's blocking stands, side by side, and the names on its own two lists: whether blocking is on, off or paused, how a blocked name is answered, the block lists it fetches with when they are next fetched and how many names they hold, and every entry of its own blocked and allowed lists - each standing for its name and every name under it, an allowed one never blocked whatever list it is on. Names what the servers do not have alike. The names of a fetched list are not given, being hundreds of thousands: block_check says whether one blocks a name.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blockListIn) (*mcp.CallToolResult, blockListOut, error) {
		only := strings.ToLower(strings.TrimSpace(in.List))
		if only != "" && only != listBlocked && only != listAllowed {
			return nil, blockListOut{}, fmt.Errorf("list %q: it takes blocked or allowed", in.List)
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, blockListOut{}, err
		}
		type read struct {
			held blockingHeld
			row  blockingRow
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (read, error) {
			held, readErr := readBlocking(ctx, srv)
			if readErr != nil {
				return read{}, readErr
			}

			return read{held: held, row: blockingRowOf(ctx, srv, &held)}, nil
		})
		if _, err := failures(answers); err != nil {
			return nil, blockListOut{}, err
		}

		out := blockListOut{Servers: make([]blockingRow, 0, len(answers)), Entries: []blockEntry{}}
		var asked []string
		on := map[string][]string{}
		var order []string
		for _, a := range answers {
			if a.Err != nil {
				out.Servers = append(out.Servers, blockingRow{Server: a.Server.Name, Error: a.Err.Error()})

				continue
			}
			out.Servers = append(out.Servers, a.Value.row)
			asked = append(asked, a.Server.Name)
			for _, list := range []string{listBlocked, listAllowed} {
				for _, name := range a.Value.held.list(list) {
					key := list + "\x00" + name
					if on[key] == nil {
						order = append(order, key)
					}
					on[key] = append(on[key], a.Server.Name)
				}
			}
		}
		slices.SortStableFunc(order, func(a, b string) int {
			listA, nameA, _ := strings.Cut(a, "\x00")
			listB, nameB, _ := strings.Cut(b, "\x00")

			return cmp.Or(cmp.Compare(nameOrder(nameA), nameOrder(nameB)), -cmp.Compare(listA, listB))
		})

		find := newPattern(in.Find)
		differs := map[string]bool{}
		for _, key := range order {
			list, name, _ := strings.Cut(key, "\x00")
			entry := blockEntry{Name: name, List: list}
			if len(on[key]) != len(asked) {
				entry.OnlyOn = on[key]
				differs[list] = true
			}
			if find.matches(name) && (only == "" || only == list) {
				out.Entries = append(out.Entries, entry)
			}
		}
		out.Total = len(out.Entries)
		out.Entries = out.Entries[min(max(in.Offset, 0), len(out.Entries)):]
		if limit := limitOr(in.Limit); len(out.Entries) > limit {
			out.Entries = out.Entries[:limit]
			out.Note = fmt.Sprintf("%d entries matched and %d are given, starting at the %s: read on with offset %d, or narrow it with find or list", out.Total, limit, ordinal(max(in.Offset, 0)+1), max(in.Offset, 0)+limit)
		}

		var first *blockingRow
		for i := range out.Servers {
			row := &out.Servers[i]
			switch {
			case row.Error != "":
			case first == nil:
				first = row
			default:
				differs["blocking"] = differs["blocking"] || row.Blocking != first.Blocking
				differs["answers"] = differs["answers"] || row.Answers != first.Answers
				differs["lists"] = differs["lists"] || !slices.Equal(row.Lists, first.Lists)
			}
		}
		for _, what := range []string{"blocking", "answers", "lists", listBlocked, listAllowed} {
			if differs[what] {
				out.Differ = append(out.Differ, what)
			}
		}

		return nil, out, nil
	})

	type blockSetIn struct {
		blockServerArg

		Name   string `json:"name"              jsonschema:"the domain name to block or to allow: it stands for itself and every name under it"`
		List   string `json:"list,omitempty"    jsonschema:"blocked (the default) to have the server refuse the name, or allowed to have it never refuse the name whatever list it is on"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be done"`
	}
	type blockSetOut struct {
		Server  string        `json:"server"`
		List    string        `json:"list"`
		Name    string        `json:"name"`
		Changed bool          `json:"changed"         jsonschema:"something was changed; with a dry run, something would be"`
		Changes []string      `json:"changes"         jsonschema:"each change made; with a dry run, each that would be. Empty when the list already covers the name"`
		Now     *blockVerdict `json:"now,omitempty"   jsonschema:"whether the server blocks the name now, asked of it after the change: absent from a dry run"`
		Under   []string      `json:"under,omitempty" jsonschema:"entries already on the list under this name, which this one now stands for as well"`
		Note    string        `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "block_set",
		Description: "Put a name on one server's own list of blocked names, or on its allowed list: the entry stands for the name and every name under it. Blocked, the server refuses the name to its clients; allowed, it never refuses it, whatever block list or blocked entry it is on - the way to let one name through a list that blocks it. A name the list already covers, itself or by an entry above it, is left alone. The answer asks the server for the name afterwards and says whether it is blocked now, and when a blocked entry does nothing why: a zone on the server answers for the name, an allowed entry wins, or blocking is off. dry_run changes nothing.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blockSetIn) (*mcp.CallToolResult, blockSetOut, error) {
		name, err := entryName(in.Name)
		if err != nil {
			return nil, blockSetOut{}, err
		}
		list, err := listName(in.List)
		if err != nil {
			return nil, blockSetOut{}, err
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, blockSetOut{}, err
		}
		held, err := readBlocking(ctx, srv)
		if err != nil {
			return nil, blockSetOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}

		out := blockSetOut{Server: srv.Name, List: list, Name: name, Changes: []string{}}
		done := &changes{dry: in.DryRun}
		switch above := covering(held.list(list), name); above {
		case "":
			out.Changed, out.Under = true, under(held.list(list), name)
			if done.did("added %s to the %s list of %s", name, list, srv.Name) {
				add := srv.Client.BlockName
				if list == listAllowed {
					add = srv.Client.AllowName
				}
				if err := add(ctx, name); err != nil {
					return nil, blockSetOut{}, fmt.Errorf("adding %s to the %s list: %w. Nothing was changed", name, list, err)
				}
			}
		case name:
		default:
			out.Note = note(out.Note, fmt.Sprintf("%s is on the %s list already by the entry above it, %s, which stands for every name under it: nothing was added", name, list, above))
		}
		out.Changes = done.said
		if !strings.Contains(name, ".") {
			out.Note = note(out.Note, "the entry stands for every name that ends in ."+name)
		}
		if in.DryRun {
			return nil, out, nil
		}

		held, shown, secondary, err := listsAfter(ctx, srv, func(h *blockingHeld) bool { return covering(h.list(list), name) != "" })
		switch {
		case err != nil:
			return nil, blockSetOut{}, fmt.Errorf("the change was made, and the lists could not be read back: %w", err)
		case !shown && !secondary:
			return nil, blockSetOut{}, fmt.Errorf("the server took the change and %s is not on the %s list of %s", name, list, srv.Name)
		case secondary:
			out.Note = note(out.Note, viaPrimary(srv.Name, shown))
		default:
		}
		if !shown {
			return nil, out, nil
		}
		res, err := srv.Client.Resolve(ctx, technitium.ResolveQuery{Name: name})
		if err != nil {
			return nil, blockSetOut{}, fmt.Errorf("the change was made, and the server could not be asked for the name afterwards: %w", err)
		}
		now := held.verdictOf(srv.Name, name, res)
		out.Now = &now

		return nil, out, nil
	})

	type blockDeleteIn struct {
		blockServerArg

		Name   string `json:"name"              jsonschema:"the entry to remove: the name exactly as block_list gives it"`
		List   string `json:"list,omitempty"    jsonschema:"the list it is on: blocked (the default) or allowed"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"remove nothing, and answer with what would be removed"`
	}
	type blockDeleteOut struct {
		Server  string        `json:"server"`
		List    string        `json:"list"`
		Name    string        `json:"name"`
		Changes []string      `json:"changes"        jsonschema:"each change made; with a dry run, each that would be"`
		Now     *blockVerdict `json:"now,omitempty"  jsonschema:"whether the server blocks the name now, asked of it after the change: a name taken off the blocked list can be blocked still, by a block list; absent from a dry run"`
		Note    string        `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "block_delete",
		Description: "Take an entry off one server's own list of blocked names, or off its allowed list. The entry is named exactly: a name blocked by an entry above it is unblocked by removing that entry, which the refusal names, and with it every other name under it. The answer asks the server for the name afterwards and says whether it is blocked now, and by what - a block list can block it still, which only an allowed entry gets it past. dry_run removes nothing.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blockDeleteIn) (*mcp.CallToolResult, blockDeleteOut, error) {
		name, err := entryName(in.Name)
		if err != nil {
			return nil, blockDeleteOut{}, err
		}
		list, err := listName(in.List)
		if err != nil {
			return nil, blockDeleteOut{}, err
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, blockDeleteOut{}, err
		}
		held, err := readBlocking(ctx, srv)
		if err != nil {
			return nil, blockDeleteOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		if !slices.Contains(held.list(list), name) {
			why := fmt.Sprintf("%s is not an entry of the %s list of %s", name, list, srv.Name)
			if above := covering(held.list(list), name); above != "" {
				why += fmt.Sprintf(": it is on the list by the entry above it, %s, and removing that one takes every name under %s off with it", above, above)
			}
			if below := under(held.list(list), name); len(below) > 0 {
				why += ": the entries under it are " + strings.Join(below, ", ")
			}

			return nil, blockDeleteOut{}, errors.New(why + ". Nothing was removed")
		}

		out := blockDeleteOut{Server: srv.Name, List: list, Name: name}
		done := &changes{dry: in.DryRun}
		if done.did("removed %s from the %s list of %s", name, list, srv.Name) {
			remove := srv.Client.UnblockName
			if list == listAllowed {
				remove = srv.Client.UnallowName
			}
			if err := remove(ctx, name); err != nil {
				return nil, blockDeleteOut{}, fmt.Errorf("removing %s from the %s list: %w. Nothing was removed", name, list, err)
			}
		}
		out.Changes = done.said
		if in.DryRun {
			return nil, out, nil
		}

		held, shown, secondary, err := listsAfter(ctx, srv, func(h *blockingHeld) bool { return !slices.Contains(h.list(list), name) })
		switch {
		case err != nil:
			return nil, blockDeleteOut{}, fmt.Errorf("the entry was removed, and the lists could not be read back: %w", err)
		case !shown && !secondary:
			return nil, blockDeleteOut{}, fmt.Errorf("the server took the removal and %s is still on the %s list of %s", name, list, srv.Name)
		case secondary:
			out.Note = note(out.Note, viaPrimary(srv.Name, shown))
		default:
		}
		if !shown {
			return nil, out, nil
		}
		res, err := srv.Client.Resolve(ctx, technitium.ResolveQuery{Name: name})
		if err != nil {
			return nil, blockDeleteOut{}, fmt.Errorf("the entry was removed, and the server could not be asked for the name afterwards: %w", err)
		}
		now := held.verdictOf(srv.Name, name, res)
		out.Now = &now

		return nil, out, nil
	})
}
