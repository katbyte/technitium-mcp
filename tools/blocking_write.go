package tools

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// pauseMost is the longest a pause of blocking may be asked for: a day.
const pauseMost = 24 * 60

// blockListOf reads the address of a list for a server to fetch: an http or
// https address, with a ! before it for a list of names to allow.
func blockListOf(text string) (string, error) {
	text = strings.TrimSpace(text)
	address := strings.TrimPrefix(text, "!")
	if u, err := url.Parse(address); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(address, ", ") {
		return "", fmt.Errorf("%q is no list's address: give where the list is fetched from, as https://example.com/list.txt, with a ! before it for a list of names to allow", text)
	}

	return text, nil
}

func registerBlockingWriteTools(r *registry) {
	type blockSwitchIn struct {
		blockServerArg

		To      string `json:"to"                jsonschema:"on, off, or paused: off for a while, coming back on by itself after minutes"`
		Minutes int    `json:"minutes,omitempty" jsonschema:"for paused: how many minutes blocking stays off, up to a day"`
		DryRun  bool   `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be done"`
	}
	type blockState struct {
		Blocking    string `json:"blocking"               jsonschema:"on, off or paused"`
		PausedUntil string `json:"paused_until,omitempty" jsonschema:"when paused blocking comes back on, in UTC"`
	}
	type blockSwitchOut struct {
		Server  string      `json:"server"`
		Changed bool        `json:"changed"         jsonschema:"something was changed; with a dry run, something would be"`
		Changes []string    `json:"changes"         jsonschema:"each change made; with a dry run, each that would be"`
		Before  blockState  `json:"before"`
		After   *blockState `json:"after,omitempty" jsonschema:"how blocking stands now, read back; absent from a dry run"`
		Note    string      `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "block_switch",
		Description: "Switch a server's blocking on or off, or pause it: off for some minutes, after which it comes back on by itself. A pause is the way to find out whether blocking is what breaks something - pause it, try again, and it mends itself whatever happens next. While blocking is off or paused nothing is blocked: not the server's own entries, and not the lists it fetches. Switching it on ends a pause. A cluster's nodes all take the change. block_list says how blocking stands.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blockSwitchIn) (*mcp.CallToolResult, blockSwitchOut, error) {
		to := strings.ToLower(strings.TrimSpace(in.To))
		switch {
		case to == "pause":
			to = blockingPaused
		case to != blockingOn && to != blockingOff && to != blockingPaused:
			return nil, blockSwitchOut{}, fmt.Errorf("to %q: it takes on, off or paused", in.To)
		default:
		}
		switch {
		case to == blockingPaused && (in.Minutes <= 0 || in.Minutes > pauseMost):
			return nil, blockSwitchOut{}, fmt.Errorf("a pause is for 1 to %d minutes: give how long in minutes. To leave blocking off until it is switched on, switch it off", pauseMost)
		case to != blockingPaused && in.Minutes != 0:
			return nil, blockSwitchOut{}, errors.New("minutes is how long a pause lasts: blocking switched on or off stays so")
		default:
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, blockSwitchOut{}, err
		}
		held, err := readLists(ctx, srv)
		if err != nil {
			return nil, blockSwitchOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		out := blockSwitchOut{Server: srv.Name, Changes: []string{}}
		out.Before.Blocking, out.Before.PausedUntil = held.state()
		if to == out.Before.Blocking && to != blockingPaused {
			out.After = new(out.Before)

			return nil, out, nil
		}

		done := &changes{dry: in.DryRun}
		out.Changed = true
		switch to {
		case blockingPaused:
			if done.did("paused blocking on %s for %d minutes: nothing is blocked till then", srv.Name, in.Minutes) {
				if _, err := srv.Client.PauseBlocking(ctx, in.Minutes); err != nil {
					return nil, blockSwitchOut{}, fmt.Errorf("pausing blocking: %w. Nothing was changed", err)
				}
			}
		default:
			// switched off in a pause, the server leaves the pause running, and blocking comes back on when it ends: the pause is ended first
			if to == blockingOff && out.Before.Blocking == blockingPaused && done.did("ended the pause on %s, which would have switched blocking back on at %s", srv.Name, out.Before.PausedUntil) {
				if _, err := srv.Client.SetBlocking(ctx, true); err != nil {
					return nil, blockSwitchOut{}, fmt.Errorf("ending the pause: %w. Nothing was changed", err)
				}
			}
			if done.did("switched blocking %s on %s", to, srv.Name) {
				if _, err := srv.Client.SetBlocking(ctx, to == blockingOn); err != nil {
					return nil, blockSwitchOut{}, fmt.Errorf("switching blocking %s: %w", to, err)
				}
			}
		}
		if out.Changes = done.said; in.DryRun {
			return nil, out, nil
		}

		// switched off after a pause was ended, the server goes on giving the time the pause would have ended, though nothing is left to switch blocking back on: off is blocking not being on
		now, shown, secondary, err := listsAfter(ctx, srv, func(h *blockingHeld) bool {
			state, _ := h.state()

			return state == to || (to == blockingOff && !h.settings.EnableBlocking)
		})
		switch {
		case err != nil:
			return nil, blockSwitchOut{}, fmt.Errorf("the change was made, and how blocking stands could not be read back: %w", err)
		case !shown && !secondary:
			state, _ := now.state()

			return nil, blockSwitchOut{}, fmt.Errorf("the server took the change and blocking on %s is %s, not %s", srv.Name, state, to)
		case secondary:
			out.Note = note(out.Note, viaPrimary(srv.Name, shown))
		default:
		}
		after := blockState{}
		if after.Blocking, after.PausedUntil = now.state(); to == blockingOff && after.Blocking == blockingPaused {
			out.Note = note(out.Note, "the server goes on showing "+after.PausedUntil+", when the pause would have ended, until that time has passed: the pause is over, and nothing switches blocking back on then")
			after = blockState{Blocking: blockingOff}
		}
		out.After = &after

		return nil, out, nil
	})

	type blockListsSetIn struct {
		blockServerArg

		Lists  *[]string `json:"lists,omitempty"   jsonschema:"the lists the server is to fetch, by address: the whole set, an empty one clearing it. A ! before an address makes it a list of names to allow"`
		Add    []string  `json:"add,omitempty"     jsonschema:"lists to add to the ones it fetches"`
		Remove []string  `json:"remove,omitempty"  jsonschema:"lists to take off, by address exactly as block_list gives it"`
		Fetch  bool      `json:"fetch,omitempty"   jsonschema:"have the server fetch its lists now, whether or not the set was changed, rather than when they are next due"`
		DryRun bool      `json:"dry_run,omitempty" jsonschema:"change nothing, and answer with what would be done"`
	}
	type blockListsSetOut struct {
		Server  string       `json:"server"`
		Changed bool         `json:"changed"         jsonschema:"something was changed or asked for; with a dry run, something would be"`
		Changes []string     `json:"changes"         jsonschema:"each change made; with a dry run, each that would be"`
		Before  []string     `json:"before"          jsonschema:"the lists it fetched before"`
		After   *blockingRow `json:"after,omitempty" jsonschema:"how the server's blocking stands now, read back, with its lists and how many names they hold: a list just added holds none until it is fetched, which takes a moment. Absent from a dry run"`
		Note    string       `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "block_lists_set",
		Description: "Set the block lists one server fetches: the whole set with lists, or one added or taken off with add and remove; and with fetch have it fetch them now. A list is the address of a file of names to block, or with a ! before it of names to allow. A new list blocks nothing until the server has fetched it, which fetch asks for and which takes it a moment: the answer says how many names the lists hold when it was read, and block_list says again later. A cluster's nodes all take the change. The server's own list of blocked names is block_set's to change.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in blockListsSetIn) (*mcp.CallToolResult, blockListsSetOut, error) {
		if in.Lists != nil && (len(in.Add) > 0 || len(in.Remove) > 0) {
			return nil, blockListsSetOut{}, errors.New("give the whole set with lists, or what to add and remove: not both")
		}
		if in.Lists == nil && len(in.Add) == 0 && len(in.Remove) == 0 && !in.Fetch {
			return nil, blockListsSetOut{}, errors.New("what to do: give lists, add or remove to change the lists fetched, or fetch to have them fetched now")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, blockListsSetOut{}, err
		}
		held, err := readLists(ctx, srv)
		if err != nil {
			return nil, blockListsSetOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		have := slices.Clone(held.settings.BlockListURLs)
		out := blockListsSetOut{Server: srv.Name, Changes: []string{}, Before: append([]string{}, have...)}

		want := slices.Clone(have)
		if in.Lists != nil {
			want = []string{}
		}
		for _, text := range append(given(in.Lists), in.Add...) {
			list, listErr := blockListOf(text)
			if listErr != nil {
				return nil, blockListsSetOut{}, listErr
			}
			if !slices.Contains(want, list) {
				want = append(want, list)
			}
		}
		for _, text := range in.Remove {
			text = strings.TrimSpace(text)
			if !slices.Contains(want, text) {
				return nil, blockListsSetOut{}, fmt.Errorf("%s fetches no list at %s: it fetches %s. Nothing was changed", srv.Name, text, orNone(have))
			}
			want = slices.DeleteFunc(want, func(list string) bool { return list == text })
		}

		done := &changes{dry: in.DryRun}
		for _, list := range want {
			if !slices.Contains(have, list) {
				done.did("added the list %s to those %s fetches", list, srv.Name)
			}
		}
		for _, list := range have {
			if !slices.Contains(want, list) {
				done.did("removed the list %s from those %s fetches", list, srv.Name)
			}
		}
		if len(done.said) > 0 && !in.DryRun {
			if _, err := srv.Client.SetBlockLists(ctx, want); err != nil {
				return nil, blockListsSetOut{}, fmt.Errorf("setting the lists: %w. Nothing was changed", err)
			}
		}
		if in.Fetch && len(want) == 0 {
			out.Note = note(out.Note, "there are no lists to fetch")
		}
		if in.Fetch && len(want) > 0 && done.did("asked %s to fetch its lists now", srv.Name) {
			if err := srv.Client.UpdateBlockLists(ctx); err != nil {
				return nil, blockListsSetOut{}, fmt.Errorf("asking for the lists to be fetched: %w. The set of lists was changed as asked", err)
			}
		}
		if state, _ := held.state(); state != blockingOn && len(want) > 0 {
			out.Note = note(out.Note, "blocking is "+state+" on "+srv.Name+": nothing these lists hold is blocked until it is on")
		}
		if out.Changes, out.Changed = done.said, len(done.said) > 0; in.DryRun {
			return nil, out, nil
		}

		now, shown, secondary, err := listsAfter(ctx, srv, func(h *blockingHeld) bool { return slices.Equal(h.settings.BlockListURLs, want) })
		switch {
		case err != nil:
			return nil, blockListsSetOut{}, fmt.Errorf("the change was made, and the lists could not be read back: %w", err)
		case !shown && !secondary:
			return nil, blockListsSetOut{}, fmt.Errorf("the server took the change and %s fetches %s, not %s", srv.Name, orNone(now.settings.BlockListURLs), orNone(want))
		case secondary:
			out.Note = note(out.Note, viaPrimary(srv.Name, shown))
		default:
		}
		row := blockingRowOf(ctx, srv, &now)
		out.After = &row

		return nil, out, nil
	})
}
