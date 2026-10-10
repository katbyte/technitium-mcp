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

const (
	// cacheWalkMost is how many names under one cache_get reads before it
	// stops and says so
	cacheWalkMost = 2000
)

// cacheRow is one answer a server is keeping.
type cacheRow struct {
	Server   string `json:"server"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	TTL      int    `json:"ttl"                 jsonschema:"how many seconds more the server keeps the answer"`
	Value    string `json:"value"               jsonschema:"the answer kept, as a record's value; for a negative answer what it says: NxDomain, no such name, or NoData, no record of this type"`
	Negative bool   `json:"negative,omitempty"  jsonschema:"the server is keeping the answer that there is nothing: a client asking again is told so until the TTL runs out, whatever has been added since"`
	From     string `json:"from,omitempty"      jsonschema:"the name server the answer came from"`
	LastUsed string `json:"last_used,omitempty" jsonschema:"when the answer was last given to a client, in UTC"`
}

// cacheWalk is what one server's cache holds at a name and under it.
type cacheWalk struct {
	records []technitium.CachedRecord
	// under are the names beneath the one asked for that hold something,
	// when they were not read
	under []string
	// cut is the walk having stopped at cacheWalkMost names
	cut bool
}

// walkCache reads what a server's cache holds at a name, and with deep at
// every name under it.
func walkCache(ctx context.Context, srv *servers.Server, name string, deep bool) (cacheWalk, error) {
	var out cacheWalk
	queue, read := []string{name}, 0
	for len(queue) > 0 {
		at := queue[0]
		queue = queue[1:]
		read++
		if read > cacheWalkMost {
			out.cut = true

			break
		}
		held, err := srv.Client.Cache(ctx, at)
		if err != nil {
			return cacheWalk{}, err
		}
		// asked for a name it holds nothing at, the server answers for the
		// nearest name below that it does: that is a name under this one
		if below := cleanName(held.Domain); below != cleanName(at) {
			if below != "" && (at == "" || strings.HasSuffix(below, "."+cleanName(at))) {
				if deep {
					queue = append(queue, below)
				} else {
					out.under = append(out.under, below)
				}
			}

			continue
		}
		out.records = append(out.records, held.Records...)
		if deep {
			queue = append(queue, held.Zones...)
		} else if at == name {
			out.under = append(out.under, held.Zones...)
		}
	}
	slices.Sort(out.under)

	return out, nil
}

func registerCacheTools(r *registry) {
	type cacheGetIn struct {
		serverArg

		Name    string `json:"name"              jsonschema:"the domain name to look for in the cache"`
		Subtree bool   `json:"subtree,omitempty" jsonschema:"also every answer kept for the names under it"`
		Limit   int    `json:"limit,omitempty"   jsonschema:"the most answers to give (default 200)"`
	}
	type under struct {
		Server string   `json:"server"`
		Names  []string `json:"names"`
	}
	type cacheGetOut struct {
		Name   string          `json:"name"`
		Cached []cacheRow      `json:"cached"           jsonschema:"each answer a server is keeping for the name, server by server"`
		Total  int             `json:"total"            jsonschema:"how many answers are kept, before the limit"`
		NotOn  []string        `json:"not_on,omitempty" jsonschema:"the servers keeping nothing for the name: a query for it there is resolved afresh"`
		Under  []under         `json:"under,omitempty"  jsonschema:"the names under it each server keeps something for, when subtree was not asked for"`
		Failed []serverFailure `json:"failed,omitempty" jsonschema:"the servers that could not be asked, and why"`
		Note   string          `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "cache_get",
		Description: "Look a name up in each server's cache: the answers it is keeping from other name servers, how long each has left, where it came from, and whether it is a negative answer - the server remembering that a name did not exist, which it goes on telling clients after the record has been added until the TTL runs out. The cache holds what the server resolved elsewhere; names in its own zones are never in it. subtree gives every answer under the name as well.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in cacheGetIn) (*mcp.CallToolResult, cacheGetOut, error) {
		name := cleanName(in.Name)
		if name == "" {
			return nil, cacheGetOut{}, errors.New("which name: give the domain name to look for in the cache")
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, cacheGetOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (cacheWalk, error) {
			return walkCache(ctx, srv, name, in.Subtree)
		})
		failed, err := failures(answers)
		if err != nil {
			return nil, cacheGetOut{}, err
		}

		out := cacheGetOut{Name: name, Failed: failed, Cached: []cacheRow{}}
		for _, a := range answers {
			if a.Err != nil {
				continue
			}
			if len(a.Value.records) == 0 {
				out.NotOn = append(out.NotOn, a.Server.Name)
			}
			if len(a.Value.under) > 0 {
				out.Under = append(out.Under, under{Server: a.Server.Name, Names: a.Value.under})
			}
			if a.Value.cut {
				out.Note = note(out.Note, fmt.Sprintf("%s keeps answers for more than %d names under %s: the first %d were read, so ask for a name further down", a.Server.Name, cacheWalkMost, name, cacheWalkMost))
			}
			for i := range a.Value.records {
				rec := &a.Value.records[i]
				_, negative := rec.Negative()
				out.Cached = append(out.Cached, cacheRow{Server: a.Server.Name, Name: rec.Name, Type: rec.Type, TTL: rec.TTL(), Value: rec.Value(), Negative: negative, From: rec.Source.NameServer, LastUsed: utc(rec.LastUsedOn)})
			}
		}
		slices.SortStableFunc(out.Cached, func(a, b cacheRow) int {
			return strings.Compare(nameOrder(a.Name), nameOrder(b.Name))
		})
		out.Total = len(out.Cached)
		if limit := limitOr(in.Limit); len(out.Cached) > limit {
			out.Cached = out.Cached[:limit]
			out.Note = note(out.Note, fmt.Sprintf("%d answers are kept and the first %d are given: ask for a name further down, or raise limit", out.Total, limit))
		}

		return nil, out, nil
	})

	type cacheFlushIn struct {
		Server     string `json:"server,omitempty"     jsonschema:"the configured server whose cache to drop from: a name server_info lists, or all for every one. It can be left out only when one server is configured"`
		Name       string `json:"name,omitempty"       jsonschema:"the domain name whose kept answers to drop, with those of every name under it"`
		Everything bool   `json:"everything,omitempty" jsonschema:"drop the whole cache, every name: the server resolves everything afresh from then on. Instead of name"`
		DryRun     bool   `json:"dry_run,omitempty"    jsonschema:"drop nothing, and answer with what would be dropped"`
	}
	type flushed struct {
		Server  string `json:"server"`
		Dropped int    `json:"dropped"         jsonschema:"how many kept answers were dropped; with a dry run, how many would be. For the whole cache, the answers at its top names only: it is not all read first"`
		Error   string `json:"error,omitempty" jsonschema:"why nothing was dropped on this server"`
	}
	type cacheFlushOut struct {
		Name    string    `json:"name,omitempty"`
		Flushed []flushed `json:"flushed"        jsonschema:"what was dropped on each server"`
		Note    string    `json:"note,omitempty"`
	}
	add(r, writeTool, &mcp.Tool{
		Name:        "cache_flush",
		Description: "Drop what a server's cache is keeping for a name and every name under it, so the next query is resolved afresh: for a negative answer still being given after the record was added, or an old address after it changed. everything drops the whole cache instead. Nothing a server holds in its own zones is touched, and nothing is lost that the next query does not fetch again. server is one server or all; dry_run says what would be dropped.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in cacheFlushIn) (*mcp.CallToolResult, cacheFlushOut, error) {
		name := cleanName(in.Name)
		switch {
		case name == "" && !in.Everything:
			return nil, cacheFlushOut{}, errors.New("which name: give the domain name whose kept answers to drop, or everything to drop the whole cache")
		case name != "" && in.Everything:
			return nil, cacheFlushOut{}, errors.New("give a name to drop its answers, or everything to drop the whole cache: not both")
		default:
		}
		picked := r.servers.Every()
		if !strings.EqualFold(strings.TrimSpace(in.Server), servers.All) {
			one, err := r.servers.One(in.Server)
			if err != nil {
				return nil, cacheFlushOut{}, fmt.Errorf("%w, or all to drop from every one", err)
			}
			picked = []*servers.Server{one}
		}

		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (int, error) {
			held, err := walkCache(ctx, srv, name, name != "")
			if err != nil {
				return 0, err
			}
			if in.DryRun {
				return len(held.records), nil
			}
			if in.Everything {
				return len(held.records), srv.Client.FlushCache(ctx)
			}
			if err := srv.Client.DeleteCached(ctx, name); err != nil {
				return 0, err
			}
			// read back: nothing may be left at the name
			left, err := walkCache(ctx, srv, name, true)
			if err != nil {
				return 0, fmt.Errorf("the answers were dropped, and the cache could not be read back: %w", err)
			}
			if len(left.records) > 0 {
				return 0, fmt.Errorf("the server took the drop and still keeps %d answers at %s", len(left.records), name)
			}

			return len(held.records), nil
		})

		out := cacheFlushOut{Name: name}
		for _, a := range answers {
			row := flushed{Server: a.Server.Name, Dropped: a.Value}
			if a.Err != nil {
				row.Error = a.Err.Error()
			}
			out.Flushed = append(out.Flushed, row)
		}
		if in.DryRun {
			out.Note = "a dry run: nothing was dropped"
		}

		return nil, out, nil
	})
}
