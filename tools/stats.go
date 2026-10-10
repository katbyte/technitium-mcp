package tools

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// topDefault is how many of each top list server_stats gives, which is
	// how many the server sends with its totals, and topMost the most it
	// will fetch
	topDefault = 10
	topMost    = 1000
)

// statWindows are the windows a server keeps its statistics by, as
// server_stats names them.
var statWindows = map[string]string{
	"hour":  technitium.StatsLastHour,
	"day":   technitium.StatsLastDay,
	"week":  technitium.StatsLastWeek,
	"month": technitium.StatsLastMonth,
	"year":  technitium.StatsLastYear,
}

// statClient is a client by how much it asked.
type statClient struct {
	Address     string `json:"address"`
	Name        string `json:"name,omitempty"         jsonschema:"the name the address's PTR gives it"`
	Queries     int    `json:"queries"`
	RateLimited bool   `json:"rate_limited,omitempty" jsonschema:"the server is holding the client back for asking too much"`
}

// statName is a name by how often it was asked for.
type statName struct {
	Name    string `json:"name"`
	Queries int    `json:"queries"`
}

// statsRow is what one server did over the window, as server_stats answers.
type statsRow struct {
	Server string `json:"server"`
	Error  string `json:"error,omitempty" jsonschema:"why this server's statistics could not be read; the rest of its row is then empty"`

	Queries int `json:"queries"`
	Clients int `json:"clients" jsonschema:"how many different clients asked"`

	NoError       int `json:"no_error"       jsonschema:"queries by how each was answered: answered, with records or with none of the type asked for"`
	NxDomain      int `json:"nx_domain"      jsonschema:"answered that the name does not exist, a blocked name among them when that is how the server answers one"`
	ServerFailure int `json:"server_failure" jsonschema:"not answered: the server could not resolve the name, its forwarders or the name's own servers having failed it"`
	Refused       int `json:"refused"        jsonschema:"turned away: a client the server does not resolve for"`

	Authoritative int `json:"authoritative" jsonschema:"queries by where each answer came from: the server's own zones"`
	Recursive     int `json:"recursive"     jsonschema:"resolved for the client, through forwarders or from the root"`
	Cached        int `json:"cached"        jsonschema:"answered from what the server was keeping"`
	Blocked       int `json:"blocked"       jsonschema:"refused by a list"`
	Dropped       int `json:"dropped"       jsonschema:"not answered at all: rate limited or malformed"`

	NxDomainPercent      *float64 `json:"nx_domain_percent,omitempty"      jsonschema:"the part of the queries answered that the name does not exist"`
	ServerFailurePercent *float64 `json:"server_failure_percent,omitempty" jsonschema:"the part the server failed to answer"`
	BlockedPercent       *float64 `json:"blocked_percent,omitempty"        jsonschema:"the part a list refused"`

	TopClients []statClient   `json:"top_clients,omitempty" jsonschema:"the clients that asked most"`
	TopDomains []statName     `json:"top_domains,omitempty" jsonschema:"the names asked for most, of those that were answered"`
	TopBlocked []statName     `json:"top_blocked,omitempty" jsonschema:"the blocked names asked for most"`
	Types      map[string]int `json:"types,omitempty"       jsonschema:"queries by the record type asked for, the ten most asked"`
	Protocols  map[string]int `json:"protocols,omitempty"   jsonschema:"queries by how they came: Udp, Tcp, Tls, Https, Quic"`

	Zones         int `json:"zones"          jsonschema:"what the server holds now, whatever the window: its zones"`
	CachedEntries int `json:"cached_entries" jsonschema:"and the answers in its cache"`
}

// percent is a part of a whole as a percentage to one decimal place.
func percent(part, whole int) *float64 {
	if whole == 0 {
		return nil
	}
	p := math.Round(1000*float64(part)/float64(whole)) / 10

	return &p
}

// statsRowOf reads one server's statistics for a window, with top lists to
// the length asked for.
func statsRowOf(ctx context.Context, srv *servers.Server, window technitium.StatsWindow, top int) (statsRow, error) {
	row := statsRow{Server: srv.Name}
	stats, err := srv.Client.Stats(ctx, window)
	if err != nil {
		return row, err
	}
	// the server sends ten of each list with its totals: more are asked for by list, as are the clients when they are wanted another way
	var lists []string
	if window.OnlyRateLimited || window.NoReverseLookup {
		lists = []string{technitium.TopClients}
	}
	if top > topDefault {
		lists = []string{technitium.TopClients, technitium.TopDomains, technitium.TopBlockedDomains}
	}
	for _, list := range lists {
		more, err := srv.Client.TopStats(ctx, window, list, top)
		if err != nil {
			return row, err
		}
		switch list {
		case technitium.TopClients:
			stats.TopClients = more.TopClients
		case technitium.TopDomains:
			stats.TopDomains = more.TopDomains
		default:
			stats.TopBlockedDomains = more.TopBlockedDomains
		}
	}

	n := stats.Totals
	row.Queries, row.Clients, row.NoError, row.NxDomain, row.ServerFailure, row.Refused = n.Queries, n.Clients, n.NoError, n.NxDomain, n.ServerFailure, n.Refused
	row.Authoritative, row.Recursive, row.Cached, row.Blocked, row.Dropped, row.Zones, row.CachedEntries = n.Authoritative, n.Recursive, n.Cached, n.Blocked, n.Dropped, n.Zones, n.CachedEntries
	row.NxDomainPercent, row.ServerFailurePercent, row.BlockedPercent = percent(n.NxDomain, n.Queries), percent(n.ServerFailure, n.Queries), percent(n.Blocked, n.Queries)
	for i, c := range stats.TopClients {
		if i < top {
			row.TopClients = append(row.TopClients, statClient{Address: c.Name, Name: c.Domain, Queries: c.Hits, RateLimited: c.RateLimited})
		}
	}
	for i, d := range stats.TopDomains {
		if i < top {
			row.TopDomains = append(row.TopDomains, statName{Name: d.Name, Queries: d.Hits})
		}
	}
	for i, d := range stats.TopBlockedDomains {
		if i < top {
			row.TopBlocked = append(row.TopBlocked, statName{Name: d.Name, Queries: d.Hits})
		}
	}
	if types := stats.QueryTypes(); len(types) > 0 {
		row.Types = types
	}
	if protocols := stats.Protocols(); len(protocols) > 0 {
		row.Protocols = protocols
	}

	return row, nil
}

// when reads a time a window is given by: a whole time in UTC or with its
// zone, or a date, which is that day's start in UTC.
func when(text string) (time.Time, error) {
	text = strings.TrimSpace(text)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", time.DateOnly} {
		if t, err := time.Parse(layout, text); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("%q is no time: give it as 2026-10-09T14:00:00Z, or a date as 2026-10-09", text)
}

func registerStatsTools(r *registry) {
	type serverStatsIn struct {
		serverArg

		Window        string `json:"window,omitempty"          jsonschema:"the window the server keeps to count over: hour (the default), day, week, month or year"`
		From          string `json:"from,omitempty"            jsonschema:"or a window of one's own, with to: its start in UTC as 2026-10-09T00:00:00Z, or a date. The server counts such a window in whole days"`
		To            string `json:"to,omitempty"              jsonschema:"the end of a window of one's own"`
		Top           int    `json:"top,omitempty"             jsonschema:"how many of the clients and names that lead each list to give (default 10, at most 1000)"`
		EveryType     bool   `json:"every_type,omitempty"      jsonschema:"count every record type asked for by itself, where the server otherwise gives the leading ones and the rest as one"`
		RateLimited   bool   `json:"rate_limited,omitempty"    jsonschema:"list only the clients the server is holding back for asking too much, in place of the clients that lead"`
		ByAddressOnly bool   `json:"by_address_only,omitempty" jsonschema:"list clients by address alone, without the server looking up a name for each, which on a slow reverse zone is what takes the time"`
	}
	type serverStatsOut struct {
		Window  string     `json:"window"         jsonschema:"the window counted over"`
		Servers []statsRow `json:"servers"        jsonschema:"what each server did over the window, in the order configured"`
		Note    string     `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "server_stats",
		Description: "What each server did over a window, side by side: how many queries from how many clients, how they were answered (answered, no such name, failed, refused) and where the answers came from (its own zones, resolved, cache, blocked), with the part that failed, did not exist or was blocked as a percentage, and the clients that asked most, the names asked for most and the blocked names asked for most. For what the servers are doing, which machines lean on them, and whether failures or names that do not exist are a large part of it. The counts are the server's own running totals: for who asked for one name and when, the server's log of queries is the place.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverStatsIn) (*mcp.CallToolResult, serverStatsOut, error) {
		var window technitium.StatsWindow
		out := serverStatsOut{Window: strings.ToLower(strings.TrimSpace(in.Window))}
		switch {
		case strings.TrimSpace(in.From) != "" || strings.TrimSpace(in.To) != "":
			if out.Window != "" {
				return nil, serverStatsOut{}, errors.New("give a window the server keeps, or from and to for one of your own: not both")
			}
			var err error
			if window.Start, err = when(in.From); err != nil {
				return nil, serverStatsOut{}, fmt.Errorf("from: %w", err)
			}
			if window.End, err = when(in.To); err != nil {
				return nil, serverStatsOut{}, fmt.Errorf("to: %w", err)
			}
			if !window.End.After(window.Start) {
				return nil, serverStatsOut{}, fmt.Errorf("the window ends at %s, which is not after it starts at %s", window.End.Format(time.RFC3339), window.Start.Format(time.RFC3339))
			}
			out.Window = window.Start.Format(time.RFC3339) + " to " + window.End.Format(time.RFC3339)
			out.Note = "a window of one's own is counted in whole days"
		case out.Window == "":
			out.Window, window.Type = "hour", technitium.StatsLastHour
		default:
			if window.Type = statWindows[out.Window]; window.Type == "" {
				return nil, serverStatsOut{}, fmt.Errorf("window %q: it takes hour, day, week, month or year, or leave it out and give from and to", in.Window)
			}
		}
		switch out.Window {
		case "hour":
			out.Note = "the server counts by the minute, and the minute in progress is not in yet"
		case "day", "week", "month", "year":
			out.Note = "the server counts this window by the hour or the day, and the hour in progress is not in it: for the last minutes ask for the hour"
		default:
		}
		top := in.Top
		switch {
		case top <= 0:
			top = topDefault
		case top > topMost:
			return nil, serverStatsOut{}, fmt.Errorf("top %d: the most of each list is %d", top, topMost)
		default:
		}
		window.EveryQueryType, window.OnlyRateLimited, window.NoReverseLookup = in.EveryType, in.RateLimited, in.ByAddressOnly
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, serverStatsOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (statsRow, error) {
			return statsRowOf(ctx, srv, window, top)
		})
		if _, err := failures(answers); err != nil {
			return nil, serverStatsOut{}, err
		}

		out.Servers = make([]statsRow, 0, len(answers))
		for _, a := range answers {
			row := a.Value
			if a.Err != nil {
				row = statsRow{Server: a.Server.Name, Error: a.Err.Error()}
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})
}
