package tools

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// logDefault is how many queries log_search gives when no limit is
	// asked for, and logMost the furthest into the matches it reads to give
	// a page of them
	logDefault = 100
	logMost    = 10000
	// logCountMost is how many matching queries of one server are read to
	// be counted
	logCountMost = 50000
)

// The values a log is searched by, each as the server writes it, by how it
// may be typed.
var (
	logResults   = canonical("NoError", "FormatError", "ServerFailure", "NxDomain", "NotImplemented", "Refused")
	logSources   = canonical("Authoritative", "Recursive", "Cached", "Blocked", "UpstreamBlocked", "CacheBlocked")
	logProtocols = canonical("Udp", "Tcp", "Tls", "Https", "Quic")
	// logCounts are what the queries can be counted by, each with the part of an entry it is
	logCounts = map[string]func(e *technitium.LogEntry) string{
		"client": func(e *technitium.LogEntry) string { return e.Client },
		"name":   func(e *technitium.LogEntry) string { return cleanName(e.Name) },
		"type":   func(e *technitium.LogEntry) string { return e.Type },
		"result": func(e *technitium.LogEntry) string { return e.RCode },
		"source": func(e *technitium.LogEntry) string { return e.ResponseType },
	}
)

// canonical are values by their lower case, so one typed in any case is
// found and sent as the server writes it.
func canonical(values ...string) map[string]string {
	out := map[string]string{}
	for _, value := range values {
		out[strings.ToLower(value)] = value
	}

	return out
}

// oneOf reads a value typed in any case as one of a set, "" for none given.
func oneOf(what, text string, set map[string]string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", nil
	}
	if value, ok := set[strings.ToLower(text)]; ok {
		return value, nil
	}
	values := make([]string, 0, len(set))
	for _, value := range set {
		values = append(values, value)
	}
	slices.Sort(values)

	return "", fmt.Errorf("%s %q: it takes %s", what, text, strings.Join(values, ", "))
}

// lengthOf reads a length of time as 90m, 24h or 7d.
func lengthOf(text string) (time.Duration, error) {
	text = strings.ToLower(strings.TrimSpace(text))
	if days, isDays := strings.CutSuffix(text, "d"); isDays {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	if d, err := time.ParseDuration(text); err == nil && d > 0 {
		return d, nil
	}

	return 0, fmt.Errorf("%q is no length of time: give it as 30m, 6h or 7d", text)
}

// logRow is one query a server answered, as log_search gives it.
type logRow struct {
	Server   string   `json:"server"`
	Time     string   `json:"time"              jsonschema:"when it was asked, in UTC"`
	Client   string   `json:"client"            jsonschema:"the address that asked"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Result   string   `json:"result"            jsonschema:"how it was answered: NoError, NxDomain (no such name), ServerFailure, Refused"`
	Source   string   `json:"source"            jsonschema:"where the answer came from: Authoritative, the server's own zones; Recursive, resolved for the client; Cached; Blocked, refused by a list"`
	Protocol string   `json:"protocol"`
	Answer   string   `json:"answer,omitempty"  jsonschema:"what was answered, each record as its type and value, a chain in order; absent for an answer with no records"`
	TookMS   *float64 `json:"took_ms,omitempty" jsonschema:"how long resolving it took, in milliseconds, for an answer that was resolved"`
}

// logCount is how many of the queries share one value of what they were
// counted by.
type logCount struct {
	Value   string         `json:"value"`
	Queries int            `json:"queries"`
	On      map[string]int `json:"on,omitempty" jsonschema:"how many of them each server answered, when more than one server was read"`
}

// logInfo is one server's log, as log_search says of it: what keeps it, and
// how much it holds.
type logInfo struct {
	Server  string `json:"server"`
	Error   string `json:"error,omitempty" jsonschema:"why this server's log could not be searched: it has no app that keeps one, or would not be read"`
	App     string `json:"app,omitempty"   jsonschema:"the app that keeps the log"`
	Keeps   string `json:"keeps,omitempty" jsonschema:"how far back the log goes: the days and the number of queries the app keeps. A query older than that is in no answer here"`
	Matched int    `json:"matched"         jsonschema:"how many queries in this server's log matched"`
	Note    string `json:"note,omitempty"`
}

// logOf finds the app that keeps a server's searchable log, and what the
// app's configuration says of how much it keeps.
func logOf(ctx context.Context, srv *servers.Server) (q technitium.LogQuery, info logInfo, err error) {
	info = logInfo{Server: srv.Name}
	apps, err := srv.Client.Apps(ctx)
	if err != nil {
		return q, info, err
	}
	i := slices.IndexFunc(apps, func(app technitium.App) bool { return app.LogsQueries() })
	if i < 0 {
		return q, info, fmt.Errorf("%s has no app that keeps a searchable log of queries: install Query Logs (Sqlite) from the Apps section of its web console, and it logs from then on", srv.Name)
	}
	q.App, info.App = apps[i].Name, apps[i].Name+" "+apps[i].Version
	q.ClassPath, _ = apps[i].QueryLog()
	info.Keeps, info.Note = logKeeps(ctx, srv, apps[i].Name)

	return q, info, nil
}

// logKeeps is what an app's configuration says of how much its log keeps,
// and anything of it worth a note. The configuration is the app's own to lay
// out: it is read for what is known of it, and passed over otherwise.
func logKeeps(ctx context.Context, srv *servers.Server, app string) (keeps, said string) {
	text, err := srv.Client.AppConfig(ctx, app)
	if err != nil {
		return "", "how much the log keeps could not be read: " + err.Error()
	}
	var config struct {
		EnableLogging *bool `json:"enableLogging"`
		MaxLogDays    *int  `json:"maxLogDays"`
		MaxLogRecords *int  `json:"maxLogRecords"`
	}
	if json.Unmarshal([]byte(text), &config) != nil {
		return "", ""
	}

	var parts []string
	if config.MaxLogDays != nil && *config.MaxLogDays > 0 {
		parts = append(parts, fmt.Sprintf("the last %d days", *config.MaxLogDays))
	}
	if config.MaxLogRecords != nil && *config.MaxLogRecords > 0 {
		parts = append(parts, fmt.Sprintf("at most %d queries", *config.MaxLogRecords))
	}
	if config.EnableLogging != nil && !*config.EnableLogging {
		said = "the app's logging is switched off in its configuration: no query is being logged"
	}

	return strings.Join(parts, ", "), said
}

func registerLogTools(r *registry) {
	type logSearchIn struct {
		serverArg

		Name        string `json:"name,omitempty"         jsonschema:"only queries for a name that matches: a * stands for any run of characters and the whole name must match, as *.example.com; without one the text may be anywhere in the name"`
		Client      string `json:"client,omitempty"       jsonschema:"only queries from this client: one address, exactly"`
		Type        string `json:"type,omitempty"         jsonschema:"only queries for this record type: A, AAAA, PTR, ..."`
		Result      string `json:"result,omitempty"       jsonschema:"only queries answered so: NoError, NxDomain, ServerFailure or Refused"`
		Source      string `json:"source,omitempty"       jsonschema:"only queries answered from: Authoritative (the server's own zones), Recursive, Cached, Blocked, UpstreamBlocked or CacheBlocked"`
		Protocol    string `json:"protocol,omitempty"     jsonschema:"only queries that came by: Udp, Tcp, Tls, Https or Quic"`
		Class       string `json:"class,omitempty"        jsonschema:"only queries asked in this class: IN, which nearly every query is, or CH for the few that ask a server about itself"`
		Last        string `json:"last,omitempty"         jsonschema:"only queries asked in the last while, as 30m, 6h or 7d"`
		Since       string `json:"since,omitempty"        jsonschema:"only queries asked from this time on, in UTC as 2026-10-09T14:00:00Z, or a date"`
		Until       string `json:"until,omitempty"        jsonschema:"only queries asked before this time"`
		CountBy     string `json:"count_by,omitempty"     jsonschema:"count the matching queries instead of listing them, by client, name, type, result or source: who asks for a name, which names do not exist, what a client asks for. Every matching query is read"`
		OldestFirst bool   `json:"oldest_first,omitempty" jsonschema:"list from the oldest; the newest come first without it"`
		Limit       int    `json:"limit,omitempty"        jsonschema:"the most queries to list (default 100), or with count_by the most counts (default 200)"`
		Offset      int    `json:"offset,omitempty"       jsonschema:"how many to pass over first, to read on from a limit"`
	}
	type logSearchOut struct {
		Queries []logRow   `json:"queries,omitempty" jsonschema:"the queries that matched, the servers' together in the order of their times"`
		Counts  []logCount `json:"counts,omitempty"  jsonschema:"with count_by: each value and how many of the matching queries have it, the most first"`
		Total   int        `json:"total"             jsonschema:"how many queries matched in all, on every server read"`
		Logs    []logInfo  `json:"logs"              jsonschema:"each server's log: the app that keeps it, how far back it goes, and how many of its queries matched"`
		Note    string     `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "log_search",
		Description: "Search the servers' logs of the queries they answered: who asked for what, when, and what they were told. Filter by name, client, record type, how it was answered, where the answer came from and when; or with count_by count the matches instead of listing them - by client to see who is still asking for a name, by name to see which names a client asks for or which do not exist. A server keeps this log only with an app installed that does, Query Logs (Sqlite) being the usual one, and only as far back as the app is set to: each server's row says which app, how much it keeps, and when it has none. server_stats gives running totals without one.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in logSearchIn) (*mcp.CallToolResult, logSearchOut, error) {
		var q technitium.LogQuery
		var err error
		if q.RCode, err = oneOf("result", in.Result, logResults); err != nil {
			return nil, logSearchOut{}, err
		}
		if q.ResponseType, err = oneOf("source", in.Source, logSources); err != nil {
			return nil, logSearchOut{}, err
		}
		if q.Protocol, err = oneOf("protocol", in.Protocol, logProtocols); err != nil {
			return nil, logSearchOut{}, err
		}
		q.Type, q.Class, q.OldestFirst = strings.ToUpper(strings.TrimSpace(in.Type)), strings.ToUpper(strings.TrimSpace(in.Class)), in.OldestFirst
		// the log matches a name whole, with a * for any run: text given without one may be anywhere in the name
		if q.Name = strings.TrimSuffix(strings.TrimSpace(in.Name), "."); q.Name != "" && !strings.Contains(q.Name, "*") {
			q.Name = "*" + q.Name + "*"
		}
		if client := strings.TrimSpace(in.Client); client != "" {
			addr, ok := parseAddr(client)
			if !ok {
				return nil, logSearchOut{}, fmt.Errorf("client %q: the log is searched by one client's address, exactly, as 10.0.0.5", in.Client)
			}
			q.Client = addr.String()
		}
		switch {
		case strings.TrimSpace(in.Last) != "" && (strings.TrimSpace(in.Since) != "" || strings.TrimSpace(in.Until) != ""):
			return nil, logSearchOut{}, errors.New("give last for the time up to now, or since and until for a time of your own: not both")
		case strings.TrimSpace(in.Last) != "":
			length, lengthErr := lengthOf(in.Last)
			if lengthErr != nil {
				return nil, logSearchOut{}, fmt.Errorf("last: %w", lengthErr)
			}
			q.Start = time.Now().Add(-length)
		default:
			if strings.TrimSpace(in.Since) != "" {
				if q.Start, err = when(in.Since); err != nil {
					return nil, logSearchOut{}, fmt.Errorf("since: %w", err)
				}
			}
			if strings.TrimSpace(in.Until) != "" {
				if q.End, err = when(in.Until); err != nil {
					return nil, logSearchOut{}, fmt.Errorf("until: %w", err)
				}
			}
			if !q.Start.IsZero() && !q.End.IsZero() && !q.End.After(q.Start) {
				return nil, logSearchOut{}, fmt.Errorf("until %s is not after since %s", q.End.Format(time.RFC3339), q.Start.Format(time.RFC3339))
			}
		}
		countBy := strings.ToLower(strings.TrimSpace(in.CountBy))
		if countBy != "" && logCounts[countBy] == nil {
			return nil, logSearchOut{}, fmt.Errorf("count_by %q: it takes client, name, type, result or source", in.CountBy)
		}
		offset, limit := max(in.Offset, 0), in.Limit
		switch {
		case limit <= 0 && countBy != "":
			limit = listDefault
		case limit <= 0:
			limit = logDefault
		default:
		}
		// a page of the servers' queries together is cut from the first of each server's, so that many are read from each
		q.Page, q.PerPage = 1, offset+limit
		if countBy != "" {
			q.PerPage = logCountMost
		}
		if q.PerPage > logMost && countBy == "" {
			return nil, logSearchOut{}, fmt.Errorf("offset %d and limit %d reach past the first %d matches, which is as far as a listing reads: narrow the search by time, name or client, or count the matches with count_by", offset, limit, logMost)
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, logSearchOut{}, err
		}

		type read struct {
			info logInfo
			page *technitium.LogPage
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (read, error) {
			whose, info, err := logOf(ctx, srv)
			if err != nil {
				return read{}, err
			}
			search := q
			search.App, search.ClassPath = whose.App, whose.ClassPath
			page, err := srv.Client.QueryLog(ctx, search)
			if err != nil {
				return read{}, err
			}
			info.Matched = page.TotalEntries

			return read{info: info, page: page}, nil
		})
		if _, err := failures(answers); err != nil {
			return nil, logSearchOut{}, err
		}

		out := logSearchOut{Logs: make([]logInfo, 0, len(answers))}
		var rows []logRow
		counted := map[string]*logCount{}
		for _, a := range answers {
			if a.Err != nil {
				out.Logs = append(out.Logs, logInfo{Server: a.Server.Name, Error: a.Err.Error()})

				continue
			}
			out.Logs = append(out.Logs, a.Value.info)
			out.Total += a.Value.page.TotalEntries
			if countBy != "" && a.Value.page.TotalEntries > len(a.Value.page.Entries) {
				out.Note = note(out.Note, fmt.Sprintf("%d queries matched on %s and the first %d were counted: narrow the search by time to count them all", a.Value.page.TotalEntries, a.Server.Name, len(a.Value.page.Entries)))
			}
			for i := range a.Value.page.Entries {
				e := &a.Value.page.Entries[i]
				if countBy == "" {
					rows = append(rows, logRow{Server: a.Server.Name, Time: utc(e.Timestamp), Client: e.Client, Name: e.Name, Type: e.Type, Result: e.RCode, Source: e.ResponseType, Protocol: e.Protocol, Answer: e.Answer, TookMS: e.ResponseRTT})

					continue
				}
				value := logCounts[countBy](e)
				if counted[value] == nil {
					counted[value] = &logCount{Value: value}
					if len(picked) > 1 {
						counted[value].On = map[string]int{}
					}
				}
				counted[value].Queries++
				if len(picked) > 1 {
					counted[value].On[a.Server.Name]++
				}
			}
		}

		if countBy != "" {
			out.Counts = make([]logCount, 0, len(counted))
			for _, c := range counted {
				out.Counts = append(out.Counts, *c)
			}
			slices.SortFunc(out.Counts, func(a, b logCount) int {
				return cmp.Or(-cmp.Compare(a.Queries, b.Queries), cmp.Compare(a.Value, b.Value))
			})
			values := len(out.Counts)
			out.Counts = out.Counts[min(offset, len(out.Counts)):]
			if len(out.Counts) > limit {
				out.Counts = out.Counts[:limit]
				out.Note = note(out.Note, fmt.Sprintf("the queries have %d different values and %d are given, starting at the %s: read on with offset %d", values, limit, ordinal(offset+1), offset+limit))
			}

			return nil, out, nil
		}

		// the servers' queries together, in the order of their times: each server's own are in order already
		slices.SortStableFunc(rows, func(a, b logRow) int {
			if in.OldestFirst {
				return cmp.Compare(a.Time, b.Time)
			}

			return cmp.Compare(b.Time, a.Time)
		})
		rows = rows[min(offset, len(rows)):]
		if len(rows) > limit {
			rows = rows[:limit]
		}
		if out.Queries = rows; out.Total > offset+len(rows) {
			out.Note = note(out.Note, fmt.Sprintf("%d queries matched and %d are given, starting at the %s: read on with offset %d, narrow the search, or count them with count_by", out.Total, len(rows), ordinal(offset+1), offset+len(rows)))
		}

		return nil, out, nil
	})
}
