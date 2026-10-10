package tools

import (
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

// The most lines of a log file a call gives, and how many it gives when it
// is not told.
const (
	logLinesMost    = 2000
	logLinesDefault = 200
	exportRowsMost  = 5000
)

// logFilter is what a search of the log of queries is narrowed by, as a
// tool is given it.
type logFilter struct {
	Name     string `json:"name,omitempty"     jsonschema:"only queries for a name that matches: a * stands for any run of characters and the whole name must match, as *.example.com; without one the text may be anywhere in the name"`
	Client   string `json:"client,omitempty"   jsonschema:"only queries from this client: one address, exactly"`
	Type     string `json:"type,omitempty"     jsonschema:"only queries for this record type: A, AAAA, PTR, ..."`
	Result   string `json:"result,omitempty"   jsonschema:"only queries answered so: NoError, NxDomain, ServerFailure or Refused"`
	Source   string `json:"source,omitempty"   jsonschema:"only queries answered from: Authoritative, Recursive, Cached, Blocked, UpstreamBlocked or CacheBlocked"`
	Protocol string `json:"protocol,omitempty" jsonschema:"only queries that came by: Udp, Tcp, Tls, Https or Quic"`
	Class    string `json:"class,omitempty"    jsonschema:"only queries asked in this class: IN, which nearly every query is, or CH"`
	Last     string `json:"last,omitempty"     jsonschema:"only queries asked in the last while, as 30m, 6h or 7d"`
	Since    string `json:"since,omitempty"    jsonschema:"only queries asked from this time on, in UTC as 2026-10-09T14:00:00Z, or a date"`
	Until    string `json:"until,omitempty"    jsonschema:"only queries asked before this time"`
}

// query reads the filters as the client takes them.
func (f logFilter) query() (technitium.LogQuery, error) {
	var q technitium.LogQuery
	var err error
	if q.RCode, err = oneOf("result", f.Result, logResults); err != nil {
		return q, err
	}
	if q.ResponseType, err = oneOf("source", f.Source, logSources); err != nil {
		return q, err
	}
	if q.Protocol, err = oneOf("protocol", f.Protocol, logProtocols); err != nil {
		return q, err
	}
	q.Type, q.Class = strings.ToUpper(strings.TrimSpace(f.Type)), strings.ToUpper(strings.TrimSpace(f.Class))
	// the log matches a name whole, with a * for any run: text given without one may be anywhere in the name
	if q.Name = strings.TrimSuffix(strings.TrimSpace(f.Name), "."); q.Name != "" && !strings.Contains(q.Name, "*") {
		q.Name = "*" + q.Name + "*"
	}
	if client := strings.TrimSpace(f.Client); client != "" {
		addr, ok := parseAddr(client)
		if !ok {
			return q, fmt.Errorf("client %q: the log is searched by one client's address, exactly", client)
		}
		q.Client = addr.String()
	}
	last, since, until := strings.TrimSpace(f.Last), strings.TrimSpace(f.Since), strings.TrimSpace(f.Until)
	switch {
	case last != "" && (since != "" || until != ""):
		return q, errors.New("give last for the time up to now, or since and until for a time of your own: not both")
	case last != "":
		length, lengthErr := lengthOf(last)
		if lengthErr != nil {
			return q, fmt.Errorf("last: %w", lengthErr)
		}
		q.Start = time.Now().Add(-length)
	default:
		if since != "" {
			if q.Start, err = when(since); err != nil {
				return q, fmt.Errorf("since: %w", err)
			}
		}
		if until != "" {
			if q.End, err = when(until); err != nil {
				return q, fmt.Errorf("until: %w", err)
			}
		}
	}

	return q, nil
}

func registerOpsMoreTools(r *registry) {
	type logFile struct {
		File string `json:"file" jsonschema:"the file's name, the day it is for: log_read and log_delete take it"`
		Size string `json:"size" jsonschema:"how big it is, as the server writes a size"`
	}
	type logFilesOn struct {
		Server string    `json:"server"`
		Files  []logFile `json:"files"           jsonschema:"the server's log files, newest first"`
		Error  string    `json:"error,omitempty"`
	}
	type logFilesOut struct {
		Servers []logFilesOn `json:"servers"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "log_files",
		Description: "The files each server writes its own log to, a file a day: what the server did and what went wrong - a zone transfer that failed, a block list that could not be fetched, who signed in and what they changed. log_read reads one. This is not the log of queries, which log_search searches.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverArg) (*mcp.CallToolResult, logFilesOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, logFilesOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) ([]technitium.LogFile, error) {
			return srv.Client.LogFiles(ctx)
		})
		if _, err := failures(answers); err != nil {
			return nil, logFilesOut{}, err
		}

		out := logFilesOut{Servers: []logFilesOn{}}
		for _, a := range answers {
			row := logFilesOn{Server: a.Server.Name, Files: []logFile{}}
			if a.Err != nil {
				row.Error = a.Err.Error()
			}
			for _, f := range a.Value {
				row.Files = append(row.Files, logFile{File: f.FileName, Size: f.Size})
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})

	type logReadIn struct {
		serverArg

		File     string `json:"file,omitempty"     jsonschema:"the log file, as log_files names it: a day, as 2026-10-09. Left out, each server's newest is read"`
		Contains string `json:"contains,omitempty" jsonschema:"only the lines with this text in them, whatever its case: a zone's name, an address, error"`
		Lines    int    `json:"lines,omitempty"    jsonschema:"the most lines to give, counted back from the end of the file (default 200, at most 2000)"`
	}
	type logReadOn struct {
		Server  string   `json:"server"`
		File    string   `json:"file,omitempty"`
		Lines   []string `json:"lines"           jsonschema:"the lines, oldest first"`
		Matched int      `json:"matched"         jsonschema:"how many lines of the file matched, of which the last are given"`
		Of      int      `json:"of"              jsonschema:"how many lines the file has"`
		Error   string   `json:"error,omitempty"`
	}
	type logReadOut struct {
		Servers []logReadOn `json:"servers"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "log_read",
		Description: "Read a server's own log for a day: the end of the file, where what happened last is, or only its lines with some text in them. It is where a failure explains itself - why a zone transfer was refused, why a block list was not fetched, what an app threw, who signed in and what they changed - in the server's own words, with times in UTC unless it is set to use its own. Each server asked reads its own file.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in logReadIn) (*mcp.CallToolResult, logReadOut, error) {
		lines := in.Lines
		switch {
		case lines <= 0:
			lines = logLinesDefault
		case lines > logLinesMost:
			lines = logLinesMost
		default:
		}
		contains := strings.ToLower(strings.TrimSpace(in.Contains))
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, logReadOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (logReadOn, error) {
			row := logReadOn{Server: srv.Name, File: strings.TrimSpace(in.File), Lines: []string{}}
			if row.File == "" {
				files, err := srv.Client.LogFiles(ctx)
				if err != nil {
					return row, err
				}
				if len(files) == 0 {
					return row, errors.New("the server has no log files: its logging may be off, which settings_get shows under loggingType")
				}
				row.File = files[0].FileName
			}
			text, err := srv.Client.DownloadLog(ctx, row.File, 0)
			if err != nil {
				return row, err
			}
			for line := range strings.SplitSeq(text, "\n") {
				if line = strings.TrimRight(line, "\r"); line == "" {
					continue
				}
				row.Of++
				if contains == "" || strings.Contains(strings.ToLower(line), contains) {
					row.Matched++
					row.Lines = append(row.Lines, line)
				}
			}
			if len(row.Lines) > lines {
				row.Lines = row.Lines[len(row.Lines)-lines:]
			}

			return row, nil
		})
		if _, err := failures(answers); err != nil {
			return nil, logReadOut{}, err
		}

		out := logReadOut{Servers: []logReadOn{}}
		for _, a := range answers {
			row := a.Value
			if a.Err != nil {
				row.Server, row.Error = a.Server.Name, a.Err.Error()
				if row.Lines == nil {
					row.Lines = []string{}
				}
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})

	type logDeleteIn struct {
		writeServerArg

		File   string `json:"file,omitempty"    jsonschema:"the log file to delete, as log_files names it"`
		All    bool   `json:"all,omitempty"     jsonschema:"delete every log file the server has"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"delete nothing, and answer with what would be"`
	}
	type logDeleteOut struct {
		Server  string   `json:"server"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		Left    int      `json:"left"           jsonschema:"how many log files the server has now; with a dry run, how many it has. The server starts today's again as soon as it has something to write, which a deletion is"`
		Note    string   `json:"note,omitempty"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "log_delete",
		Description: "Delete one of a server's own log files, or all of them, for good. The log is the record of who changed what and of every failure, so this is for a disk that is filling, not for tidiness: the server already deletes files older than the days it is set to keep (settings_get, maxLogFileDays). The log of queries is not touched.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in logDeleteIn) (*mcp.CallToolResult, logDeleteOut, error) {
		file := strings.TrimSpace(in.File)
		if (file == "") == !in.All {
			return nil, logDeleteOut{}, errors.New("give the file to delete, or all for every one: one of the two")
		}
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, logDeleteOut{}, err
		}
		files, err := srv.Client.LogFiles(ctx)
		if err != nil {
			return nil, logDeleteOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}
		out := logDeleteOut{Server: srv.Name, Changes: []string{}, Left: len(files)}
		done := &changes{dry: in.DryRun}
		switch {
		case in.All && len(files) == 0:
			out.Note = "the server has no log files: there is nothing to delete"

			return nil, out, nil
		case in.All:
			if done.did("deleted all %d log files of %s", len(files), srv.Name) {
				if err := srv.Client.DeleteAllLogs(ctx); err != nil {
					return nil, logDeleteOut{}, fmt.Errorf("deleting the log files: %w", err)
				}
			}
		case !slices.ContainsFunc(files, func(f technitium.LogFile) bool { return f.FileName == file }):
			// the server deletes a file that is not there without a word, so it is said here
			out.Note = "the server has no log file by that name: log_files names the ones it has"

			return nil, out, nil
		default:
			if done.did("deleted the log file %s of %s", file, srv.Name) {
				if err := srv.Client.DeleteLog(ctx, file); err != nil {
					return nil, logDeleteOut{}, fmt.Errorf("deleting the log file: %w", err)
				}
			}
		}
		out.Changed, out.Changes = true, done.said
		if !in.DryRun {
			after, err := srv.Client.LogFiles(ctx)
			if err != nil {
				return nil, logDeleteOut{}, fmt.Errorf("the log was deleted and the files could not be listed again: %w", err)
			}
			out.Left = len(after)
		}

		return nil, out, nil
	})

	type logExportIn struct {
		serverArg
		logFilter

		Limit int `json:"limit,omitempty" jsonschema:"the most rows to give from each server (default 200, at most 5000)"`
	}
	type logExportOn struct {
		Server string `json:"server"`
		CSV    string `json:"csv,omitempty"   jsonschema:"the matching queries as CSV: a line of headings, then a query a line, newest first"`
		Rows   int    `json:"rows"            jsonschema:"how many queries are in csv"`
		Of     int    `json:"of"              jsonschema:"how many matched in all"`
		Error  string `json:"error,omitempty"`
	}
	type logExportOut struct {
		Servers []logExportOn `json:"servers"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "log_export",
		Description: "The servers' logs of queries as CSV, for what log_search would find: every matching query a line, with when it was asked, by which client, over what, how it was answered and with what. It is for handing the queries on - to a spreadsheet, a report, another tool - where log_search is for reading and counting them. Give it filters: an export of everything a busy server logged is very large, and only the first rows up to the limit are given.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in logExportIn) (*mcp.CallToolResult, logExportOut, error) {
		q, err := in.query()
		if err != nil {
			return nil, logExportOut{}, err
		}
		limit := in.Limit
		switch {
		case limit <= 0:
			limit = listDefault
		case limit > exportRowsMost:
			limit = exportRowsMost
		default:
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, logExportOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (logExportOn, error) {
			row := logExportOn{Server: srv.Name}
			own, _, err := logOf(ctx, srv)
			if err != nil {
				return row, err
			}
			asked := q
			asked.App, asked.ClassPath = own.App, own.ClassPath
			text, err := srv.Client.ExportQueryLog(ctx, asked)
			if err != nil {
				return row, err
			}
			lines := strings.Split(strings.TrimRight(text, "\r\n"), "\n")
			row.Of = max(len(lines)-1, 0)
			row.Rows = min(row.Of, limit)
			row.CSV = strings.Join(lines[:row.Rows+min(len(lines), 1)], "\n")

			return row, nil
		})
		if _, err := failures(answers); err != nil {
			return nil, logExportOut{}, err
		}

		out := logExportOut{Servers: []logExportOn{}}
		for _, a := range answers {
			row := a.Value
			if a.Err != nil {
				row.Server, row.Error = a.Server.Name, a.Err.Error()
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})

	type metricsOn struct {
		Server        string `json:"server"`
		UpSince       string `json:"up_since,omitempty"       jsonschema:"when the server started, UTC"`
		UptimeSeconds int64  `json:"uptime_seconds,omitempty"`
		Queries       int    `json:"queries"                  jsonschema:"every query it has answered since it started"`
		NoError       int    `json:"no_error"`
		ServerFailure int    `json:"server_failure"`
		NxDomain      int    `json:"nx_domain"`
		Refused       int    `json:"refused"`
		Authoritative int    `json:"authoritative"            jsonschema:"answered from its own zones"`
		Recursive     int    `json:"recursive"                jsonschema:"answered by asking other servers"`
		Cached        int    `json:"cached"                   jsonschema:"answered from what it had kept"`
		Blocked       int    `json:"blocked"`
		Dropped       int    `json:"dropped"                  jsonschema:"not answered at all: over a rate limit, or malformed"`
		Clients       int    `json:"clients"`
		Healthy       bool   `json:"healthy"                  jsonschema:"the server resolved a name for itself just now, which is its own check that it is running and can resolve"`
		Unhealthy     string `json:"unhealthy,omitempty"      jsonschema:"why that check failed"`
		Prometheus    string `json:"prometheus,omitempty"     jsonschema:"the same counters as Prometheus reads them, when asked for"`
		Error         string `json:"error,omitempty"`
	}
	type metricsIn struct {
		serverArg

		Prometheus bool   `json:"prometheus,omitempty" jsonschema:"also give the counters as the text Prometheus scrapes"`
		Check      string `json:"check,omitempty"      jsonschema:"the name the health check has the server resolve; localhost without it, which proves the server runs, where a public name proves it reaches the outside"`
	}
	type metricsOut struct {
		Servers []metricsOn `json:"servers"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "server_metrics",
		Description: "Each server's health and its counters since it started: whether it can resolve a name right now - its own health check, which writes nothing to the log of queries - how long it has been up, and how many queries it has answered in all, by how and from where. server_stats gives the same kinds of numbers over a window of time, with who asked for what; this is the lifetime total and the quick answer to whether a server is alive. With check it resolves a name of your choosing, which tells a server that runs from one that also reaches the outside.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in metricsIn) (*mcp.CallToolResult, metricsOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, metricsOut{}, err
		}
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) (metricsOn, error) {
			row := metricsOn{Server: srv.Name}
			got, err := srv.Client.Metrics(ctx)
			if err != nil {
				return row, err
			}
			total := got.Lifetime
			row.UpSince, row.UptimeSeconds = utc(got.UpSince), got.UptimeSeconds
			row.Queries, row.NoError, row.ServerFailure, row.NxDomain, row.Refused = total.Queries, total.NoError, total.ServerFailure, total.NxDomain, total.Refused
			row.Authoritative, row.Recursive, row.Cached, row.Blocked, row.Dropped, row.Clients = total.Authoritative, total.Recursive, total.Cached, total.Blocked, total.Dropped, total.Clients
			if healthErr := srv.Client.HealthCheck(ctx, cleanName(in.Check), ""); healthErr != nil {
				row.Unhealthy = healthErr.Error()
			} else {
				row.Healthy = true
			}
			if in.Prometheus {
				if row.Prometheus, err = srv.Client.MetricsText(ctx); err != nil {
					return row, err
				}
			}

			return row, nil
		})
		if _, err := failures(answers); err != nil {
			return nil, metricsOut{}, err
		}

		out := metricsOut{Servers: []metricsOn{}}
		for _, a := range answers {
			row := a.Value
			if a.Err != nil {
				row.Server, row.Error = a.Server.Name, a.Err.Error()
			}
			out.Servers = append(out.Servers, row)
		}

		return nil, out, nil
	})

	type statsDeleteIn struct {
		writeServerArg

		DryRun bool `json:"dry_run,omitempty" jsonschema:"delete nothing, and answer with what would be"`
	}
	type statsDeleteOut struct {
		Server  string   `json:"server"`
		Changed bool     `json:"changed"`
		Changes []string `json:"changes"`
		Queries int      `json:"queries" jsonschema:"how many queries the last year's statistics counted before they were deleted"`
	}
	add(r, deleteTool, &mcp.Tool{
		Name:        "stats_delete",
		Description: "Delete every statistic a server keeps, from its disk and from memory: the dashboard and server_stats start again from nothing, and what was counted cannot be had back. The log of queries is a separate thing and is not touched, nor is the count of queries since the server started (server_metrics).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in statsDeleteIn) (*mcp.CallToolResult, statsDeleteOut, error) {
		srv, err := r.servers.One(in.Server)
		if err != nil {
			return nil, statsDeleteOut{}, err
		}
		before, err := srv.Client.Stats(ctx, technitium.StatsWindow{Type: "LastYear"})
		if err != nil {
			return nil, statsDeleteOut{}, fmt.Errorf("%s: %w", srv.Name, err)
		}

		out := statsDeleteOut{Server: srv.Name, Changed: true, Queries: before.Totals.Queries}
		done := &changes{dry: in.DryRun}
		if done.did("deleted every statistic %s kept, which counted %d queries over the last year", srv.Name, before.Totals.Queries) {
			if err := srv.Client.DeleteAllStats(ctx); err != nil {
				return nil, statsDeleteOut{}, fmt.Errorf("deleting the statistics: %w", err)
			}
		}
		out.Changes = done.said

		return nil, out, nil
	})
}
