package technitium

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// A server keeps no searchable record of the queries it answers by itself:
// an app does, Query Logs (Sqlite) being the usual one, and the log is asked
// for by the app's name and the class of its part that keeps it (App.QueryLog).

// LogQuery is a search of an app's log of queries.
type LogQuery struct {
	// App and ClassPath are whose log: an installed app's name, and the
	// class of its part that keeps the log
	App, ClassPath string

	// Name is the name asked for: exactly, or with a * for any run of
	// characters. Case does not matter
	Name string
	// Client is the address that asked, exactly
	Client string
	// Type is the record type asked for, and RCode how it was answered:
	// NoError, NxDomain, ServerFailure, Refused
	Type, RCode string
	// Class is the class asked in: IN for nearly every query there is, and
	// CH for the few that ask a server about itself
	Class string
	// ResponseType is where the answer came from: Authoritative, Recursive,
	// Cached, Blocked, UpstreamBlocked or CacheBlocked
	ResponseType string
	// Protocol is how the query came: Udp, Tcp, Tls, Https or Quic
	Protocol string
	// Start and End bound when it was asked; a zero time is no bound
	Start, End time.Time

	// OldestFirst orders the entries from the oldest; the newest come first
	// without it
	OldestFirst bool
	// Page is which page of the matches, from 1, and PerPage how many
	// entries a page holds: the server's own 10 when 0
	Page, PerPage int
}

// LogEntry is one query a server answered, as an app logged it.
type LogEntry struct {
	// Timestamp is when it was asked, in UTC
	Timestamp string `json:"timestamp"`
	Client    string `json:"clientIpAddress"`
	Protocol  string `json:"protocol"`
	// ResponseType is where the answer came from, and RCode how it went
	ResponseType string `json:"responseType"`
	RCode        string `json:"rcode"`
	// ResponseRTT is how long resolving it took, in milliseconds, for an
	// answer that was resolved; nil for one the server had
	ResponseRTT *float64 `json:"responseRtt"`
	Name        string   `json:"qname"`
	Type        string   `json:"qtype"`
	Class       string   `json:"qclass"`
	// Answer is what was answered, as text: A 10.0.0.4, or a chain as
	// CNAME emby.example.com., A 10.0.0.4; "" for an answer with no records
	Answer string `json:"answer"`
}

// LogPage is one page of the entries a search matched.
type LogPage struct {
	PageNumber   int        `json:"pageNumber"`
	TotalPages   int        `json:"totalPages"`
	TotalEntries int        `json:"totalEntries"`
	Entries      []LogEntry `json:"entries"`
}

// QueryLog searches an app's log of queries and returns one page of what
// matched, with how many matched in all.
func (c *Client) QueryLog(ctx context.Context, q LogQuery) (*LogPage, error) {
	params, err := q.filter("logs/query")
	if err != nil {
		return nil, err
	}
	params.Set("descendingOrder", strconv.FormatBool(!q.OldestFirst))
	if q.Page > 0 {
		params.Set("pageNumber", strconv.Itoa(q.Page))
	}
	if q.PerPage > 0 {
		params.Set("entriesPerPage", strconv.Itoa(q.PerPage))
	}

	var out LogPage
	if err := c.read(ctx, "logs/query", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// AppConfig reads an installed app's configuration, which is text of the
// app's own kind - JSON, for most; "" for an app that has none.
func (c *Client) AppConfig(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", errors.New("apps/config/get: which app")
	}

	var out struct {
		Config *string `json:"config"`
	}
	if err := c.read(ctx, "apps/config/get", url.Values{"name": {name}}, &out); err != nil {
		return "", err
	}
	if out.Config == nil {
		return "", nil
	}

	return *out.Config, nil
}

// filter is what a search of the log is narrowed by, as both the calls that
// search it take it.
func (q LogQuery) filter(path string) (url.Values, error) {
	if q.App == "" || q.ClassPath == "" {
		return nil, errors.New(path + ": whose log: it needs the app's name and the class of its part that keeps the log")
	}
	params := url.Values{"name": {q.App}, "classPath": {q.ClassPath}}
	set(params, map[string]string{"qname": q.Name, "clientIpAddress": q.Client, "qtype": q.Type, "qclass": q.Class, "rcode": q.RCode, "responseType": q.ResponseType, "protocol": q.Protocol})
	if !q.Start.IsZero() {
		params.Set("start", q.Start.UTC().Format(time.RFC3339))
	}
	if !q.End.IsZero() {
		params.Set("end", q.End.UTC().Format(time.RFC3339))
	}

	return params, nil
}

// ExportQueryLog is a search of an app's log of queries as a CSV file:
// every entry that matched, a line each under a line of headings, where
// QueryLog gives a page of them. Its paging and its order are not asked for.
func (c *Client) ExportQueryLog(ctx context.Context, q LogQuery) (string, error) {
	params, err := q.filter("logs/export")
	if err != nil {
		return "", err
	}
	text, err := c.readText(ctx, "logs/export", params)

	// the server begins the file with a byte order mark, which is no part
	// of its first heading
	return strings.TrimPrefix(text, "\ufeff"), err
}

// LogFile is one of the files the server writes its own log to: what it
// did and what went wrong, a file a day.
type LogFile struct {
	// FileName is the file's name, the day it is for: 2020-09-19
	FileName string `json:"fileName"`
	// Size is how big the file is, as the server writes a size: 8.14 KB
	Size string `json:"size"`
}

// LogFiles lists the server's log files, newest first.
func (c *Client) LogFiles(ctx context.Context) ([]LogFile, error) {
	var out struct {
		Files []LogFile `json:"logFiles"`
	}
	if err := c.read(ctx, "logs/list", nil, &out); err != nil {
		return nil, err
	}

	return out.Files, nil
}

// DownloadLog reads one of the server's log files, by the name LogFiles
// gives it: the whole file, or with limitMB its first so many megabytes.
func (c *Client) DownloadLog(ctx context.Context, fileName string, limitMB int) (string, error) {
	if fileName == "" {
		return "", errors.New("logs/download: which log file")
	}
	params := url.Values{"fileName": {fileName}}
	if limitMB > 0 {
		params.Set("limit", strconv.Itoa(limitMB))
	}

	return c.readText(ctx, "logs/download", params)
}

// DeleteLog deletes one of the server's log files for good.
func (c *Client) DeleteLog(ctx context.Context, fileName string) error {
	if fileName == "" {
		return errors.New("logs/delete: which log file")
	}

	return c.write(ctx, "logs/delete", url.Values{"log": {fileName}}, nil)
}

// DeleteAllLogs deletes every log file the server has for good.
func (c *Client) DeleteAllLogs(ctx context.Context) error {
	return c.write(ctx, "logs/deleteAll", nil, nil)
}
