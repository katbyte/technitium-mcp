package technitium

import (
	"context"
	"errors"
	"net/url"
	"strconv"
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
	if q.App == "" || q.ClassPath == "" {
		return nil, errors.New("logs/query: whose log: it needs the app's name and the class of its part that keeps the log")
	}
	params := url.Values{"name": {q.App}, "classPath": {q.ClassPath}, "descendingOrder": {strconv.FormatBool(!q.OldestFirst)}}
	for param, value := range map[string]string{"qname": q.Name, "clientIpAddress": q.Client, "qtype": q.Type, "rcode": q.RCode, "responseType": q.ResponseType, "protocol": q.Protocol} {
		if value != "" {
			params.Set(param, value)
		}
	}
	if !q.Start.IsZero() {
		params.Set("start", q.Start.UTC().Format(time.RFC3339))
	}
	if !q.End.IsZero() {
		params.Set("end", q.End.UTC().Format(time.RFC3339))
	}
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
