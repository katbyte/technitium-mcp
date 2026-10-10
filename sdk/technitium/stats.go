package technitium

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"time"
)

// The windows a server keeps its statistics by.
const (
	StatsLastHour  = "LastHour"
	StatsLastDay   = "LastDay"
	StatsLastWeek  = "LastWeek"
	StatsLastMonth = "LastMonth"
	StatsLastYear  = "LastYear"
	// statsCustom is a window given by its start and its end
	statsCustom = "Custom"
)

// The lists a server keeps of who asked most and what was asked for most.
const (
	TopClients        = "TopClients"
	TopDomains        = "TopDomains"
	TopBlockedDomains = "TopBlockedDomains"
)

// StatsWindow is the time a server's statistics are asked for: one of the
// windows it keeps (StatsLastHour, the default, to StatsLastYear), or the
// time between Start and End.
type StatsWindow struct {
	Type       string
	Start, End time.Time

	// EveryQueryType has Stats give each record type asked for its own
	// count, where the server otherwise gives the leading ones and the rest
	// as one
	EveryQueryType bool
	// NoReverseLookup has TopStats give clients by address alone, without
	// the server looking up a name for each, and OnlyRateLimited only the
	// clients it is holding back for asking too much
	NoReverseLookup, OnlyRateLimited bool
}

// params are the window as the API takes one.
func (w StatsWindow) params() (url.Values, error) {
	if w.Start.IsZero() != w.End.IsZero() {
		return nil, errors.New("a window of one's own needs both its start and its end")
	}
	if !w.Start.IsZero() {
		if !w.End.After(w.Start) {
			return nil, errors.New("a window ends after it starts")
		}

		return url.Values{"type": {statsCustom}, "start": {w.Start.UTC().Format(time.RFC3339)}, "end": {w.End.UTC().Format(time.RFC3339)}}, nil
	}
	if w.Type == "" {
		return url.Values{"type": {StatsLastHour}}, nil
	}

	return url.Values{"type": {w.Type}}, nil
}

// Stats is what a server did over a window, as its dashboard shows it.
type Stats struct {
	Totals StatTotals `json:"stats"`
	// TopClients, TopDomains and TopBlockedDomains are the ten that asked
	// most and were asked for most: TopStats gives more
	TopClients        []TopClient `json:"topClients"`
	TopDomains        []TopDomain `json:"topDomains"`
	TopBlockedDomains []TopDomain `json:"topBlockedDomains"`

	QueryTypeChart chart `json:"queryTypeChartData"`
	ProtocolChart  chart `json:"protocolTypeChartData"`
}

// StatTotals are a window's counts. The queries are counted by how each was
// answered twice over: by its response code (NoError, ServerFailure,
// NxDomain, Refused) and by where the answer came from (Authoritative,
// Recursive, Cached, Blocked, Dropped).
type StatTotals struct {
	Queries       int `json:"totalQueries"`
	NoError       int `json:"totalNoError"`
	ServerFailure int `json:"totalServerFailure"`
	NxDomain      int `json:"totalNxDomain"`
	Refused       int `json:"totalRefused"`
	Authoritative int `json:"totalAuthoritative"`
	Recursive     int `json:"totalRecursive"`
	Cached        int `json:"totalCached"`
	Blocked       int `json:"totalBlocked"`
	Dropped       int `json:"totalDropped"`
	Clients       int `json:"totalClients"`

	// what the server holds now, whatever the window
	Zones         int `json:"zones"`
	CachedEntries int `json:"cachedEntries"`
	// AllowedZones and BlockedZones are the names on the server's own two
	// lists; AllowListZones and BlockListZones the names of the lists it
	// fetches
	AllowedZones   int `json:"allowedZones"`
	BlockedZones   int `json:"blockedZones"`
	AllowListZones int `json:"allowListZones"`
	BlockListZones int `json:"blockListZones"`
}

// TopClient is a client by how much it asked.
type TopClient struct {
	// Name is the client's address, and Domain the name its PTR gives it
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Hits   int    `json:"hits"`
	// RateLimited is the server holding the client back for asking too much
	RateLimited bool `json:"rateLimited"`
}

// TopDomain is a name by how often it was asked for.
type TopDomain struct {
	Name string `json:"name"`
	Hits int    `json:"hits"`
}

// chart is a count for each of a set of labels, as the dashboard draws one.
type chart struct {
	Labels   []string `json:"labels"`
	Datasets []struct {
		Data []int `json:"data"`
	} `json:"datasets"`
}

// counts are a chart's counts by label.
func (c *chart) counts() map[string]int {
	out := map[string]int{}
	if len(c.Datasets) == 0 {
		return out
	}
	for i, label := range c.Labels {
		if i < len(c.Datasets[0].Data) {
			out[label] = c.Datasets[0].Data[i]
		}
	}

	return out
}

// QueryTypes are the window's queries by the record type asked for: the ten
// most asked.
func (s *Stats) QueryTypes() map[string]int { return s.QueryTypeChart.counts() }

// Protocols are the window's queries by how they came: Udp, Tcp, Tls, Https,
// Quic.
func (s *Stats) Protocols() map[string]int { return s.ProtocolChart.counts() }

// Stats reads what the server did over a window.
func (c *Client) Stats(ctx context.Context, window StatsWindow) (*Stats, error) {
	params, err := window.params()
	if err != nil {
		return nil, errors.New("dashboard/stats/get: " + err.Error())
	}
	params.Set("utc", yes)
	if window.EveryQueryType {
		params.Set("dontTrimQueryTypeData", yes)
	}

	var out Stats
	if err := c.read(ctx, "dashboard/stats/get", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// TopStats reads one of the server's lists for a window - TopClients,
// TopDomains or TopBlockedDomains - to as many entries as asked for.
func (c *Client) TopStats(ctx context.Context, window StatsWindow, list string, limit int) (*Stats, error) {
	params, err := window.params()
	if err != nil {
		return nil, errors.New("dashboard/stats/getTop: " + err.Error())
	}
	if list != TopClients && list != TopDomains && list != TopBlockedDomains {
		return nil, errors.New("dashboard/stats/getTop: which list: " + TopClients + ", " + TopDomains + " or " + TopBlockedDomains)
	}
	params.Set("statsType", list)
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	for param, on := range map[string]bool{"noReverseLookup": window.NoReverseLookup, "onlyRateLimitedClients": window.OnlyRateLimited} {
		if on {
			params.Set(param, yes)
		}
	}

	var out Stats
	if err := c.read(ctx, "dashboard/stats/getTop", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}
