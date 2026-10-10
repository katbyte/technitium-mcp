package tools

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// settingsRow is how one server is set up, as server_settings answers.
type settingsRow struct {
	Server string `json:"server"`
	Error  string `json:"error,omitempty" jsonschema:"why this server's settings could not be read; the rest of its row is then empty"`

	Listens []string `json:"listens,omitempty" jsonschema:"the addresses the server answers DNS on"`
	Also    []string `json:"also,omitempty"    jsonschema:"the other ways it answers DNS, when any is on: DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC and the rest"`

	Recursion         string   `json:"recursion,omitempty"          jsonschema:"whose queries for names it does not hold it resolves: Deny, Allow (anyone who can reach it), AllowOnlyForPrivateNetworks, or UseSpecifiedNetworkACL with the networks in recursion_networks"`
	RecursionNetworks []string `json:"recursion_networks,omitempty" jsonschema:"the networks it resolves for, a ! before one it does not"`
	Forwarders        []string `json:"forwarders,omitempty"         jsonschema:"the name servers it sends what it does not hold to; absent, it resolves from the root itself"`
	ForwarderProtocol string   `json:"forwarder_protocol,omitempty" jsonschema:"how it reaches them: Udp, Tcp, Tls, Https or Quic"`
	Proxy             string   `json:"proxy,omitempty"              jsonschema:"the proxy it resolves through, as its type and address"`
	DNSSECValidation  bool     `json:"dnssec_validation"`
	QNameMinimization bool     `json:"qname_minimization"`

	TransferNetworks []string `json:"transfer_networks,omitempty" jsonschema:"who may transfer any zone from the server, whatever a zone's own settings say"`
	NotifyNetworks   []string `json:"notify_networks,omitempty"   jsonschema:"who may send it a notify, whatever a zone's own settings say"`
	TSIGKeys         []string `json:"tsig_keys,omitempty"         jsonschema:"its transfer keys, each as its name and algorithm: a key's secret is never given"`

	Blocking        string   `json:"blocking"                    jsonschema:"off, or how a blocked name is answered: NxDomain, AnyAddress or CustomAddress"`
	BlockLists      []string `json:"block_lists,omitempty"       jsonschema:"the lists it blocks from, by address"`
	BlockListsEvery string   `json:"block_lists_every,omitempty" jsonschema:"how often the lists are fetched"`
	BlockListsNext  string   `json:"block_lists_next,omitempty"  jsonschema:"when they are next fetched, in UTC"`

	DefaultTTL       int    `json:"default_ttl"                jsonschema:"the TTL a record made with none is given, in seconds"`
	CacheNegativeTTL int    `json:"cache_negative_ttl"         jsonschema:"how long the answer that a name does not exist is kept, at most, in seconds"`
	ServeStale       bool   `json:"serve_stale,omitempty"      jsonschema:"it answers from an expired kept answer while it fetches a fresh one"`
	Console          string `json:"console,omitempty"          jsonschema:"where its web console and API answer: the http port, and the https one when TLS is on, with whether the certificate is one it signed for itself"`
	QueryLog         string `json:"query_log,omitempty"        jsonschema:"where it writes its log, and whether queries go in it; a log of queries that can be searched is an app's (apps)"`
	UpdateCheck      bool   `json:"update_check,omitempty"     jsonschema:"it looks for newer versions of itself"`
	AppsAutoUpdate   bool   `json:"apps_auto_update,omitempty" jsonschema:"it updates its apps by itself"`

	Apps []string `json:"apps,omitempty" jsonschema:"the DNS apps installed, each as its name and version; one that keeps a searchable log of queries says so"`
	Note string   `json:"note,omitempty"`
}

// settingsRowOf reads one server's settings and apps.
func settingsRowOf(ctx context.Context, srv *servers.Server) (settingsRow, error) {
	row := settingsRow{Server: srv.Name}
	s, err := srv.Client.Settings(ctx)
	if err != nil {
		return row, err
	}

	row.Listens, row.Recursion, row.RecursionNetworks, row.Forwarders = s.LocalEndPoints, s.Recursion, s.RecursionNetworkACL, s.Forwarders
	row.DNSSECValidation, row.QNameMinimization, row.TransferNetworks, row.NotifyNetworks = s.DNSSECValidation, s.QNameMinimization, s.ZoneTransferAllowedNetworks, s.NotifyAllowedNetworks
	row.DefaultTTL, row.CacheNegativeTTL, row.ServeStale, row.UpdateCheck, row.AppsAutoUpdate = s.DefaultRecordTTL, s.CacheNegativeRecordTTL, s.ServeStale, s.CheckForUpdate, s.AppsAutoUpdate
	if len(s.Forwarders) > 0 {
		row.ForwarderProtocol = s.ForwarderProtocol
	}
	if s.Proxy != nil {
		row.Proxy = s.Proxy.Type + " " + s.Proxy.Address + ":" + strconv.Itoa(s.Proxy.Port)
	}
	for _, key := range s.TSIGKeys {
		row.TSIGKeys = append(row.TSIGKeys, key.Name+" ("+key.Algorithm+")")
	}
	for name, on := range map[string]bool{"DNS-over-UDP-PROXY": s.EnableDNSOverUDPProxy, "DNS-over-TCP-PROXY": s.EnableDNSOverTCPProxy, "DNS-over-HTTP": s.EnableDNSOverHTTP, "DNS-over-TLS": s.EnableDNSOverTLS, "DNS-over-HTTPS": s.EnableDNSOverHTTPS, "DNS-over-HTTP/3": s.EnableDNSOverHTTP3, "DNS-over-QUIC": s.EnableDNSOverQUIC} {
		if on {
			row.Also = append(row.Also, name)
		}
	}
	slices.Sort(row.Also)

	row.Blocking = "off"
	if s.EnableBlocking {
		row.Blocking = s.BlockingType
		row.BlockLists = s.BlockListURLs
		if len(s.BlockListURLs) > 0 {
			row.BlockListsEvery, row.BlockListsNext = fmt.Sprintf("%dh", s.BlockListUpdateIntervalHours), utc(s.BlockListNextUpdatedOn)
		}
	}

	row.Console = fmt.Sprintf("http on %d", s.WebServiceHTTPPort)
	if s.WebServiceEnableTLS {
		row.Console += fmt.Sprintf(", https on %d", s.WebServiceTLSPort)
		if s.WebServiceUseSelfSignedCert {
			row.Console += " with a certificate it signed for itself"
		}
		if s.WebServiceHTTPToTLSRedirect {
			row.Console += ", http sent on to https"
		}
	}
	row.QueryLog = s.LoggingType
	if s.LoggingType == "File" || s.LoggingType == "FileAndConsole" {
		row.QueryLog += " in " + s.LogFolder
	}
	if s.LogQueries {
		row.QueryLog += ", queries logged"
	}

	// the apps are the Apps section's to show, which a token may not read
	apps, appsErr := srv.Client.Apps(ctx)
	if appsErr != nil {
		row.Note = "the installed apps could not be read: " + appsErr.Error()
	}
	for i := range apps {
		text := apps[i].Name + " " + apps[i].Version
		if apps[i].LogsQueries() {
			text += " (keeps a searchable log of queries)"
		}
		row.Apps = append(row.Apps, text)
	}

	return row, nil
}

// settingsDiffer names the settings two servers do not have alike.
func settingsDiffer(rows []settingsRow) []string {
	var read []*settingsRow
	for i := range rows {
		if rows[i].Error == "" {
			read = append(read, &rows[i])
		}
	}
	if len(read) < 2 {
		return nil
	}

	var out []string
	check := func(what string, of func(r *settingsRow) string) {
		for _, r := range read[1:] {
			if of(r) != of(read[0]) {
				out = append(out, what)

				return
			}
		}
	}
	list := func(of func(r *settingsRow) []string) func(r *settingsRow) string {
		return func(r *settingsRow) string { return strings.Join(of(r), "\x00") }
	}
	check("listens", list(func(r *settingsRow) []string { return r.Listens }))
	check("also", list(func(r *settingsRow) []string { return r.Also }))
	check("recursion", func(r *settingsRow) string { return r.Recursion + "\x00" + strings.Join(r.RecursionNetworks, "\x00") })
	check("forwarders", func(r *settingsRow) string {
		return r.ForwarderProtocol + "\x00" + strings.Join(r.Forwarders, "\x00") + "\x00" + r.Proxy
	})
	check("dnssec_validation", func(r *settingsRow) string { return strconv.FormatBool(r.DNSSECValidation) })
	check("qname_minimization", func(r *settingsRow) string { return strconv.FormatBool(r.QNameMinimization) })
	check("transfer_networks", list(func(r *settingsRow) []string { return r.TransferNetworks }))
	check("notify_networks", list(func(r *settingsRow) []string { return r.NotifyNetworks }))
	check("tsig_keys", list(func(r *settingsRow) []string { return r.TSIGKeys }))
	check("blocking", func(r *settingsRow) string { return r.Blocking })
	check("block_lists", func(r *settingsRow) string { return strings.Join(r.BlockLists, "\x00") + "\x00" + r.BlockListsEvery })
	check("default_ttl", func(r *settingsRow) string { return strconv.Itoa(r.DefaultTTL) })
	check("cache_negative_ttl", func(r *settingsRow) string { return strconv.Itoa(r.CacheNegativeTTL) })
	check("serve_stale", func(r *settingsRow) string { return strconv.FormatBool(r.ServeStale) })
	check("console", func(r *settingsRow) string { return r.Console })
	check("query_log", func(r *settingsRow) string { return r.QueryLog })
	check("apps", list(func(r *settingsRow) []string { return r.Apps }))

	return out
}

func registerSettingsTools(r *registry) {
	type serverSettingsOut struct {
		Servers []settingsRow `json:"servers"          jsonschema:"each configured server's settings, in the order configured"`
		Differ  []string      `json:"differ,omitempty" jsonschema:"the settings the servers do not have alike, by the name each has in a row. A cluster's nodes copy their settings from its primary, so there every one named here is a node that has not, or a setting each node keeps for itself"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "server_settings",
		Description: "How each configured server is set up, side by side: where it answers DNS and by which protocols, whose queries it resolves and through which forwarders, DNSSEC validation, who may transfer zones from it and its transfer keys by name, what it blocks and from which lists, its default TTL and how long it keeps a negative answer, where its console answers and whether over TLS, its log, and the DNS apps installed. No secret is among them: a transfer key is its name, and no password is read. It names the settings the servers do not have alike.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serverArg) (*mcp.CallToolResult, serverSettingsOut, error) {
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, serverSettingsOut{}, err
		}
		answers := ask(ctx, picked, settingsRowOf)
		if _, err := failures(answers); err != nil {
			return nil, serverSettingsOut{}, err
		}

		out := serverSettingsOut{Servers: make([]settingsRow, 0, len(answers))}
		for _, a := range answers {
			row := a.Value
			if a.Err != nil {
				row = settingsRow{Server: a.Server.Name, Error: a.Err.Error()}
			}
			out.Servers = append(out.Servers, row)
		}
		out.Differ = settingsDiffer(out.Servers)

		return nil, out, nil
	})
}
