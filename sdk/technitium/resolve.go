package technitium

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Who a server can be asked to put a query to.
const (
	// ResolveThisServer asks the server itself, as a client of it would:
	// its own zones first, then its cache, its forwarders or recursion, with
	// its block lists applied
	ResolveThisServer = "this-server"
	// ResolveRecursively has the server resolve from the root, past its own
	// zones, cache, forwarders and block lists
	ResolveRecursively = "recursive-resolver"
)

// ResolveQuery is a question for a server to put to a name server.
type ResolveQuery struct {
	// Via is who answers: ResolveThisServer, ResolveRecursively, or the
	// address of any name server, which the server asks from where it is
	Via string
	// Name and Type are the question: emby.example.com, A
	Name, Type string
	// Protocol is Udp (the default), Tcp, Tls, Https or Quic
	Protocol string
	// DNSSEC asks for validation
	DNSSEC bool
	// ClientSubnet is a network the question is asked as if from, 203.0.113.0/24
	// say: what a name server that answers by where the asker is would tell
	// a client there
	ClientSubnet string
}

// Resolution is a name server's answer to a query, as the server that asked
// it got it.
type Resolution struct {
	Metadata struct {
		// NameServer is who answered: a name and its address
		NameServer string `json:"NameServer"`
		Protocol   string `json:"Protocol"`
		// RoundTripTime is how long the answer took, as the server writes
		// it: 16.24 ms
		RoundTripTime string `json:"RoundTripTime"`
	} `json:"Metadata"`
	// RCode is how the query went: NoError, NxDomain, ServerFailure, Refused
	RCode string `json:"RCODE"`
	// Authoritative is the answer coming from a zone the name server holds
	// itself, not from its cache or from another server
	Authoritative bool `json:"AuthoritativeAnswer"`
	Truncated     bool `json:"Truncation"`
	// AuthenticData is the answer having been validated with DNSSEC
	AuthenticData bool             `json:"AuthenticData"`
	Answer        []ResolvedRecord `json:"Answer"`
	Authority     []ResolvedRecord `json:"Authority"`
	Additional    []ResolvedRecord `json:"Additional"`
	// EDNS is what the answer carries beside its records: among it, the
	// name server's own word on why it answered as it did
	EDNS struct {
		Options []struct {
			Code string `json:"Code"`
			Data struct {
				InfoCode  string `json:"InfoCode"`
				ExtraText string `json:"ExtraText"`
			} `json:"Data"`
		} `json:"Options"`
	} `json:"EDNS"`
}

// Block is why a name server refused a name, as its answer says: a
// Technitium server says which of its lists the name is on.
type Block struct {
	// Source is where the entry is: BlockedZone for the server's own list
	// of blocked names, BlockList for a list it fetches, and for anything
	// else - an app's - the server's own word
	Source string
	// List is the address of the list the entry is on, for a fetched one
	List string
	// Entry is the name that is blocked: the name asked for, or one above it
	Entry string
	// Text is the whole of what the server said
	Text string
}

// Where a blocked name's entry is.
const (
	BlockedZone = "blocked-zone"
	BlockList   = "block-list-zone"
)

// Blocked is why the name server blocked the name, nil for an answer that
// does not say it was blocked.
func (r *Resolution) Blocked() *Block {
	for _, option := range r.EDNS.Options {
		if option.Code != "EXTENDED_DNS_ERROR" || option.Data.InfoCode != "Blocked" {
			continue
		}
		block := &Block{Text: option.Data.ExtraText}
		// source=block-list-zone; blockListUrl=https://example.com/list.txt; domain=ads.example.com
		for part := range strings.SplitSeq(option.Data.ExtraText, ";") {
			key, value, _ := strings.Cut(strings.TrimSpace(part), "=")
			switch key {
			case "source":
				block.Source = value
			case "blockListUrl":
				block.List = value
			case "domain":
				block.Entry = value
			default:
			}
		}

		return block
	}

	return nil
}

// ResolvedRecord is one record of an answer. Its data is laid out as a DNS
// message's is, which is not how a zone's record carries the same data:
// IPAddress where a zone's record has ipAddress, Domain for a CNAME's target.
type ResolvedRecord struct {
	Name string `json:"Name"`
	Type string `json:"Type"`
	// TTLText is the TTL as the server writes it, with its length in words:
	// 3600 (1h)
	TTLText string `json:"TTL"`
	Data    RData  `json:"RDATA"`
}

// TTL is the record's TTL in seconds.
func (r *ResolvedRecord) TTL() int { return leadingInt(r.TTLText) }

// leadingInt is the number a text begins with, 0 when it begins with none.
func leadingInt(s string) int {
	digits, _, _ := strings.Cut(strings.TrimSpace(s), " ")
	n, _ := strconv.Atoi(digits)

	return n
}

// resolvedFields are the fields that make up an answer record's value, by
// type, in the order a zone file writes them.
var resolvedFields = map[string][]string{
	"A":     {"IPAddress"},
	"AAAA":  {"IPAddress"},
	"NS":    {"NameServer"},
	"CNAME": {"Domain"},
	"PTR":   {"Domain"},
	"DNAME": {"Domain"},
	"MX":    {"Preference", "Exchange"},
	"TXT":   {"Text"},
	"SRV":   {"Priority", "Weight", "Port", "Target"},
	"SOA":   {"PrimaryNameServer", "ResponsiblePerson", "Serial", "Refresh", "Retry", "Expire", "Minimum"},
	"CAA":   {"Flags", "Tag", "Value"},
}

// resolvedTarget is the field holding the name an answer record points at.
var resolvedTarget = map[string]string{"NS": "NameServer", "CNAME": "Domain", "PTR": "Domain", "DNAME": "Domain", "MX": "Exchange", "SRV": "Target"}

// Value is the record's data on one line, as a zone file would write it; a
// type this client has no layout for is written as its fields by name.
func (r *ResolvedRecord) Value() string {
	fields, ok := resolvedFields[r.Type]
	if !ok {
		names := make([]string, 0, len(r.Data))
		for name := range r.Data {
			names = append(names, name)
		}
		slices.Sort(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, fmt.Sprintf("%s=%v", name, r.Data[name]))
		}

		return strings.Join(parts, " ")
	}

	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		text := r.Data.field(f)
		// an SOA's times come with their length in words: 900 (15m)
		if r.Type == "SOA" && strings.Contains(text, " (") {
			text, _, _ = strings.Cut(text, " ")
		}
		parts = append(parts, text)
	}

	return strings.Join(parts, " ")
}

// Target is the domain name the record points at, "" for a type that points
// at none.
func (r *ResolvedRecord) Target() string { return r.Data.field(resolvedTarget[r.Type]) }

// Address is the address of an A or an AAAA record.
func (r *ResolvedRecord) Address() (netip.Addr, bool) {
	if r.Type != "A" && r.Type != "AAAA" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(r.Data.field("IPAddress"))

	return addr, err == nil
}

// Resolve has the server put a query to a name server - itself, by default -
// and returns the answer: what a client of the server would be told. A name
// that does not exist is an answer, with its RCode, and no error.
func (c *Client) Resolve(ctx context.Context, q ResolveQuery) (*Resolution, error) {
	if q.Name == "" {
		return nil, errors.New("dnsClient/resolve: which name")
	}
	params := url.Values{"domain": {q.Name}, "server": {q.Via}, "type": {q.Type}}
	if q.Via == "" {
		params.Set("server", ResolveThisServer)
	}
	if q.Type == "" {
		params.Set("type", "A")
	}
	if q.Protocol != "" {
		params.Set("protocol", q.Protocol)
	}
	if q.DNSSEC {
		params.Set("dnssec", yes)
	}
	set(params, map[string]string{"eDnsClientSubnet": q.ClientSubnet})

	var out struct {
		Result Resolution `json:"result"`
	}
	if err := c.read(ctx, "dnsClient/resolve", params, &out); err != nil {
		return nil, err
	}

	return &out.Result, nil
}

// ImportResolved asks a question as Resolve does and writes the records of
// the answer into a zone of the server's own: the closest primary or
// forwarder zone it holds for the name, or a new primary zone made for it.
// It is how a zone held elsewhere is copied in a record set at a time, and
// it changes the server where Resolve only asks.
func (c *Client) ImportResolved(ctx context.Context, q ResolveQuery) (*Resolution, error) {
	if q.Name == "" {
		return nil, errors.New("dnsClient/resolve: which name")
	}
	params := url.Values{"domain": {q.Name}, "server": {q.Via}, "type": {q.Type}, "import": {yes}}
	if q.Via == "" {
		params.Set("server", ResolveRecursively)
	}
	if q.Type == "" {
		params.Set("type", "A")
	}
	set(params, map[string]string{"protocol": q.Protocol, "eDnsClientSubnet": q.ClientSubnet})
	if q.DNSSEC {
		params.Set("dnssec", yes)
	}

	var out struct {
		Result Resolution `json:"result"`
	}
	if err := c.write(ctx, "dnsClient/resolve", params, &out); err != nil {
		return nil, err
	}

	return &out.Result, nil
}

// HealthCheck asks the server to resolve a name for itself, which answers
// whether it is running and can resolve at all; nothing of it is written to
// the log of queries. "" asks for localhost, and no type for an A record.
func (c *Client) HealthCheck(ctx context.Context, name, recordType string) error {
	params := url.Values{}
	set(params, map[string]string{"domain": name, "type": recordType})

	return c.read(ctx, "dnsClient/healthCheck", params, nil)
}
