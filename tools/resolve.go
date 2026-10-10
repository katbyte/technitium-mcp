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
	// askedItself is how an answer says a server answered the question
	// itself, as it would a client's
	askedItself = "itself"
	// resolverRecursive is what a resolvers entry asks for the server's own
	// recursion by
	resolverRecursive = "recursive"
)

// resolveRow is one answer to a question: one server's own, or what another
// name server told that server.
type resolveRow struct {
	Server string `json:"server"          jsonschema:"the configured server that put the question"`
	Asked  string `json:"asked"           jsonschema:"who answered: itself, the server answering as it would a client - its own zones, then its cache, its forwarders or recursion, its block lists applied; recursive, the server resolving from the root past all of those; or the address of the other name server it asked"`
	Error  string `json:"error,omitempty" jsonschema:"why there is no answer: the name server could not be reached, or the server would not ask"`

	Result    string   `json:"result,omitempty"      jsonschema:"how the question went: NoError, NxDomain (no such name), ServerFailure, Refused. NoError with no answers is a name that exists and has no record of the type asked for"`
	Answers   []string `json:"answers,omitempty"     jsonschema:"the values the name ends at: the records of the type asked for at the end of any chain"`
	Chain     []string `json:"chain,omitempty"       jsonschema:"when the name is a CNAME: each record of the answer in order, as name, type and value, down to the answers"`
	TTL       int      `json:"ttl,omitempty"         jsonschema:"the shortest TTL in the answer, in seconds: how long a client may keep it"`
	OwnZone   bool     `json:"own_zone,omitempty"    jsonschema:"the answer came from a zone the name server holds itself; absent, it came from its cache, a forwarder or recursion"`
	Validated bool     `json:"validated,omitempty"   jsonschema:"the answer was validated with DNSSEC"`
	Blocked   string   `json:"blocked,omitempty"     jsonschema:"the name server says it blocked the name, and by what: an entry on its own list of blocked names, or one on a block list it fetches, named by its address. A blocked name is answered as one that does not exist, or with an address that leads nowhere"`
	Answered  string   `json:"answered_by,omitempty" jsonschema:"the name server that answered, as the server that asked names it"`
	Took      string   `json:"took,omitempty"        jsonschema:"how long the answer took to come"`
}

// same reports whether two answers say the same thing of the name.
func (r *resolveRow) same(o *resolveRow) bool {
	return r.Error == "" && o.Error == "" && r.Result == o.Result && slices.Equal(r.Answers, o.Answers) && (r.Blocked == "") == (o.Blocked == "")
}

// resolveRowOf puts one question to one name server through one configured
// server.
func resolveRowOf(ctx context.Context, srv *servers.Server, asked, name, recordType string, dnssec bool) resolveRow {
	row := resolveRow{Server: srv.Name, Asked: asked}
	via := asked
	switch asked {
	case askedItself:
		via = technitium.ResolveThisServer
	case resolverRecursive:
		via = technitium.ResolveRecursively
	default:
	}

	res, err := srv.Client.Resolve(ctx, technitium.ResolveQuery{Via: via, Name: name, Type: recordType, DNSSEC: dnssec})
	if err != nil {
		row.Error = err.Error()

		return row
	}
	row.Result, row.OwnZone, row.Validated, row.Answered, row.Took = res.RCode, res.Authoritative, res.AuthenticData, res.Metadata.NameServer, res.Metadata.RoundTripTime
	if b := res.Blocked(); b != nil {
		row.Blocked = blockedBy(b)
	}

	aliased := false
	for i := range res.Answer {
		rec := &res.Answer[i]
		if rec.Type == "RRSIG" {
			continue
		}
		if ttl := rec.TTL(); row.TTL == 0 || ttl < row.TTL {
			row.TTL = ttl
		}
		row.Chain = append(row.Chain, rec.Name+" "+rec.Type+" "+rec.Value())
		// a CNAME is on the way to the answer unless a CNAME is what was asked for
		if rec.Type == "CNAME" && !strings.EqualFold(recordType, "CNAME") && !strings.EqualFold(recordType, "ANY") {
			aliased = true

			continue
		}
		row.Answers = append(row.Answers, rec.Value())
	}
	slices.Sort(row.Answers)
	if !aliased {
		row.Chain = nil
	}

	return row
}

func registerResolveTools(r *registry) {
	type resolveIn struct {
		serverArg

		Name      string   `json:"name"                jsonschema:"the domain name to resolve; for the name an address has, give the address"`
		Type      string   `json:"type,omitempty"      jsonschema:"the record type to ask for: A (the default), AAAA, CNAME, MX, TXT, PTR, NS, SOA, SRV, ANY, ...; PTR is asked when name is an address"`
		Resolvers []string `json:"resolvers,omitempty" jsonschema:"other name servers to put the same question to, from each server, for comparison with its own answer: the address of a public resolver such as 1.1.1.1 or 8.8.8.8 to see what the outside world is told, or recursive to have the server resolve from the root past its own zones, cache, forwarders and block lists"`
		DNSSEC    bool     `json:"dnssec,omitempty"    jsonschema:"ask for DNSSEC validation"`
	}
	type resolveOut struct {
		Name    string       `json:"name"`
		Type    string       `json:"type"`
		Answers []resolveRow `json:"answers"          jsonschema:"each server's own answer first, then what each other name server asked told it"`
		Differ  bool         `json:"differ,omitempty" jsonschema:"the configured servers' own answers are not the same: the name resolves differently depending on which a client asks"`
		Note    string       `json:"note,omitempty"`
	}
	add(r, readTool, &mcp.Tool{
		Name:        "dns_resolve",
		Description: "Resolve a name on each configured server as a client of it would be answered, side by side: how it went, what the name ends at, every CNAME on the way, the shortest TTL, and whether the answer came from a zone the server holds or from its cache or upstream. This is what the servers really answer, where audit_names and record_find read what their zones hold. resolvers puts the same question to other name servers from each server - a public resolver, to see what the outside world is told for a split-horizon name, or the server's own recursion. A name a server blocks is said to be blocked, and by which list. An address is resolved to its name.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in resolveIn) (*mcp.CallToolResult, resolveOut, error) {
		name := strings.TrimSuffix(strings.TrimSpace(in.Name), ".")
		if name == "" {
			return nil, resolveOut{}, errors.New("which name: give the domain name to resolve")
		}
		recordType := strings.ToUpper(strings.TrimSpace(in.Type))
		// an address is asked for its name, at the name its PTR is at
		if addr, ok := parseAddr(name); ok {
			if recordType != "" && recordType != "PTR" {
				return nil, resolveOut{}, fmt.Errorf("%s is an address, which has a PTR record at %s and no %s: leave type out", name, reverseName(addr), recordType)
			}
			name, recordType = reverseName(addr), "PTR"
		}
		if recordType == "" {
			recordType = "A"
		}
		picked, err := r.servers.Pick(in.Server)
		if err != nil {
			return nil, resolveOut{}, err
		}

		asked := []string{askedItself}
		for _, resolver := range in.Resolvers {
			if resolver = strings.TrimSpace(resolver); resolver != "" && !slices.Contains(asked, resolver) {
				asked = append(asked, resolver)
			}
		}

		// every server is asked at once, and each puts its questions in turn
		answers := ask(ctx, picked, func(ctx context.Context, srv *servers.Server) ([]resolveRow, error) {
			rows := make([]resolveRow, 0, len(asked))
			for _, who := range asked {
				rows = append(rows, resolveRowOf(ctx, srv, who, name, recordType, in.DNSSEC))
			}

			return rows, nil
		})

		out := resolveOut{Name: name, Type: recordType}
		for i := range asked {
			for _, a := range answers {
				out.Answers = append(out.Answers, a.Value[i])
			}
		}
		own := out.Answers[:len(picked)]
		out.Differ = slices.ContainsFunc(own, func(row resolveRow) bool { return row.Error == "" && own[0].Error == "" && !row.same(&own[0]) })
		if slices.ContainsFunc(own, func(row resolveRow) bool { return row.Error != "" }) {
			out.Note = "a server could not answer for itself, so whether the servers agree is not known for it: its row says why"
		}

		return nil, out, nil
	})
}
