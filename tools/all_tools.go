// Package tools defines the MCP tools exposed by technitium-mcp, split by the
// resource they act on (server.go, zones.go, ...). Tools are named
// resource-first (server_*, zone_*, record_*, audit_*) so they group by what
// they act on.
//
// Every tool is about one or more of the configured servers, named by its
// server argument: a read asks every server unless one is named and sets the
// answers side by side, and a change is made on one named server at a time.
//
// Every tool is registered through add with a kind: read tools never change a
// server, write tools do and are only registered with --enable-write, and
// delete tools remove what cannot be put back and are only registered with
// --enable-delete as well. A session reads until it is told it may do more:
// these are DNS servers, and a wrong change takes a network's names away.
// --toolsets picks the groups a session needs, --allow-tools adds tools to
// them by name, and --deny-tools takes tools away.
package tools

import (
	"errors"

	mcpregistry "github.com/katbyte/go-kt/mcp/registry"
	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Options controls which tools are registered.
type Options struct {
	// EnableWrite registers the tools that change a server. Off unless the
	// operator opts in: with nothing said, a session can only read.
	EnableWrite bool
	// EnableDelete registers the tools that delete. A delete is a change, so
	// it needs EnableWrite too, and is refused without it rather than
	// quietly registering nothing.
	EnableDelete bool
	// Toolsets, when set, restricts registration to the named groups (see
	// Toolsets). "core" is always included, so a set can be asked for on its
	// own. Allow adds to them and Deny takes away.
	Toolsets []string
	// Allow names tools to register: exact names, prefix/suffix globs
	// (zone_*, *_delete) or the "essential" preset. Beside Toolsets it adds
	// those tools to the sets, wherever they belong: the sets plus these.
	// With no Toolsets it is the whole choice, and only the tools it names
	// are registered, core not among them unless named. A name or pattern
	// that matches no tool is refused rather than registering nothing.
	Allow []string
	// Deny removes matching tools from whatever the two above chose: it is
	// how a set is narrowed.
	Deny []string
}

// Toolsets group the tools by the job someone is doing, so a client can load a
// working subset instead of all of them: every tool's definition (name,
// description, input schema) is spent from a client's context before anyone
// has asked a question.
//
// "all" is every tool, which is what the library does when no toolset is asked
// for; the technitium-mcp binary defaults to core instead (see
// cli.FlagData.ToolOptions).
//
// --toolsets also takes a resource family - server, zone, record, dns, cache, dhcp, block, log, audit - which is every
// tool with that prefix. Those are derived from the registered names rather
// than listed here, so they cannot go stale.
//
// Every tool belongs to exactly one set (TestToolsetsPartition proves it), and
// core is added to whatever else is asked for, because none of the other sets
// can find a zone or read a record on their own.
var Toolsets = map[string][]string{
	// enough to see what the servers are and what they hold: the base every
	// other set assumes
	mcpregistry.Core: {
		"server_info", "zone_list", "zone_records", "record_find", "dns_resolve", "cache_get",
		// an audit by its name, and asked all day: does each of these host
		// names have a record
		"audit_names",
	},
	// find what is wrong: each audit reads every zone whole and answers
	// with what it found at fault, and audit_all with how much each found
	"audit": {
		"audit_all", "audit_servers", "audit_targets", "audit_reverse", "audit_overlaps", "audit_naming", "audit_state", "audit_dhcp", "audit_blocking", "audit_zones", "audit_security", "audit_split",
	},
	// how the servers are set up and what they are doing
	"ops": {
		"server_settings", "server_stats", "log_search", "zone_get", "zone_export",
	},
	// what the servers refuse to resolve, and why: their lists of blocked
	// and allowed names, and with --enable-write the entries on them
	"block": {
		"block_check", "block_list", "block_set", "block_delete", "block_switch", "block_lists_set",
	},
	// the addresses the servers lease: who has which, and with
	// --enable-write keeping one for a machine
	"dhcp": {
		"dhcp_scopes", "dhcp_leases", "dhcp_reservation_set", "dhcp_reservation_delete", "dhcp_lease_delete", "dhcp_scope_set",
	},
	// change what the zones hold: every tool here needs --enable-write
	"edit": {
		"record_set", "record_delete", "record_repoint", "cache_flush", "zone_create", "zone_edit", "zone_resync",
	},
}

// ToolsetOrder is the order a listing shows the sets in: the base first.
var ToolsetOrder = []string{mcpregistry.Core, "audit", "ops", "block", "dhcp", "edit"}

// EssentialTools is the curated preset selected by --allow-tools essential:
// enough to see what the servers are and read what they hold.
var EssentialTools = []string{
	"server_info",
	"zone_list",
	"zone_records",
}

// The kinds a tool is added with, in go-kt's registry's terms: a read tool
// never changes what a server holds, a write tool does, and a delete tool
// removes what cannot be put back.
const (
	readTool   = mcpregistry.Read
	writeTool  = mcpregistry.Write
	deleteTool = mcpregistry.Delete
)

// registry is this application's tools and what they share. Which of them a
// session gets, and what each tells a client about itself, is go-kt's
// registry's work, so the allow and deny patterns are checked against every
// tool before any is registered.
type registry struct {
	servers *servers.Set
	opts    Options
	// tools holds every tool queued, made when the first is (see queued)
	tools *mcpregistry.Registry
	// errorLog is where a handler's panic is logged; nil is the process's
	// log
	errorLog func(format string, args ...any)
}

// toolHints are what a tool tells a client about itself beyond its kind, in
// the MCP annotations' terms. A write tool is destructive when it can change
// or take away what was there and additive when it only ever adds; idempotent
// when calling it again with the same arguments changes nothing more.
//
// Every write tool has an entry, each decided on its own rather than taken
// from the kind. A write tool missing from here is marked destructive, and
// fails TestEveryWriteToolIsHinted.
var toolHints = map[string]mcpregistry.Hints{
	// a value, a TTL or a comment written over, and with only the other
	// records of the type removed; the same again changes nothing more
	"record_set": {Idempotent: true},
	// addresses written over and PTRs moved; run again, nothing holds the
	// old address and nothing more is done
	"record_repoint": {Idempotent: true},
	// kept answers dropped, which the next query fetches again; a second
	// drop finds nothing
	"cache_flush": {Idempotent: true},
	// a reservation's address, name or comment written over; the same again
	// finds it so and changes nothing
	"dhcp_reservation_set": {Idempotent: true},
	// a name put on a list, which takes nothing off it; the same again
	// finds it there
	"block_set": {Additive: true, Idempotent: true},
	// a zone made, which takes away nothing that was there; made again, it
	// is found there
	"zone_create": {Additive: true, Idempotent: true},
	// options and an SOA written over; the same again finds them so
	"zone_edit": {Idempotent: true},
	// a transfer asked for, which changes nothing but how fresh the copy is
	"zone_resync": {Idempotent: true},
	// a scope made or written over, and switched on or off; the same again
	// finds it so
	"dhcp_scope_set": {Idempotent: true},
	// blocking switched; the same again finds it so, but a pause asked for
	// again starts over
	"block_switch": {},
	// the set of lists written over; the same again finds it so
	"block_lists_set": {Idempotent: true},
}

// queued is every tool queued so far, in go-kt's registry, which is made
// when the first tool is.
func (r *registry) queued() *mcpregistry.Registry {
	if r.tools == nil {
		r.tools = mcpregistry.New(mcpregistry.Config{
			Toolsets:  Toolsets,
			Essential: EssentialTools,
			Hints:     toolHints,
			LogError:  r.errorLog,
		})
	}

	return r.tools
}

// add queues a typed tool for registration. go-kt's registry sets the MCP
// annotations from kind and the tool's hints so clients can tell read-only
// from destructive tools without parsing descriptions, turns a panic in the
// handler into an ordinary tool error, and sends empty collections as []
// rather than null: an AI client reading "zones": null cannot tell "none"
// from "not fetched", and Go leaves un-appended slices nil.
func add[In, Out any](r *registry, kind mcpregistry.Kind, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	mcpregistry.Add(r.queued(), kind, t, h)
}

// RegisterAll adds every tool permitted by opts to the MCP server and returns
// the names registered. It fails when an allow/deny pattern matches no tool,
// so a typo cannot silently hide one.
func RegisterAll(server *mcp.Server, set *servers.Set, opts Options) ([]string, error) {
	if err := opts.check(); err != nil {
		return nil, err
	}
	r := &registry{servers: set, opts: opts}
	queueTools(r)

	return r.queued().Register(server, opts.selection())
}

// check refuses options that contradict themselves.
func (o *Options) check() error {
	if o.EnableDelete && !o.EnableWrite {
		return errors.New("--enable-delete needs --enable-write (TECHNITIUM_ENABLE_WRITE=true) beside it: a delete is a change, and no change is made without that")
	}

	return nil
}

// selection is the part of the options that chooses tools, as go-kt's
// registry takes it: its read-only is this application's default, which
// enabling writes lifts.
func (o *Options) selection() mcpregistry.Selection {
	return mcpregistry.Selection{
		ReadOnly:     !o.EnableWrite,
		EnableDelete: o.EnableDelete,
		Toolsets:     o.Toolsets,
		Allow:        o.Allow,
		Deny:         o.Deny,
	}
}

// queueTools queues every tool, before any filtering.
func queueTools(r *registry) {
	registerServerTools(r)
	registerSettingsTools(r)
	registerZoneTools(r)
	registerRecordTools(r)
	registerRecordWriteTools(r)
	registerRepointTool(r)
	registerResolveTools(r)
	registerCacheTools(r)
	registerDHCPTools(r)
	registerDHCPWriteTools(r)
	registerBlockingTools(r)
	registerStatsTools(r)
	registerLogTools(r)
	registerZoneSetupTools(r)
	registerZoneWriteTools(r)
	registerDHCPScopeTools(r)
	registerBlockingWriteTools(r)
	registerSplitAudit(r)
	registerNameAudit(r)
	registerAudits(r)
}

// ToolInfo describes a registered tool without a server to register it on.
type ToolInfo = mcpregistry.Info

// described is every tool queued with no server behind it, for the answers
// that need none: registration never calls a client, only the handlers do.
func described(opts Options) (*mcpregistry.Registry, error) {
	set, err := servers.New([]string{"https://describe.invalid"}, []string{"describe"})
	if err != nil {
		return nil, err
	}
	r := &registry{servers: set, opts: opts}
	queueTools(r)

	return r.queued(), nil
}

// Describe lists the tools opts would register, for `technitium-mcp tools`.
// It needs no connectivity, and makes the same choice RegisterAll does.
func Describe(opts Options) ([]ToolInfo, error) {
	if err := opts.check(); err != nil {
		return nil, err
	}
	reg, err := described(opts)
	if err != nil {
		return nil, err
	}

	return reg.Describe(opts.selection())
}

// ToolsetNames lists the curated toolsets, for help output.
func ToolsetNames() []string {
	return mcpregistry.New(mcpregistry.Config{Toolsets: Toolsets}).ToolsetNames()
}

// FamilyNames lists the resource prefixes accepted by --toolsets, for help
// output.
func FamilyNames() []string {
	reg, err := described(Options{})
	if err != nil {
		return nil
	}

	return reg.FamilyNames()
}
