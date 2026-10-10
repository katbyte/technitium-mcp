# technitium-mcp - a Technitium DNS Server MCP server, CLI and Go SDK

[![GitHub release](https://img.shields.io/github/v/release/katbyte/technitium-mcp?color=blueviolet)](https://github.com/katbyte/technitium-mcp/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/katbyte/technitium-mcp?color=00ADD8)](https://github.com/katbyte/technitium-mcp/blob/main/go.mod)
[![License](https://img.shields.io/github/license/katbyte/technitium-mcp?color=blue)](https://github.com/katbyte/technitium-mcp/blob/main/LICENSE)
![build](https://github.com/katbyte/technitium-mcp/actions/workflows/build.yaml/badge.svg)
![tests](https://github.com/katbyte/technitium-mcp/actions/workflows/pr-integration.yaml/badge.svg)
![lint](https://github.com/katbyte/technitium-mcp/actions/workflows/pr-golangci-lint.yaml/badge.svg)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/katbyte/technitium-mcp/badges/coverage.json)](https://github.com/katbyte/technitium-mcp/actions/workflows/coverage.yaml)

An [MCP](https://modelcontextprotocol.io) server, CLI and Go SDK for [Technitium DNS Server](https://technitium.com/dns/), so a model working on a network can see what its DNS servers hold, compare servers that are meant to agree, and find what is wrong - from Claude Code, Claude Desktop, or any other MCP client - without falling back to `dig` and guesswork.

Wrapping the API lets a model browse a DNS server. The reason this exists is the layer above: **audits**, each a sweep over every zone on every server for one kind of thing that goes wrong - a zone one server has and the other does not, a CNAME to a name with no record, an address whose PTR names another host, a record that is never served because a zone further down answers instead - returning a worklist with the fix beside each finding.

**It is early.** Forty-three tools are built and tested against real servers. What is still wanted is listed in [docs/ROADMAP.md](docs/ROADMAP.md).

### What is in the box

- **Several servers, side by side.** One process works on every server you name. A read asks all of them and sets the answers beside each other, so a zone one server lacks, or a record two servers hold differently, shows without comparing by hand. A server that is down is said beside the answers of the ones that are up.
- **A Go SDK.** `sdk/technitium` is a typed client for the Technitium API, standard library and [go-kt](https://github.com/katbyte/go-kt) only, with no knowledge of MCP. Technitium publishes no OpenAPI document, so it is written by hand from the server's API document, which is vendored under [api-defs/](api-defs/README.md) and held against the client by the tests: every call, and every parameter sent.
- **Tested against real servers, three ways.** Every tool and every SDK method runs against real Technitium servers in Docker: on one server, on two that know nothing of each other, and on two made a cluster through the API during the run. Each run fails if a registered tool was never seen to answer. The leases the DHCP tools are tested on are real ones: a small DHCP client is run on the test servers' own network and asks for them.

### The audits

| audit | what it finds |
|---|---|
| `audit_all` | every audit in one reading of the zones, counts only: where to look first |
| `audit_servers` | where servers meant to hold the same do not: a zone one lacks (and, in a cluster, that it is not in the catalog the other node follows), a zone two servers each hold as their own primary, the records that differ, a copy behind its primary or whose transfer failed or that has expired |
| `audit_targets` | records that point at a name and end nowhere: a CNAME to a name with no record, a loop, a long chain, a CNAME at a zone's own name or beside other records, an MX, SRV or NS whose target is missing or is a CNAME |
| `audit_reverse` | addresses and PTRs that disagree: an address with no PTR (with the call that adds it), a PTR naming a host that does not hold the address, several PTRs for one address, a network with addresses in use and no reverse zone |
| `audit_overlaps` | records never served because a zone further down on the same server answers for the name; one name with addresses in two networks; the odd public address in a zone of private ones, or the reverse; and every wildcard, which makes a mistyped name resolve |
| `audit_naming` | probable slips: a stray space or invisible character, an underscore in a host name, two names a typing slip apart, a TTL under a minute, over a week, or far from the one the rest of its zone has, and one host's names written two ways (`emby-dock` beside `jf.dock`) |
| `audit_state` | what is switched off or set to vanish: disabled zones and records, records set to delete themselves |
| `audit_zones` | a zone's own records and options against the servers that hold it: a name server it names that is none of them, a holder none of its NS records names, an SOA naming a primary that is not the server holding it as one - what a renamed server leaves behind - and a primary that gives its copies no transfer or no word of a change |
| `audit_security` | what is left open: a server resolving for anyone, a console over plain HTTP alone, the password a server ships with, a zone anyone may transfer or change with no key, an API token unused for ninety days, a server behind the version that is out |
| `audit_split` | the inside and the outside of a split horizon, by asking a resolver you name for every name the zones hold: an override whose public name is gone, a private address the outside is given, a name that resolves outside and has no record here, and a parallel domain that does not answer as the zone it mirrors. Not part of `audit_all`: it asks other people's name servers |
| `audit_blocking` | what the servers block: blocking switched off or paused with lists still set, block lists not fetched or holding nothing, a blocked name that blocks nothing because a zone on the server answers for it or an allowed entry wins, an entry another already stands for, and servers that do not block alike |
| `audit_dhcp` | DHCP against itself and against the zones: one server leasing alone, two leasing the same addresses, a scope running out or naming name servers that are not these, reservations that cannot work or have no name in DNS, a record made by hand at an address a scope gives out or has given to another machine, and records the server wrote for a lease that is gone |
| `audit_names` | a list of host names - every name a reverse proxy routes - each said to have records and where it ends, or why not |

### The tools

| tool | what it answers |
|---|---|
| `server_info` | each configured server: the name it is configured under, its own domain name, version, whether an update is out, when it started, its cluster, and the account the token acts as with what that account may not read, change or delete. A server that cannot be reached is listed with the reason. Start here |
| `zone_list` | the zones on every server, one row a zone: its type, serial, whether disabled or signed, when it last changed, a secondary's transfer state - as each server holds it, with which servers lack it and what differs between the copies. `counts` adds each copy's size |
| `zone_records` | one zone's records from every server holding it, as one table: a record held alike is one row, and one only some servers hold (or hold with another TTL or comment) names them. Filters by type, name, value, comment and state; `summary` for counts; `limit` and `offset` to page |
| `record_find` | records across every zone at once. By address: what holds it, its PTR, and everything that ends at it through a chain of CNAMEs - what a change of address would touch, or whether an address is free. By target: what points at a name. Or by name, value, type or comment |
| `dns_resolve` | what each server really answers for a name, side by side: the result, every CNAME on the way, the TTL, whether it came from its own zone, and when the server blocked it, by which list. Asks other resolvers the same from each server, to see what the outside world is told |
| `cache_get` | what each server's cache is keeping for a name: the answer, how long it has left, where it came from, and whether it is the answer that the name does not exist |
| `server_settings` | how each server is set up, side by side, and which settings they do not have alike: where it answers, whose queries it resolves and through what, transfers and keys by name, blocking, TTLs, console, log, apps. No secret is among them |
| `server_stats` | what each server did over the last hour, day, week, month or year, or between two times: queries and clients, how they were answered and from where, the part that failed, did not exist or was blocked, and the clients and names that lead |
| `zone_get` | how one zone is served and copied on each server holding it: its type and catalog, what its SOA and NS records name, who may ask, transfer and update and with which keys, who is told of a change, and for a copy where it transfers from |
| `zone_export` | one zone whole as a zone file, comments included: a copy to keep before a change, or to take elsewhere |
| `log_search` | the servers' logs of the queries they answered: who asked for what, when, and what they were told, filtered by name, client, type, result, source and time - or counted by client or by name, for who is still asking for an old name and which names do not exist. Needs the Query Logs app on the server, and says so when it is missing |
| `block_check` | whether each server blocks a name and what makes it so: its own blocked list or a block list it fetches, by entry; and for an entry that does not block the name, why not - an allowed entry over it, blocking off or paused, or a zone on the server answering for the name |
| `block_list` | how each server's blocking stands - on, off or paused, how a blocked name is answered, the lists fetched and how many names they hold - and every entry of its own blocked and allowed lists, with what the servers do not have alike |
| `dhcp_scopes` | each server's DHCP scopes: the range and what it leaves out, whether it is on and on which address, the gateway, name servers and domain machines are given, whether leases are recorded in DNS, and how many addresses are free, leased and reserved. Says which servers lease at all |
| `dhcp_leases` | the machines: every lease, dynamic or reserved, with hardware address, name and expiry, and every reservation nobody holds. `find` looks one up by name, address or hardware address however it is written: what has this address, where is this machine |

With `--enable-write`:

| tool | what it does |
|---|---|
| `record_set` | makes a record be there with the value given: added, changed in place, or left alone when it already is. Keeps the TTL and comment of what it changes, and of the records beside it, which the server would drop. `only` makes it the single record of its type; `ptr` sets the PTR too; `dry_run` says what would be done. Refuses a server that holds only a copy of the zone, saying where to make the change |
| `record_repoint` | moves every record at one address to another across all zones, with the PTRs: for a host that changes address. Refused when the new address belongs to another name unless `share` says so; `dry_run` lists every change |
| `cache_flush` | drops what a cache keeps for a name and everything under it, on one server or all |
| `zone_create` | makes a zone: a primary, a secondary that copies another server's, or a forwarder; a reverse zone by its network (`10.0.0.0/24`); a member of a cluster's catalog when asked. Says what else it does: takes names over from a zone above, and can empty the server's cache |
| `zone_edit` | changes how a zone is served: who may ask, transfer and update it and with which lists, who is told of a change, on or off, its catalog, and what its SOA says. Reads the zone back, because the server says ok to options it does not take |
| `zone_resync` | has a server transfer its copy of a zone from the primary again now |
| `dhcp_scope_set` | makes a DHCP scope or changes one: range, exclusions, lease time, gateway, name servers, domain, on or off. A new scope is left off unless asked otherwise, and a range another server here already leases is refused for a scope that is to be on |
| `block_switch` | switches blocking on or off, or pauses it for some minutes: the way to find out whether blocking is what breaks something |
| `block_lists_set` | sets the block lists a server fetches, whole or one at a time, and has it fetch them now |
| `block_set` | puts a name on a server's blocked list, or on its allowed list to let it past whatever blocks it; then asks the server for the name and says whether it is blocked now, and if a blocked entry does nothing, why |
| `dhcp_reservation_set` | keeps an address for a machine: pin this host. Added, replaced, or left alone when it already is. Refuses what the server would take and could not work: an address outside the scope's network, the server's or the gateway's, one kept for or held by another machine. Says, before it is done, when the server will write the name over a record made by hand |
| `record_delete` | (also needs `--enable-delete`) deletes a record and answers with it as it was, which is what puts it back |
| `block_delete` | (also needs `--enable-delete`) takes an entry off the blocked or the allowed list, and says how the name stands afterwards: a block list can block it still |
| `dhcp_reservation_delete` | (also needs `--enable-delete`) removes a reservation and answers with it as it was, and with the records the server took out of DNS with it |
| `dhcp_lease_delete` | (also needs `--enable-delete`) has a server forget a lease, for a machine that is gone. The server drops a reservation with its lease; this puts the reservation back |

## Setup

Make an API token on each server: web console, Administration, Sessions, Create Token. The token acts as the user it is made for. A user who is not an administrator sees no zones unless each zone's own permissions name them, so an administrator's token is the simple way: technitium-mcp only reads unless `--enable-write` is given. The server must be 15.0 or newer.

Settings come from flags, `TECHNITIUM_*` environment variables, or a `.technitium-mcp` file in `$HOME` (and one in the working directory, read over it key by key):

```
# one server
SERVER=http://nas:5380
TOKEN=<token>
```

```
# several, each under a name the tools take
SERVER=ns1=http://192.168.1.2:5380,ns2=http://192.168.1.3:5380
TOKEN=ns1=<token>,ns2=<token>
```

```bash
technitium-mcp info     # each server's name, version and account, or why it cannot be asked
technitium-mcp tools    # what would be registered with the current settings
technitium-mcp serve    # the MCP server, on stdio
```

Register it with Claude Code in `.mcp.json`:

```json
{ "mcpServers": { "technitium": { "command": "technitium-mcp", "args": ["serve"] } } }
```

| flag | environment | |
|---|---|---|
| `--server`, `-s` | `TECHNITIUM_SERVER` | the address a web console answers on, or several as `name=url` |
| `--token`, `-t` | `TECHNITIUM_TOKEN` | one token for every server, or one each as `name=token` |
| `--enable-write` | `TECHNITIUM_ENABLE_WRITE` | register the tools that change a server; without it every tool only reads |
| `--enable-delete` | `TECHNITIUM_ENABLE_DELETE` | register the tools that delete as well; needs `--enable-write` |
| `--read-only` | `TECHNITIUM_READ_ONLY` | the default, said out loud, for a start line shared with the other servers; refused beside `--enable-write` |
| `--toolsets` | `TECHNITIUM_TOOLSETS` | groups of tools: `all`, `core` (the default), `audit`, `ops`, `block`, `dhcp`, `edit`, or a family like `zone` |
| `--allow-tools` | `TECHNITIUM_ALLOW_TOOLS` | tools to add to the toolsets, by name or a glob like `zone_*`: `--toolsets core --allow-tools zone_get` is core and that one tool. With no `--toolsets`, only the tools named are registered |
| `--deny-tools` | `TECHNITIUM_DENY_TOOLS` | tools never to register, by name or glob: how a toolset is narrowed |
| `--listen` | `TECHNITIUM_LISTEN` | serve MCP over HTTP at this address instead of stdio |
| `--auth-token` | `TECHNITIUM_AUTH_TOKEN` | the bearer token HTTP clients must send; required with `--listen` unless `--allow-no-auth` |

`TECHNITIUM_LOG` sets the log level (`debug`, `trace`). `docker-compose.yml` runs the released image as an always-on HTTP server; see `.env.example`.

## Development

```bash
make tools      # build the pinned dev tools into .tools/bin
make build      # compile, with the version from git
make test       # unit tests with the race detector: canned servers, and the client against the API document
make testacc    # both live suites on real Technitium servers in Docker: one, then two, then the two as a cluster
make lint       # golangci-lint with the azproviderlint plugin
make apicheck   # how much of the Technitium API the SDK wraps
make check-all  # everything
```

| where | what |
|---|---|
| `sdk/technitium` | the client: one server, typed calls |
| `sdk/technitium/technitiumtest` | a canned server for tests, which holds every request against the API document |
| `sdk/apidoc`, `api-defs/` | the vendored API document and its reader |
| `lib/servers` | the named servers one process works on |
| `tools/` | the MCP tools |
| `cli/` | the commands and settings |
| `integration/`, `acceptance/` | the live suites: the SDK, and the tools, against real servers |

The live suites run on servers `scripts/testenv.sh` starts, and refuse any others. Each suite runs three times on the same servers, in order: one server (`up single`), a second started beside it (`add`), and the two made a cluster, which the suite does itself through `sdk/technitium`. `make testacc TOPOLOGIES=cluster` goes straight to the last; `TECHNITIUM_TEST_IMAGE=technitium/dns-server:15.5.0 make testacc` runs another version. The script gives each server the Query Logs (Sqlite) app, which the log search reads, from the file the server's own app store names: fetched once and kept in `.tools/cache`. For the DHCP tests it also hands the suites a small image with a DHCP client in it (busybox), which they run on the servers' network for a moment as a machine asking for a lease; nothing outside that network hears it.
