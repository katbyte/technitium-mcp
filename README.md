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

**The whole server is covered.** The SDK wraps every one of the 139 calls in Technitium's API document and can send every parameter the document gives them, and 106 tools put them to use: zones and records of every type, the cache, blocking, DHCP, DNSSEC, clusters, accounts and permissions, apps, settings, backups and logs. Each is tested against real servers.

### What is in the box

- **Several servers, side by side.** One process works on every server you name. A read asks all of them and sets the answers beside each other, so a zone one server lacks, or a record two servers hold differently, shows without comparing by hand. A server that is down is said beside the answers of the ones that are up.
- **Reads only, until told otherwise.** No tool that changes a server is registered without `--enable-write`, and none that deletes without `--enable-delete` beside it. Every change takes `dry_run`, which says what would be done and sends nothing, and answers with what it did read back from the server: a Technitium server says ok to things it did not do.
- **A Go SDK.** `sdk/technitium` is a typed client for the Technitium API, standard library and [go-kt](https://github.com/katbyte/go-kt) only, with no knowledge of MCP. Technitium publishes no OpenAPI document, so it is written by hand from the server's API document, which is vendored under [api-defs/](api-defs/README.md) and held against the client by the tests, both ways: every call the client makes and every parameter it sends is one the document has, and every call and every parameter the document has is one a test of the client sends.
- **Tested against real servers, three ways.** Every tool and every SDK method runs against real Technitium servers in Docker: on one server, on two that know nothing of each other, and on two made a cluster through the API during the run. Each run fails if a registered tool was never seen to answer. The leases the DHCP tools are tested on are real ones: a small DHCP client is run on the test servers' own network and asks for them.

### The audits

| audit | what it finds |
|---|---|
| `audit_all` | every audit in one reading of the servers, counts only: where to look first |
| `audit_servers` | where servers meant to hold the same do not: a zone one lacks (and, in a cluster, that it is not in the catalog the other node follows), a zone two servers each hold as their own primary, the records that differ, a copy behind its primary or whose transfer failed or that has expired |
| `audit_targets` | records that point at a name and end nowhere: a CNAME to a name with no record, a loop, a long chain, a CNAME at a zone's own name or beside other records, an MX, SRV or NS whose target is missing or is a CNAME |
| `audit_reverse` | addresses and PTRs that disagree: an address with no PTR (with the call that adds it), a PTR naming a host that does not hold the address, several PTRs for one address, a network with addresses in use and no reverse zone |
| `audit_overlaps` | records never served because a zone further down on the same server answers for the name; one name with addresses in two networks; the odd public address in a zone of private ones, or the reverse; and every wildcard, which makes a mistyped name resolve |
| `audit_naming` | probable slips: a stray space or invisible character, an underscore in a host name, two names a typing slip apart, a TTL under a minute, over a week, or far from the one the rest of its zone has, and one host's names written two ways (`emby-dock` beside `jf.dock`) |
| `audit_state` | what is switched off or set to vanish: disabled zones and records, records set to delete themselves |
| `audit_zones` | a zone's own records and options against the servers that hold it: a name server it names that is none of them and no node of their cluster, a holder none of its NS records names, an SOA naming a primary that is not the server holding it as one - what a renamed server leaves behind - and a primary that gives its copies no transfer or no word of a change; reverse zones of one address each, and ones with no PTR in them |
| `audit_security` | what is left open: a server resolving for anyone, a console over plain HTTP alone, the password a server ships with, a zone anyone may transfer or change with no key, an API token unused for ninety days, a server behind the version that is out |
| `audit_access` | accounts and permissions that make a server easier to take than it need be: an administrator who signs in with a password alone, an account nobody has ever used, a switched-off account whose tokens are still there, the admin account the server ships with left on beside another administrator, a section every account may change |
| `audit_cluster` | a cluster that is not whole: a node the others cannot reach, nodes that do not agree who the nodes are, a secondary that has stopped fetching the configuration, nodes on different versions, a cluster of one, a node that is not configured here and so was read by no audit, and a server left outside a cluster the others are in |
| `audit_dnssec` | what the keys of the signed zones are waiting for or leave weak: a key that waits for its DS record at the parent zone, a key made and never put in the zone, a zone whose names anyone can list, a zone signing key the server never replaces, an algorithm no longer trusted, signatures the server has let expire |
| `audit_queries` | what the servers' resolving and the last day of queries say is wrong: a server that cannot resolve a name right now, a forwarder of its that does not answer, fails or is slow (each is asked), a server with no log of queries, one answering too much with a failure, one client asking for most of everything, a busy client with no name, a name asked for far more often than its TTL allows, and the names in the servers' own zones that clients keep asking for and that do not exist |
| `audit_apps` | the DNS apps the servers run: an app behind the version the store has, an app one server runs and another does not, and one they run at different versions or configured differently |
| `audit_blocking` | what the servers block: blocking switched off or paused with lists still set, block lists not fetched or holding nothing, a blocked name that blocks nothing because a zone on the server answers for it or an allowed entry wins, an entry another already stands for, and servers that do not block alike |
| `audit_dhcp` | DHCP against itself and against the zones: one server leasing alone, two leasing the same addresses, a scope running out, naming name servers that are not these or naming one server twice, reservations that cannot work (an address outside the network, a hardware address of all zeros) or have no name in DNS, a record made by hand at an address a scope gives out or has given to another machine, and records the server wrote for a lease that is gone |
| `audit_split` | the inside and the outside of a split horizon, by asking a resolver you name for every name the zones hold: an override whose public name is gone, a private address the outside is given, a name that resolves outside and has no record here, and a parallel domain that does not answer as the zone it mirrors. Not part of `audit_all`: it asks other people's name servers |
| `audit_names` | a list of host names - every name a reverse proxy routes - each said to have records and where it ends, or why not |

`audit_all` runs every one but `audit_split`, which asks other people's name servers, and `audit_names`, which checks a list you give it.

## Installation

```bash
go install github.com/katbyte/technitium-mcp@latest
```

The servers must be Technitium DNS Server 15.0 or newer: the token is sent as a header, which older servers do not read. Both live suites pass on 15.5 and 15.6; the versions from 15.0 to 15.4 have not been run.

## Configuration

Make an API token on each server: web console, Administration, Sessions, Create Token. The token acts as the user it is made for. A user who is not an administrator sees only the zones whose own permissions name them, and none of the accounts, so an administrator's token is the simple way: technitium-mcp only reads unless `--enable-write` is given. `server_info` says what the token may do on each server.

Settings come from flags, `TECHNITIUM_*` environment variables, or a configuration file.

| flag | environment | |
|---|---|---|
| `--server`, `-s` | `TECHNITIUM_SERVER` | the address a web console answers on, or several as `name=url` |
| `--token`, `-t` | `TECHNITIUM_TOKEN` | one token for every server, or one each as `name=token` |
| `--enable-write` | `TECHNITIUM_ENABLE_WRITE` | register the tools that change a server; without it every tool only reads |
| `--enable-delete` | `TECHNITIUM_ENABLE_DELETE` | register the tools that delete as well; needs `--enable-write` |
| `--read-only` | `TECHNITIUM_READ_ONLY` | the default, said out loud, for a start line shared with the other servers; refused beside `--enable-write` |
| `--toolsets` | `TECHNITIUM_TOOLSETS` | groups of tools: `all`, `core` (the default, and always included), `audit`, `ops`, `edit`, `block`, `dhcp`, `dnssec`, `cluster`, `admin`, `apps`, or a family like `zone` |
| `--allow-tools` | `TECHNITIUM_ALLOW_TOOLS` | tools to add to the toolsets, by name or a glob like `zone_*`: `--toolsets core --allow-tools zone_get` is core and that one tool. With no `--toolsets`, only the tools named are registered |
| `--deny-tools` | `TECHNITIUM_DENY_TOOLS` | tools never to register, by name or glob: how a toolset is narrowed |
| `--listen` | `TECHNITIUM_LISTEN` | serve MCP over HTTP at this address instead of stdio |
| `--auth-token` | `TECHNITIUM_AUTH_TOKEN` | the bearer token HTTP clients must send; required with `--listen` unless `--allow-no-auth` |
| `--allow-no-auth` | `TECHNITIUM_ALLOW_NO_AUTH` | serve HTTP with no bearer token: anyone who can reach the port can use every tool |

`TECHNITIUM_LOG` sets the log level (`info`, `debug`, `trace`); unset, only warnings and errors are logged. At `info` and below, one line is logged for every call of a tool that changes or deletes: the tool, what it was sent with passwords, codes and keys blanked, and whether it answered, was refused or failed. A dry run is told apart by its `dry_run` argument.

### Configuration file

A `.technitium-mcp` file in `$HOME`, and one in the working directory read over it key by key, so a project's file needs only the settings it changes. Keys are the environment variable names, with or without the `TECHNITIUM_` prefix. A flag or an environment variable beats either file.

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

Every node of a cluster is configured by its own address. The API has a way to ask one node through another, and the SDK wraps it (`OnNode`), but the servers pass on only half their calls that way - not the list of zones, the settings or anything of DHCP - so a node reached through another could answer only some of the tools.

## Usage

```bash
technitium-mcp info     # each server's name, version and account, or why it cannot be asked
technitium-mcp tools    # what would be registered with the current settings
technitium-mcp serve    # the MCP server, on stdio
```

### Register with Claude Code

`.mcp.json`:

```json
{ "mcpServers": { "technitium": { "command": "technitium-mcp", "args": ["serve"] } } }
```

### Run as a service (HTTP transport)

`serve --listen :8080` serves the MCP Streamable HTTP transport at `/mcp` (and `GET /healthz`) instead of stdio. Clients must send `Authorization: Bearer <token>` with the token `TECHNITIUM_AUTH_TOKEN` holds, and the server refuses to start without one unless `--allow-no-auth` says anyone who can reach the port may use every tool.

```bash
claude mcp add --transport http technitium http://nas:8080/mcp --header "Authorization: Bearer $TECHNITIUM_AUTH_TOKEN"
```

### Docker

`docker-compose.yml` runs the released image as an always-on HTTP server, reading its secrets from a gitignored `.env`; see `.env.example`. `make docker` builds the same image from source.

## MCP Tools

Tools are named for what they act on (`zone_*`, `record_*`, `dhcp_*`, `user_*`...) and grouped into toolsets by the job someone is doing. Every tool takes `server`: a read asks every configured server unless one is named, and a change is made on one named server at a time. The `needs` column says which switch registers a tool: nothing for a read, `write` for `--enable-write`, `delete` for `--enable-delete` beside it.

### `core`: what the servers are and what they hold: loaded always

| tool | needs | what it does |
|---|---|---|
| `server_info` |  | each configured server: the name it is configured under, its own domain name, version, whether an update is out, when it started, its cluster, and the account the token acts as with what that account may not read, change or delete. A server that cannot be reached is listed with the reason. Start here |
| `zone_list` |  | the zones on every server, one row a zone: its type, serial, whether disabled or signed, when it last changed, a secondary's transfer state - as each server holds it, with which servers lack it and what differs between the copies. `counts` adds each copy's size |
| `zone_records` |  | one zone's records from every server holding it, as one table: a record held alike is one row, and one only some servers hold (or hold with another TTL or comment) names them. Filters by type, name, value, comment and state; `summary` for counts; `limit` and `offset` to page |
| `record_find` |  | records across every zone at once. By address: what holds it, its PTR, and everything that ends at it through a chain of CNAMEs - what a change of address would touch, or whether an address is free. By target: what points at a name. Or by name, value, type or comment |
| `dns_resolve` |  | what each server really answers for a name, side by side: the result, every CNAME on the way, the TTL, whether it came from its own zone, and when the server blocked it, by which list. Asks other resolvers the same from each server, to see what the outside world is told |
| `cache_get` |  | what each server's cache is keeping for a name: the answer, how long it has left, where it came from, and whether it is the answer that the name does not exist |
| `audit_names` |  | a list of host names - every name a reverse proxy routes - each said to have records and where it ends, or why not |

### `audit`: find what is wrong

The seventeen `audit_*` tools in [the table above](#the-audits), every one of them a read. `audit_names` is in `core`.

### `ops`: how the servers are set up, what they are doing, and keeping one running

| tool | needs | what it does |
|---|---|---|
| `server_settings` |  | how each server is set up, side by side, and which settings they do not have alike: where it answers, whose queries it resolves and through what, transfers and keys by name, blocking, TTLs, console, log, apps. No secret is among them |
| `settings_get` |  | every setting a server has, the hundred and thirty or so behind the console's Settings pages, by the name the API gives it, side by side where the servers differ. Nothing secret is given |
| `server_stats` |  | what each server did over the last hour, day, week, month or year, or between two times: queries and clients, how they were answered and from where, the part that failed, did not exist or was blocked, and the clients and names that lead |
| `server_metrics` |  | whether each server can resolve a name right now - its own health check - how long it has been up, and every query it has answered since it started, by how and from where; the same counters as Prometheus reads them when asked |
| `log_search` |  | the servers' logs of the queries they answered: who asked for what, when, and what they were told, filtered by name, client, type, result, source and time - or counted by client or by name, for who is still asking for an old name and which names do not exist. Needs the Query Logs app on the server, and says so when it is missing |
| `log_export` |  | the log of queries as CSV, for what `log_search` would find: for handing on to a spreadsheet or another tool |
| `log_files` |  | the files each server writes its own log to, a file a day |
| `log_read` |  | a server's own log for a day: its end, or only the lines with some text in them. Where a failure explains itself - why a transfer was refused, why a block list was not fetched, who signed in and what they changed |
| `zone_get` |  | how one zone is served and copied on each server holding it: its type and catalog, what its SOA and NS records name, who may ask, transfer and update and with which keys, who is told of a change, and for a copy where it transfers from |
| `zone_export` |  | one zone whole as a zone file, comments included: a copy to keep before a change, or to take elsewhere |
| `settings_backup` |  | writes a backup of a server - all of it, or the parts named - to a zip file on the machine the tool runs on, readable by its owner alone and never over a file that is there. The server is only read |
| `settings_set` | write | changes any setting by the name `settings_get` gives it. Only what differs is sent, a name the server does not know is refused, and a value the server rewrote or passed over is said |
| `tsig_key_set` | write | adds a transfer key (TSIG) or changes one, leaving the server's other keys as they are. The secret is never read back |
| `tsig_key_delete` | delete | takes a transfer key off a server, leaving the rest |
| `settings_restore` | delete | puts parts of a server back from a backup's zip file, writing over what the server has of each. With a dry run, lists what the backup holds |
| `stats_delete` | delete | deletes every statistic a server keeps: the dashboard starts again from nothing |
| `log_delete` | delete | deletes one of a server's own log files, or all of them |

### `edit`: change what the zones hold

| tool | needs | what it does |
|---|---|---|
| `record_set` | write | makes a record be there with the value given: added, changed in place, or left alone when it already is. Every record type the server has, from its one line: the common ones, HTTPS and SVCB, TLSA, SSHFP, DS, NAPTR, URI and RP, the server's own FWD (a name sent on to another name server) and APP (a name answered by an installed app), and any other type as bytes. What a type has beside its value - an NS record's glue, how a forwarder is reached, what an app is told - goes in `options`, and a record changed keeps what it has. Keeps the TTL and comment of what it changes, and of the records beside it, which the server would otherwise drop. Sets the PTR too when asked, at the same TTL |
| `record_repoint` | write | moves every record at one address to another across all zones, with the PTRs: for a host that changes address. Refused when the new address belongs to another name unless `share` says so; `dry_run` lists every change |
| `cache_flush` | write | drops what a cache keeps for a name and everything under it, on one server or all |
| `zone_create` | write | makes a zone of any of the server's seven types: a primary, a secondary or a stub that copies another server's, a forwarder with how its name server is reached (or empty, to put FWD records in), a catalog, or a copy of another server's catalog or forwarder; a reverse zone by its network (`10.0.0.0/24`); a member of a cluster's catalog when asked. Says what else the change does |
| `zone_edit` | write | changes how a zone is served: who may ask, transfer and update it and with which lists, the keys a transfer may be signed with and the keys an update must be signed with and what each may change, who is told of a change, on or off, its catalog and what it keeps its own setting for, a copy's primary and how it transfers, what its SOA says and whether it numbers its changes by the day. Reads the zone back, because the server says ok to options it does not take |
| `zone_resync` | write | has a server transfer its copy of a zone from the primary again now |
| `zone_clone` | write | makes a zone that is another's copy at the time, on the same server: a zone from a template, or the first half of a rename |
| `zone_convert` | write | turns a zone into another type where it stands, keeping its records: a secondary into a primary when the server it copied from is gone |
| `zone_import` | write | adds the records of a zone file to a zone: beside what is there, in place of the names it holds, or in place of the whole zone |
| `dns_import` | write | copies a name's records in from another name server: the server asks for the name and writes the answer into the zone it holds for it. A zone held somewhere else, brought over a name at a time with nothing typed by hand |
| `record_delete` | delete | deletes a record and answers with it as it was, which is what puts it back |
| `zone_delete` | delete | deletes a whole zone with every record in it, saying first what it holds. A zone the server made for itself is refused |

### `block`: what the servers refuse to resolve, and why

| tool | needs | what it does |
|---|---|---|
| `block_check` |  | whether each server blocks a name and what makes it so: its own blocked list or a block list it fetches, by entry; and for an entry that does not block the name, why not - an allowed entry over it, blocking off or paused, or a zone on the server answering for the name |
| `block_list` |  | how each server's blocking stands - on, off or paused, how a blocked name is answered, the lists fetched and how many names they hold - and every entry of its own blocked and allowed lists, with what the servers do not have alike |
| `block_tree` |  | walks a blocked or allowed list as the tree it is kept as: whether a name is on it, and the names under it that are. For a list too long to read whole |
| `block_set` | write | puts a name on a server's blocked list, or on its allowed list to let it past whatever blocks it; then asks the server for the name and says whether it is blocked now, and if a blocked entry does nothing, why |
| `block_switch` | write | switches blocking on or off, or pauses it for some minutes: the way to find out whether blocking is what breaks something |
| `block_lists_set` | write | sets the block lists a server fetches, whole or one at a time, and has it fetch them now |
| `block_import` | write | adds many names at once to the blocked or the allowed list; names already there are left alone |
| `block_delete` | delete | takes an entry off the blocked or the allowed list, and says how the name stands afterwards: a block list can block it still |
| `block_flush` | delete | empties the blocked or the allowed list, every name at once |

### `dhcp`: the addresses the servers lease

| tool | needs | what it does |
|---|---|---|
| `dhcp_scopes` |  | each server's DHCP scopes: the range and what it leaves out, whether it is on and on which address, the gateway, name servers and domain machines are given, whether leases are recorded in DNS, and how many addresses are free, leased and reserved. Says which servers lease at all |
| `dhcp_leases` |  | the machines: every lease, dynamic or reserved, with hardware address, name and expiry, and every reservation nobody holds. `find` looks one up by name, address or hardware address however it is written: what has this address, where is this machine |
| `dhcp_reservation_set` | write | keeps an address for a machine: pin this host. Added, replaced, or left alone when it already is. Refuses what the server would take and could not work: an address outside the scope's network, the server's or the gateway's, one kept for or held by another machine. Says, before it is done, when the server will write the name over a record made by hand |
| `dhcp_lease_reserve` | write | turns the lease a machine holds into a reservation, so the address it has now is the one it keeps; or a reserved lease back into an ordinary one |
| `dhcp_scope_set` | write | makes a DHCP scope or changes one: range, exclusions, lease time, gateway, name servers, domain, on or off, and the rest of what a scope hands out - time servers, search domains, static routes, the boot server and file, vendor and numbered options - with how it leases (ping first, wait before offering, refuse made-up hardware addresses). Renames one. A new scope is left off unless asked otherwise, and a range another server here already leases is refused |
| `dhcp_reservation_delete` | delete | removes a reservation and answers with it as it was, and with the records the server took out of DNS with it |
| `dhcp_lease_delete` | delete | has a server forget a lease, for a machine that is gone. The server drops a reservation with its lease; this puts the reservation back |
| `dhcp_scope_delete` | delete | deletes a scope with its reservations and leases, counted first |

### `dnssec`: sign a zone and look after its keys

| tool | needs | what it does |
|---|---|---|
| `dnssec_get` |  | how a zone is signed on each server holding it: every key with its state and when the server next replaces it, how the zone proves a name is not there, and the DS records to give the registrar |
| `dnssec_sign` | write | signs a primary zone: the keys, the algorithm and how absence is proved as asked, and the DS record for the parent zone in the answer |
| `dnssec_edit` | write | changes how a signed zone proves a name is not there (NSEC, or NSEC3 with its iterations and salt) and the TTL of its DNSKEY records |
| `dnssec_key_add` | write | adds a key signing key or a zone signing key to a signed zone |
| `dnssec_key_edit` | write | moves a zone's keys along: publishes the ones only generated, rolls one over to a new key, retires one, or sets how often the server replaces one by itself. What the server refuses as not safe yet is said with its reason |
| `dnssec_key_delete` | delete | deletes a key that was generated and never published |
| `dnssec_unsign` | delete | takes DNSSEC off a zone: its keys are deleted for good. With a dry run, lists the keys that would go |

### `cluster`: make, grow, shrink and end a cluster

| tool | needs | what it does |
|---|---|---|
| `cluster_get` |  | how each server stands in a cluster: whether it is in one, primary or secondary, every node as it sees it with when it last fetched the configuration, and how often the nodes look at each other |
| `cluster_create` | write | makes a server the primary node of a new cluster; nothing it holds is lost |
| `cluster_join` | write | has a server join a cluster as a secondary: its settings, apps and accounts are written over with the primary's, its zones and scopes kept |
| `cluster_edit` | write | changes how a cluster runs: the times its nodes keep, the addresses a node is reached at, where a secondary finds its primary, and a fetch of the whole configuration now |
| `cluster_promote` | write | makes a secondary the cluster's primary: how a primary is moved or retired, and with `force` how a cluster is saved when its primary is lost |
| `cluster_node_delete` | delete | takes a secondary out of a cluster, asked of the primary: by asking the node to leave, or with `force` dropping one that no longer exists |
| `cluster_leave` | delete | takes a secondary out of its cluster, asked of that node; it keeps what it holds |
| `cluster_delete` | delete | deletes a cluster, asked of its primary, once no secondary is left; the server keeps everything but its place in one |

### `admin`: who may sign in and what each may do

| tool | needs | what it does |
|---|---|---|
| `user_list` |  | the accounts on each server, side by side: which are switched off, when each last signed in, and which servers have each |
| `user_get` |  | one account whole: its groups, whether it has a second factor, who is signed in as it, and its API tokens by name with when each was last used and from where |
| `group_list` |  | the groups on each server and who is in each |
| `session_list` |  | who is signed in to each server and every API token made on it: everything that can act on a server without a password. Nothing of a token but its start is given |
| `access_get` |  | who may view, modify and delete in each section of a server, or with one zone: by group, and by account where one is named |
| `sso_get` |  | how each server is set up for single sign-on (OpenID Connect). The client's secret is never read |
| `account_get` |  | the account the tool itself works under on each server: its groups, which is what the tool may do there, and its sessions and tokens |
| `user_set` | write | makes an account or changes one: its password, name, groups, whether it is switched off, how long its sessions last. Refuses to switch off the account the tool works under, or to take it out of the administrators |
| `group_set` | write | makes a group or changes one: what it is for, who is in it, its name |
| `token_create` | write | makes an API token for an account. The answer holds the token, once |
| `access_set` | write | gives an account or a group view, modify and delete in a section or with a zone, changes what one has, or takes one off the list; whoever is not named is left as they are |
| `sso_set` | write | changes how a server is set up for single sign-on |
| `account_edit` | write | changes an account as the account itself, by signing in with its name and password: its password, a second factor put on or taken off, a token of its own, one of its sessions ended. The things a server lets only an account's owner do |
| `user_delete` | delete | deletes an account with every session and token it had. The account the tool works under is refused |
| `group_delete` | delete | deletes a group; its members keep their accounts and lose what the group gave them |
| `session_delete` | delete | ends one session or deletes one API token, by its id. The token the tool works under is refused |

### `apps`: the DNS apps a server runs

| tool | needs | what it does |
|---|---|---|
| `app_list` |  | the DNS apps installed on each server, with version and parts; with `store`, which have a newer version at the server's maker's store and what else it offers |
| `app_config_get` |  | an installed app's configuration on each server, side by side, with whether they differ |
| `app_install` | write | installs an app, or updates the one installed under the name keeping its configuration: from the store by name, from an address the server fetches, or from a zip file sent to it |
| `app_config_set` | write | writes an app's configuration, whole, and answers with what it was. Text that is not JSON is refused where the configuration was JSON |
| `app_delete` | delete | uninstalls an app, with its configuration and whatever it kept |

### Choosing which tools load

**The default is `core`: seven read-only tools, about 3,000 tokens.** Every tool's name, description and input schema is spent from a client's context before anyone has asked a question, and the whole surface is about 41,000 tokens, so `--toolsets` / `TECHNITIUM_TOOLSETS` loads the groups a session needs. `core` comes along with whatever else is asked for, because no other set can find a zone or read a record on its own.

| toolset | tools, reading | ~tokens | with `--enable-write --enable-delete` | ~tokens |
|---|---|---|---|---|
| `core` *(default)* | 7 | 3,000 | 7 | 3,000 |
| `audit` | 24 | 10,700 | 24 | 10,700 |
| `ops` | 18 | 6,600 | 24 | 8,400 |
| `edit` | 7 | 3,000 | 19 | 9,800 |
| `block` | 10 | 3,800 | 16 | 5,700 |
| `dhcp` | 9 | 3,600 | 15 | 6,900 |
| `dnssec` | 8 | 3,200 | 14 | 5,400 |
| `cluster` | 8 | 3,200 | 15 | 5,700 |
| `admin` | 14 | 4,200 | 23 | 7,700 |
| `apps` | 9 | 3,400 | 12 | 4,300 |
| `all` | 51 | 17,800 | 106 | 40,900 |

Each row counts `core` with the set. Tokens are what the model sees, measured over a real `tools/list` at four bytes a token. Every tool also carries an output schema, another 56,000 tokens across `all`, which clients keep to themselves to check results rather than sending to the model.

`--toolsets` also takes a family, which is every tool whose name starts with it: `zone`, `record`, `dhcp`, `user`, `app` and so on.

```sh
TECHNITIUM_TOOLSETS=audit                 # find what is wrong, nothing that writes
TECHNITIUM_TOOLSETS=ops,block             # how the servers run and what they block
TECHNITIUM_TOOLSETS=edit,dhcp TECHNITIUM_ENABLE_WRITE=true   # change records and reservations
TECHNITIUM_TOOLSETS=core TECHNITIUM_ALLOW_TOOLS=zone_get     # core and one tool more
TECHNITIUM_TOOLSETS=all TECHNITIUM_DENY_TOOLS='cluster_*'    # everything but the cluster tools
```

`--allow-tools` also takes the `essential` preset (`server_info`, `zone_list`, `zone_records`). A name or pattern that matches no tool stops the start and says which, so a typing slip cannot hide a tool. Neither flag gets a tool past the write and delete switches.

### What a change does before it is made

- **`dry_run` on every change.** It says what would be done, in the words the real call uses, and sends nothing. It does not check whether the token may make the change: the server says that when the change is made.
- **Read back.** A change answers with what the server holds afterwards, and a server that said ok without doing it is an error that says so.
- **The tool will not lock itself out.** The account the tool works under is not switched off, deleted or taken out of the administrators; its own token is not deleted; the Administrators group is not given less than everything.
- **No secret in any answer.** Passwords, token values, transfer keys' secrets and the single sign-on secret are sent and never read back; a token is shown once, when it is made.
- **A backup is of what the server has written to disk,** which lags a change by a few seconds: one taken straight after a change can miss it. A backup holds the server's secrets, and the file is written for its owner's eyes only.

## Using the client on its own

`sdk/technitium` is a plain Go client for the Technitium API with no knowledge of MCP. Beneath it are the standard library and [go-kt's HTTP package](https://github.com/katbyte/go-kt/tree/main/chttp), which itself uses only the standard library. To talk to a Technitium server from Go, take it and ignore the rest:

```go
import "github.com/katbyte/technitium-mcp/sdk/technitium"

client, err := technitium.New("http://nas:5380", os.Getenv("TECHNITIUM_TOKEN"))
zones, err := client.Zones(ctx, technitium.ZoneFilter{})
```

It has 160 methods covering **every one of the 139 calls in Technitium's API document, and every parameter the document gives them**. `make apicheck` reads the calls out of the vendored document and says how many are wrapped. The unit tests fail when a call the client makes is not the document's, when a parameter it sends is not one the document gives the call, when a secret is sent in an address rather than a body, when a method has no test - and when a parameter the document gives a call is sent by no test, unless it is listed with why in `api-defs/unsent.txt`, which holds five names the server no longer reads. Every method is also run against a real server.

Records of every type are written from one line, as a zone file writes them:

```go
data, err := technitium.ParseValue("HTTPS", "1 . alpn=h2,h3")
rec, err := client.AddRecord(ctx, technitium.NewRecord{Zone: "example.com", Name: "www.example.com", Type: "HTTPS", TTL: 300, Data: data})
```

A read is asked for again when the connection dropped or a gateway in front of the server could not reach it; a write is sent once. A call is given two minutes: the server sends nothing of an answer until the call is done, and a server joining a cluster or a backup being restored takes as long as there is to do. A redirect is refused rather than followed, since following one turns a write into a read with nothing in it. Nothing is logged unless the client is handed a logger, and then every request and answer is traced with the token, passwords and keys blanked.

What the document gets wrong or leaves out, found by running against real servers, is written down in [api-defs/README.md](api-defs/README.md).

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

### Tests

`make test` needs no server. The client is tested against a canned one that refuses any request the API document does not describe, and the tools end to end over an in-memory MCP session against two canned servers.

Everything else runs against **real Technitium servers in Docker**, because a canned server can only confirm what was already believed.

| | covers | command |
|---|---|---|
| `integration/` | the `sdk/technitium` client: every method, against a real server | `make testacc-integration` |
| `acceptance/` | the tools: every one of them, the journeys, and the built binary | `make testacc-acceptance` |

The live suites run on servers `scripts/testenv.sh` starts, and refuse any others. Each suite runs three times on the same servers, in order: one server (`up single`), a second started beside it (`add`), and the two made a cluster, which the suite does itself through `sdk/technitium`. A last pass then runs the tests that take the cluster apart - a node leaving, a secondary promoted, the cluster deleted - alone, since nothing else can run beside them. `make testacc TOPOLOGIES=cluster` goes straight to the cluster; `TECHNITIUM_TEST_IMAGE=technitium/dns-server:15.5.0 make testacc` runs another version. The script gives each server the Query Logs (Sqlite) app, which the log search reads, from the file the server's own app store names: fetched once and kept in `.tools/cache`. For the DHCP tests it also hands the suites a small image with a DHCP client in it (busybox), which they run on the servers' network for a moment as a machine asking for a lease; nothing outside that network hears it.

Each acceptance run records every tool it calls and fails if a registered tool was never seen to answer. The integration suite fails if a client method has no live test.

The journeys (`acceptance/journey_*_test.go`) chain the tools the way a session does and read the server back through the client after every write, because a tool's own answer is not proof: a first setup made from nothing with the tools alone, audited to nothing of its own, taken down again, and the server found holding exactly what it held before; a host moved to a new address with everything that pointed at it; every finding an audit can fix, fixed, audited again and put back; a zone's whole life from made to signed to deleted; a mistake undone from a backup; a token that may only look, held to that across every tool; an administrator's token without the write switches; many calls at once; every write done twice; every read leaving the servers unchanged; and two servers that differ brought into line.

`acceptance/binary_test.go` builds the real binary and speaks to it as a client does, which the rest never touches: `serve` over stdio saying nothing on stdout but the protocol, the flags registering what they say they do, the configuration file in the working directory read, `serve --listen` over HTTP with its bearer token, a start that cannot be made refused with the reason, and the `info` and `tools` commands.
