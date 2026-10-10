# Tool roadmap

What technitium-mcp is for, what is built, and what is wanted next. The wanted list is what a model doing sysadmin work on a real network - two clustered Technitium servers, split-horizon names, DHCP on one node - asked for after two days of using `dig` and guesswork instead (2026-10-09).

Design rules, in priority order:

1. **The tools are everything the model needs.** A model must never have to fall back to `dig`, `curl` or the raw API to check something. If a question about the DNS servers cannot be answered with a tool, that is a missing tool.
2. **Several servers from the first tool.** One process holds every server under a name. Every tool takes `server`: a read asks all of them unless one is named and sets the answers side by side; a change is made on one named server at a time. A server that cannot be asked is said beside the answers of the ones that can, never in place of them.
3. **Exhaustive, not sampled.** An audit reads everything it is about. Accuracy is worth more than the calls it costs.
4. **Filter, count and page inside the tool.** Anything that can be large (records, logs, leases, stats) takes filters, a summary mode, a limit and an offset, and says when it stopped short and how to read on. Every record is read before any is left out, so a filter never misses one.
5. **Compact by default, `details` for the rest.** A row carries what a decision needs. A field that says nothing (not disabled, no comment, never expires) is left out.
6. **Read-only until told otherwise.** No tool that changes a server is registered without `--enable-write`, and none that deletes without `--enable-delete` beside it. Every write takes `dry_run` and answers with before and after, read back from the server. A bulk write lists each change.
7. **Say what to do, not what the API said.** "The zone is a secondary on this server: make the change on its primary" rather than the server's own refusal passed through.
8. **No credential in any answer.** Tokens, TSIG keys and passwords are masked wherever a setting is shown, and never reach an error message or a log line.
9. **Every time says its zone.** Times are given in UTC with the `Z`.
10. **Resource-first names** (`zone_*`, `record_*`, `cache_*`, `audit_*`) so tools group by what they act on.
11. **Tested against throwaway servers, three ways.** Every suite runs on real Technitium servers in Docker arranged each way the tools are used: one server, two on their own, and two made a cluster through the API in the run. A real network's servers are never a test target.

## Done

| Area | Tools | Answers |
|---|---|---|
| know the servers | `server_info` | "which servers are there, are they up, what version, what may this token do on each, and what is each one's place in the cluster" |
| know the zones | `zone_list`, `zone_records`, `zone_get`, `zone_export` | "what zones does each hold, where do the copies differ, where can a zone be changed, what is in this zone, how is it served and replicated", and the zone as a file to keep |
| change the zones | `zone_create`, `zone_edit`, `zone_resync` | "make this zone", "let the other server transfer it", "fix the SOA a rename left behind", "pull the copy again" |
| find | `record_find`, `audit_names` | "what points at this address, by address or by chain", "is that address taken", "which of the host names in these reverse-proxy rules have no record" |
| resolve | `dns_resolve`, `cache_get`, `cache_flush` | "does this resolve, to what, through what, on each server, and what is the outside world told", "is a stale answer being kept" |
| change records | `record_set`, `record_delete`, `record_repoint` | "add the right DNS entries", "change everything at the old address to the new one" - each with a dry run, the PTR, and the result read back |
| settings | `server_settings` | "how is each server set up, and where do they differ" |
| stats | `server_stats` | "what is the server doing", "which machines lean on it", "is a large part of it failures or names that do not exist" |
| query logs | `log_search` | "who is still asking for the old name", "which clients ask for a name that does not exist", "what was this machine told" |
| blocking | `block_check`, `block_list`, `block_set`, `block_delete`, `block_switch`, `block_lists_set`, and `dns_resolve` saying what blocked a name | "why does this name not resolve", "why is this one not blocked", "let this name through", "do the servers block the same", "is blocking what breaks this", "add this list" |
| DHCP | `dhcp_scopes`, `dhcp_leases`, `dhcp_reservation_set`, `dhcp_reservation_delete`, `dhcp_lease_delete`, `dhcp_scope_set` | "what has this address", "where is this machine", "is the pool running out", "pin this host", "give the second server a scope of its own" - the changes refuse what the server would take and could not work, and say what the server does to DNS with them |
| audits | `audit_all`, `audit_servers`, `audit_targets`, `audit_reverse`, `audit_overlaps`, `audit_naming`, `audit_state`, `audit_dhcp`, `audit_blocking`, `audit_zones`, `audit_security`, `audit_split` | "what is wrong": the servers against each other, records that end nowhere, addresses against their PTRs, records never served, probable slips, what is switched off, DHCP against itself and the zones, what is blocked, zones whose own records do not fit their servers, what is left open, and - asked of a resolver named - where the inside and the outside of a split horizon do not fit |

## Wanted

| Area | Tools | Answers |
|---|---|---|
| deleting what was made | `zone_delete`, `dhcp_scope_delete`: neither is built, on purpose so far - a zone or a scope deleted takes everything in it, and the server's own console asks twice | "take this zone away" |
| zones, the rest | a zone's update keys (the TSIG policies an update must be signed with), DNSSEC signing, converting a zone's type | "let the DHCP server on the other box update this zone" |

## Audits still wanted

Built: the servers against each other, broken and pointless records, addresses and PTRs, records never served, naming, what is switched off, DHCP, blocking, how zones are set up, and what is left open (see Done). Each answers with concrete findings - zone, name, the values at fault, a suggested fix - and `audit_all` runs every one. Still wanted:

- **Addresses, the rest.** A setting for the local subnets, to add to the ones the reverse zones and the DHCP scopes give: today an address in a network with no reverse zone is found by `audit_reverse`, and the odd address of the other kind by `audit_overlaps`.
- **Split horizon, the rest.** Names that resolve publicly with no internal override can only be found for names given to `audit_split`: nothing lists what a public zone holds.
- **Blocking, the rest.** Allowed entries that no list blocks any more, which the API gives no way to ask but one name at a time.
- **Resolution.** Forwarders that fail or are slow (timed with a test query); DNSSEC validation failures in recent logs; a high SERVFAIL or NXDOMAIN rate; the top NXDOMAIN names from local clients. `server_stats` and `log_search` give the numbers; no audit weighs them yet.

## Open questions

- **Servers older than 15.0.** The client sends its token as a bearer header, which the API reads from 15.0. An older server refuses every call with "invalid token". Supporting one means sending the token in the request body as well.
- **Clusters, the rest.** The tools say a node's role, which copy of a zone is the primary and where it can be changed, refuse a change asked of a copy and name the server to ask instead, and are tested on a real cluster. Still to do: reaching a cluster's nodes through one of them with the API's `node` parameter, so a cluster is configured once rather than a server at a time.
- **One process for several servers, or one a server?** embyfin-mcp settled on one instance a server with a `--config` flag. This server holds several because its point is setting them side by side - the zone one node lacks, the record two hold differently - which one instance a server cannot do. Worth confirming, and a `--config` flag may be wanted here too for the same file layout.
- **A token that sees no zones.** An account that is not a DNS administrator is given no zone's permissions, and the server lists it nothing rather than refusing. `server_info` should say so when the token's account is in that position.

## Guarded / deliberately excluded

- Nothing that deletes is registered without `--enable-delete`.
- Not wrapped as tools, ever: creating users and tokens, changing passwords, two-factor setup, backup restore, installing apps from files. `sdk/technitium` may come to cover them - it is a general client - but none is a judgment a model should be making on a DNS server.
