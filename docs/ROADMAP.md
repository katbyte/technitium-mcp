# Tool roadmap

What technitium-mcp is for and what is built. It began as the list of what a model doing sysadmin work on a real network - two clustered Technitium servers, split-horizon names, DHCP on one node - asked for after two days of using `dig` and guesswork instead (2026-10-09), and now covers the whole server: every call in its API document and every parameter those calls take.

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
| know the servers | `server_info`, `server_metrics` | "which servers are there, are they up, what version, what may this token do on each, and what is each one's place in the cluster", "can it resolve right now" |
| know the zones | `zone_list`, `zone_records`, `zone_get`, `zone_export` | "what zones does each hold, where do the copies differ, where can a zone be changed, what is in this zone, how is it served and replicated", and the zone as a file to keep |
| change the zones | `zone_create`, `zone_edit`, `zone_resync`, `zone_clone`, `zone_convert`, `zone_import`, `zone_delete`, `dns_import` | "make this zone" of any of the seven types, "let the other server transfer it", "let the DHCP server on the other box update this zone" with a key, "fix the SOA a rename left behind", "pull the copy again", "copy this zone in from where it is held", "take this zone away" |
| find | `record_find`, `audit_names` | "what points at this address, by address or by chain", "is that address taken", "which of the host names in these reverse-proxy rules have no record" |
| resolve | `dns_resolve`, `cache_get`, `cache_flush` | "does this resolve, to what, through what, on each server, and what is the outside world told", "is a stale answer being kept" |
| change records | `record_set`, `record_delete`, `record_repoint` | "add the right DNS entries" of every record type the server has, "send this part of the zone to another name server", "change everything at the old address to the new one" - each with a dry run, the PTR, and the result read back |
| DNSSEC | `dnssec_get`, `dnssec_sign`, `dnssec_unsign`, `dnssec_edit`, `dnssec_key_add`, `dnssec_key_edit`, `dnssec_key_delete` | "sign this zone", "what do I give the registrar", "roll this key", "what is this key waiting for" |
| settings | `server_settings`, `settings_get`, `settings_set`, `tsig_key_set`, `tsig_key_delete` | "how is each server set up, and where do they differ", "change this setting", "make a key two servers share" |
| backups | `settings_backup`, `settings_restore` | "keep a copy of this server before I change it", "put it back" |
| stats | `server_stats`, `stats_delete` | "what is the server doing", "which machines lean on it", "is a large part of it failures or names that do not exist" |
| logs | `log_search`, `log_export`, `log_files`, `log_read`, `log_delete` | "who is still asking for the old name", "what was this machine told", "why did the transfer fail", "who changed that" |
| blocking | `block_check`, `block_list`, `block_tree`, `block_set`, `block_delete`, `block_import`, `block_flush`, `block_switch`, `block_lists_set` | "why does this name not resolve", "why is this one not blocked", "let this name through", "do the servers block the same", "is blocking what breaks this", "add this list" |
| DHCP | `dhcp_scopes`, `dhcp_leases`, `dhcp_reservation_set`, `dhcp_reservation_delete`, `dhcp_lease_reserve`, `dhcp_lease_delete`, `dhcp_scope_set`, `dhcp_scope_delete` | "what has this address", "where is this machine", "is the pool running out", "pin this host", "give the second server a scope of its own", "hand out the time server and this route too" |
| clusters | `cluster_get`, `cluster_create`, `cluster_join`, `cluster_edit`, `cluster_promote`, `cluster_node_delete`, `cluster_leave`, `cluster_delete` | "make these two a cluster", "is the cluster whole", "the primary is gone: make this one the primary", "take this node out" |
| accounts | `user_list`, `user_get`, `user_set`, `user_delete`, `group_list`, `group_set`, `group_delete`, `session_list`, `session_delete`, `token_create`, `access_get`, `access_set`, `sso_get`, `sso_set`, `account_get`, `account_edit` | "who can sign in and what may each do", "whose token is this and when was it last used", "make a token that may only look", "let this account change one zone" |
| apps | `app_list`, `app_install`, `app_config_get`, `app_config_set`, `app_delete` | "what is installed and is it current", "install the split horizon app", "how is it configured" |
| audits | `audit_all`, `audit_servers`, `audit_targets`, `audit_reverse`, `audit_overlaps`, `audit_naming`, `audit_state`, `audit_dhcp`, `audit_blocking`, `audit_zones`, `audit_security`, `audit_access`, `audit_cluster`, `audit_dnssec`, `audit_queries`, `audit_apps`, `audit_split` | "what is wrong": the servers against each other, records that end nowhere, addresses against their PTRs, records never served, probable slips, what is switched off, DHCP against itself and the zones, what is blocked, zones whose own records do not fit their servers, what is left open, accounts and permissions that are too loose, a cluster that is not whole, keys waiting for something, forwarders that fail and names clients keep asking for that do not exist, apps behind the store, and - asked of a resolver named - where the inside and the outside of a split horizon do not fit |

## What is not built, and why

Each of these is something the server gives no way to do, or that the tools reach another way.

- **Names that resolve publicly with no internal override.** `audit_split` finds them only among the names it is given or the zones hold: nothing lists what a public zone holds.
- **Allowed names that no block list blocks any more.** A server says which list blocks a name only by blocking it, so an allowed entry cannot be asked about without taking it off.
- **Reaching a cluster's nodes through one of them.** The API passes a call on to another node when asked, and the client wraps that (`OnNode`), but only 69 of the 139 calls are passed on, and the list of zones, the settings and everything of DHCP are not among them. A node reached that way could answer only some tools, so every node is configured by its own address.
- **Client methods with no tool of their own.** The calls a cluster's nodes make of each other (`AdmitSecondaryNode`, `UpdateSecondaryNode`, `TransferConfig`, `NotifySecondary`, `CreateSSOUser`, `SetSSOUser`) are not for anyone else to make. `CreateTokenFor` is what `account_edit` does inside the session it signs in with; `CatalogZones`, `ZonesPage`, `DeleteZones`, `DeleteAddress`, `CacheAbove` and the calls that name a lease by its client identifier are other ways to what `zone_create`, `zone_list`, `zone_delete`, `record_delete`, `cache_get` and the lease tools already do.

## Known limits

- **A secondary told of new times for its cluster can stop answering cluster calls.** Seen on 15.6 servers after the API set a cluster's heartbeat and fetch times with a secondary in it, which is the call `cluster_edit` makes for them: not every time, and with `curl` alone, so it is the servers'. The node goes on answering everything else and has to be restarted, or dropped with `cluster_node_delete` and `force`, to be of use to the cluster again. Why is not found; [api-defs/README.md](../api-defs/README.md) has what was seen.
- **A dry run does not check the token's permissions.** It says what would be done; whether the account may do it is said by the server when the change is made.
- **Servers older than 15.0.** The client sends its token as a bearer header, which the API reads from 15.0. An older server refuses every call with "invalid token".
- **A forwarder record has no TTL, and a secondary zone is made only while its primary answers.** Both are the server's own rules, and the tools say so rather than fail later.

## Open questions

- **A setting for the local subnets**, to add to the ones the reverse zones and the DHCP scopes give: today an address in a network with no reverse zone is found by `audit_reverse`, and the odd address of the other kind by `audit_overlaps`.
- **A token that sees no zones.** An account that is not a DNS administrator is shown only the zones whose permissions name it, with no word that others exist. `account_get` and `access_get` show why; `server_info` could say it outright.
- **`dry_run` or `confirm`.** This server previews a change with `dry_run`, where its sibling servers ask for a second call with `confirm`.

## Guarded

- Nothing that changes a server is registered without `--enable-write`, and nothing that deletes without `--enable-delete` beside it. That includes the whole of accounts, clusters, apps, backups and settings.
- The tools that could lock the tool out refuse to: the account it works under is not switched off, deleted or taken out of the administrators, its own token is not deleted, and the Administrators group is not given less than everything.
- No password, token, key or secret is read back in any answer. A token is shown once, when it is made.
