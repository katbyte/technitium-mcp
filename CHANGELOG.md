# Changelog

## Unreleased

### Added

- the first three tools, all reads: `server_info` describes each configured server and what the API token may do on it, `zone_list` sets the servers' zones side by side and says where the copies differ, and `zone_records` reads a zone from every server holding it as one table, with filters, counts and paging
- the audits: `audit_servers` (where the servers do not hold the same), `audit_targets` (records that end nowhere), `audit_reverse` (addresses against their PTRs), `audit_overlaps` (records never served, and wildcards), `audit_naming` (probable slips) and `audit_state` (what is switched off), each giving findings with a fix, and `audit_all` counting what every one found in one reading
- `server_settings` sets each server's settings side by side, with no secret among them, and names the ones that differ
- `record_find` searches every zone at once: what holds an address, its PTR and every name that reaches it through a chain of CNAMEs; what points at a name; or any record by name, value, type or comment
- `audit_names` checks a list of host names against the servers' zones and says which have records, where each ends, and why the rest do not
- `dns_resolve` asks each server what it really answers for a name, with the chain, and puts the same question to other resolvers
- `cache_get` and `cache_flush` read and drop what a server's cache keeps for a name
- `record_set`, `record_delete` and `record_repoint` change records, each with a dry run, PTR handling and the result read back; they keep the comments the server drops from the records beside the one changed
- DHCP: `dhcp_scopes` sets each server's scopes side by side with how many addresses are free, `dhcp_leases` finds a machine by name, address or hardware address among the leases and the reservations nobody holds, `dhcp_reservation_set` and `dhcp_reservation_delete` keep an address for a machine and stop keeping it, and `dhcp_lease_delete` has a server forget a lease; the changes refuse what the server would accept and could not work, and say what the server does to its zones with them
- blocking: `block_check` says whether each server blocks a name and by which entry of which list, or why an entry that is there does not block it; `block_list` sets the servers' blocking and their own blocked and allowed lists side by side; `block_set` and `block_delete` put a name on a list and take it off, and ask the server for the name afterwards; `dns_resolve` says when an answer was a block, and by what
- `audit_blocking` finds blocking that is off or paused, lists that are not fetched or hold nothing, entries that block nothing, and servers that do not block alike
- `zone_get` sets how each server serves and copies a zone side by side, and `zone_export` gives a zone whole as a zone file
- `audit_zones` finds NS and SOA records that do not name the servers holding a zone, and primaries that will not feed their copies; `audit_security` finds what is left open: open recursion, a console in the clear, a default password, zones anyone may transfer or change, unused tokens, an old version
- zones can be made and changed: `zone_create` (primary, secondary or forwarder, a reverse zone by its network, a member of a catalog), `zone_edit` (who may ask, transfer and update, who is notified, on or off, the SOA) and `zone_resync`
- `dhcp_scope_set` makes and changes DHCP scopes, leaving a new one switched off unless asked and refusing a range another server already leases
- `block_switch` switches blocking on, off or paused, and `block_lists_set` sets the lists fetched and fetches them
- `audit_split` holds the zones against what a named outside resolver answers; `audit_naming` also finds a TTL far from its zone's usual one and one host's names written two ways; `audit_overlaps` also finds the odd public address among private ones
- `log_search` searches the servers' logs of the queries they answered, by name, client, type, result, source and time, and counts the matches by client or by name; it reads the log the Query Logs app keeps, and says which servers have none
- `server_stats` sets what each server did over a window side by side: queries, how they were answered and from where, the part that failed or was blocked, and the clients and names that lead
- `audit_dhcp` finds where DHCP and the zones do not agree: one server leasing alone, ranges two servers both lease, reservations that cannot work or have no name, records made by hand at addresses a scope gives out, and records left by leases that are gone
- every tool only reads unless `--enable-write` is given, and none deletes without `--enable-delete` beside it
- clusters: `server_info` gives each node's role and the other nodes as it sees them, `zone_list` says where a zone can be changed when some servers hold only a copy, and `zone_records` reads a primary and its copy as one zone
- several servers in one process, each under a name: `--server ns1=http://192.168.1.2:5380,ns2=http://192.168.1.3:5380`, with a token each or one for all; every tool takes `server`, and a read asks every server unless one is named
- `sdk/technitium`, a Go client for the Technitium DNS Server API written from its API document, which is vendored under `api-defs/` and checked against the client by the tests
- the `serve`, `tools`, `info` and `version` commands, settings from flags, `TECHNITIUM_*` environment variables and `.technitium-mcp` files in `$HOME` and the working directory, and a container image
