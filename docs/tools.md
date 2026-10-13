# The tools

Tools are named for what they act on (`zone_*`, `record_*`, `dhcp_*`, `user_*`...) and grouped into toolsets by the job someone is doing. Every tool takes `server`: a read asks every configured server unless one is named, and a change is made on one named server at a time. The `needs` column says which switch registers a tool: nothing for a read, `write` for `--enable-write`, `delete` for `--enable-delete` beside it.

## `core`: what the servers are and what they hold: loaded always

| tool | needs | what it does |
|---|---|---|
| `server_info` |  | each configured server: the name it is configured under, its own domain name, version, whether an update is out, when it started, its cluster, and the account the token acts as with what that account may not read, change or delete. A server that cannot be reached is listed with the reason. Start here |
| `zone_list` |  | the zones on every server, one row a zone: its type, serial, whether disabled or signed, when it last changed, a secondary's transfer state - as each server holds it, with which servers lack it and what differs between the copies. `counts` adds each copy's size |
| `zone_records` |  | one zone's records from every server holding it, as one table: a record held alike is one row, and one only some servers hold (or hold with another TTL or comment) names them. Filters by type, name, value, comment and state; `summary` for counts; `limit` and `offset` to page |
| `record_find` |  | records across every zone at once. By address: what holds it, its PTR, and everything that ends at it through a chain of CNAMEs - what a change of address would touch, or whether an address is free. By target: what points at a name. Or by name, value, type or comment |
| `dns_resolve` |  | what each server really answers for a name, side by side: the result, every CNAME on the way, the TTL, whether it came from its own zone, and when the server blocked it, by which list. Asks other resolvers the same from each server, to see what the outside world is told |
| `cache_get` |  | what each server's cache is keeping for a name: the answer, how long it has left, where it came from, and whether it is the answer that the name does not exist |
| `audit_names` |  | a list of host names - every name a reverse proxy routes - each said to have records and where it ends, or why not |

## `audit`: find what is wrong

The seventeen `audit_*` tools in [docs/audits.md](audits.md), every one of them a read. `audit_names` is in `core`.

## `ops`: how the servers are set up, what they are doing, and keeping one running

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

## `edit`: change what the zones hold

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

## `block`: what the servers refuse to resolve, and why

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

## `dhcp`: the addresses the servers lease

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

## `dnssec`: sign a zone and look after its keys

| tool | needs | what it does |
|---|---|---|
| `dnssec_get` |  | how a zone is signed on each server holding it: every key with its state and when the server next replaces it, how the zone proves a name is not there, and the DS records to give the registrar |
| `dnssec_sign` | write | signs a primary zone: the keys, the algorithm and how absence is proved as asked, and the DS record for the parent zone in the answer |
| `dnssec_edit` | write | changes how a signed zone proves a name is not there (NSEC, or NSEC3 with its iterations and salt) and the TTL of its DNSKEY records |
| `dnssec_key_add` | write | adds a key signing key or a zone signing key to a signed zone |
| `dnssec_key_edit` | write | moves a zone's keys along: publishes the ones only generated, rolls one over to a new key, retires one, or sets how often the server replaces one by itself. What the server refuses as not safe yet is said with its reason |
| `dnssec_key_delete` | delete | deletes a key that was generated and never published |
| `dnssec_unsign` | delete | takes DNSSEC off a zone: its keys are deleted for good. With a dry run, lists the keys that would go |

## `cluster`: make, grow, shrink and end a cluster

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

## `admin`: who may sign in and what each may do

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

## `apps`: the DNS apps a server runs

| tool | needs | what it does |
|---|---|---|
| `app_list` |  | the DNS apps installed on each server, with version and parts; with `store`, which have a newer version at the server's maker's store and what else it offers |
| `app_config_get` |  | an installed app's configuration on each server, side by side, with whether they differ |
| `app_install` | write | installs an app, or updates the one installed under the name keeping its configuration: from the store by name, from an address the server fetches, or from a zip file sent to it |
| `app_config_set` | write | writes an app's configuration, whole, and answers with what it was. Text that is not JSON is refused where the configuration was JSON |
| `app_delete` | delete | uninstalls an app, with its configuration and whatever it kept |

## Choosing which tools load

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

## What a change does before it is made

- **`dry_run` on every change.** It says what would be done, in the words the real call uses, and sends nothing. It does not check whether the token may make the change: the server says that when the change is made.
- **Read back.** A change answers with what the server holds afterwards, and a server that said ok without doing it is an error that says so.
- **The tool will not lock itself out.** The account the tool works under is not switched off, deleted or taken out of the administrators; its own token is not deleted; the Administrators group is not given less than everything.
- **No secret in any answer.** Passwords, token values, transfer keys' secrets and the single sign-on secret are sent and never read back; a token is shown once, when it is made.
- **A backup is of what the server has written to disk,** which lags a change by a few seconds: one taken straight after a change can miss it. A backup holds the server's secrets, and the file is written for its owner's eyes only.
