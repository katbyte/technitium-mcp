# api-defs

The Technitium API document, vendored, and what the server does that the document does not say.

## The document

Technitium publishes no machine-readable description of its HTTP API: no OpenAPI document, in its repository or served by a running server. What it has is `APIDOCS.md`, written for people. So `sdk/technitium` is written by hand rather than generated, and the document is vendored here as the thing the client is held against.

| File | Source | Version vendored |
|---|---|---|
| `technitium-apidocs-15.6.0.md` | <https://github.com/TechnitiumSoftware/DnsServer/blob/v15.6.0/APIDOCS.md>, at the release tag | Technitium DNS Server 15.6.0 - 139 calls |
| `unwrapped.txt` | kept by hand | the calls in the document that `sdk/technitium` has no method for yet |

The file is named for the server version it describes. The highest version here is the one read, and `technitium.APIVersion` says which the client was written against; `server_info` reports it beside each server's own.

## How the client is held against it

`sdk/apidoc` reads the document: every call's path, the paths it went by in older versions, and the parameters it takes. A section it cannot read is an error, never a call quietly left out, so a document whose layout changed cannot pass for one fully covered. Three checks use it, all in `make test`:

- **Every path the client calls is in the document, at its current spelling.** The paths are read out of the client's source, where each is written out as a string, so the list is exact. A typo, an obsolete path, or a call a new version renamed fails.
- **Every call in the document is wrapped or listed in `unwrapped.txt`.** A call a new document adds fails until it is wrapped or listed on purpose; a listed call that has since been wrapped, or that the document dropped, fails too, so the list cannot rot.
- **Every parameter the client sends is one the document gives that call.** The canned server every unit test runs against (`sdk/technitium/technitiumtest`) checks each request it gets, and every client method must have a test, so a misspelled or dropped parameter fails where it is sent.

`make apicheck` prints how much of the API is wrapped, by area.

The document is a description, not the server. The integration suite (`integration/`) is what proves the client against real servers, and every client method must be called there too.

## Refreshing it

1. Download `APIDOCS.md` at the new release's tag and save it here as `technitium-apidocs-<version>.md`; delete the old one, which git keeps.
2. Run `make test`. New calls fail until wrapped or added to `unwrapped.txt`; renamed or removed calls the client uses fail by name.
3. Diff the two documents for parameters added to calls the client already wraps.
4. Set `technitium.APIVersion`, and run `make testacc` against the new server image.

## What the server does

Found by running a 15.6 server.

- **Every answer is HTTP 200.** How a call went is the `status` in the body: `ok`, `error` (with `errorMessage`), `invalid-token` or `2fa-required`. The only other status is a 404 for a path the server does not have.
- **A missing token and a wrong one answer alike**: `invalid-token`. So does every call to a server older than 15.0 from this client, which sends the token as a bearer header that those versions do not read.
- **Most answers are under `response`; the session's are beside `status`.** `status`, `user/session/get` and the token calls put their fields at the top level.
- **Every answer carries `server`**, the server's own domain name, which the document does not show.
- **`user/session/get` sends the token back.** The client has no field for it.
- **Times are UTC with a `Z`, except "never"**, which is `0001-01-01T00:00:00` with no zone: a record never used, a zone never changed.
- **A new server lists no zones.** The document's example lists `localhost` and the loopback reverse zones as `internal`; 15.6 does not list them at all.
- **Records carry more than the document's example**: `comments`, `expiryTtl`, `lastModified`, and a readable copy of each duration (`ttlString`).
- **A CNAME or a DNAME is deleted by name and type alone.** The delete call takes no `cname`.
- **Zones are private by default.** A zone's own permissions name its creator, Administrators and DNS Administrators. Any other account gets View on the Zones section and still sees an empty list of zones, with "Access was denied." for a zone's records.

### Reading while something is written

- **A zone read while a record is being written to it can be refused** with the server's own "Operation is not valid due to the current state of the object." Read again a moment later it is given whole. The client makes the read again by itself, up to five times over a second and a half.

### The cache

- **Making or deleting a zone can empty the whole cache.** A reverse zone does, and so does a zone under a top-level domain that nothing in the cache is under. A zone beside what the cache holds did not empty it with one answer kept, and did with several. The rule behind that was not found, so `zone_create` says only that it can. Nothing else tried empties it: no record added, changed or deleted, no change to a zone's options or its SOA, no DHCP scope made or switched, and no change to blocking or its lists. `TestWhatEmptiesTheCache` keeps all of it.
- **A name dropped from the cache takes every name under it.**
- **Asked for a name it keeps nothing at, `cache/list` answers for the nearest name below that it does**, skipping the empty ones between: its `domain` is then not the one asked for.
- **A negative answer is kept as a record** whose data is `dataType: DnsSpecialCacheRecordData` and a text beginning `NegativeCache: NxDomain` or `NoData`.

### When records are written

Found by the live suites, and kept by `TestWhatAWriteDoesToTheRecordsBesideIt`.

- **An update resets what it leaves out.** `zones/records/update` sent without `ttl`, `comments` or `disable` sets the TTL to 3600, clears the comment and enables the record. The client sends all of them, always.
- **Records of one type at a name share one TTL, and changing it drops the others' comments.** A record added at another TTL than the ones there, or one of them updated to another, has the server rewrite every record of the set at the new TTL without its comment. A record added with no TTL takes the server's default, which does the same. `record_set` adds at the TTL the others have unless given one, and puts their comments back when one is.
- **An address deleted takes its PTR with it.** The server removes the PTR naming the name, in the reverse zone it holds, when an A or AAAA is deleted. `record_delete` says so in its answer.
- **An address changed does not move its PTR.** With `ptr=true` the update adds the new address's PTR and leaves the old one naming the host. `record_set` removes it.
- **The refusals mislead.** Updating a record that is not there answers "zone ... does not exists"; adding one that is there, "record already exists".

### Blocking

Found by blocking names on 15.6 servers and asking them for the names, and kept by `TestBlocking` and `TestBlockingSwitched` in the integration suite.

- **A blocked name's answer says so.** It carries an extended DNS error, `Blocked`, whose text names the source and the entry: `source=blocked-zone; domain=ads.example.net` for the server's own list, and for a list it fetches the list's address as well. `dns_resolve` and `block_check` read it. Asked for the name's TXT record, the server answers with the same text.
- **An entry stands for every name under it.**
- **The allowed list wins** over the blocked list and over the lists fetched.
- **A zone the server holds answers first.** A blocked name with a record in one of the server's own zones is answered from the zone, and no list is looked at.
- **The server answers for `.test`, `.invalid` and `home.arpa` itself**, as names that do not exist, before any list is looked at: nothing under them can be seen to be blocked, which is why the suites block names under `.example`.
- **The two lists are exported as text**, one name a line, where every other call answers in JSON. Adding a name that is there, or removing one that is not, answers ok.
- **A pause is blocking off with a time**: `enableBlocking` reads false and `temporaryDisableBlockingTill` holds when it comes back. Switching blocking on ends it.
- **Switching blocking off does not end a pause.** Found by hand on a 15.6 server, a minute being too long for a test to wait: switched off in a pause, blocking came back on when the pause ended. `block_switch` ends the pause first. After that the server goes on giving the pause's old end time while blocking is off, until the time has passed, though nothing then switches it on: that part `TestBlockingSwitched` keeps.
- **`settings/set` changes what it is sent and nothing else**, unlike a record's update.
- **Lists not fetched yet are due at the server's "never" and their interval**: `blockListNextUpdatedOn` reads `0001-01-02T00:00:00` for a daily list set and never fetched, or one a fetch was just forced for.
- **A cluster's nodes share all of it.** A name blocked on a secondary node goes to the primary, which has it at once; the secondary has it once it has copied it back, about ten seconds later. `block_set` waits for that.

### Statistics

Kept by `TestStats` in the integration suite.

- **The server counts by the minute**, and a minute is in the last hour's totals once it is over: a query shows up to a minute after it was asked.
- **The longer windows are counted by the hour and the day.** The hour in progress was in none of them when this was written; a window given by its own start and end is counted in whole days, today among them.
- **A query the server is asked to make of itself counts**, as one from `127.0.0.1`: `dnsClient/resolve` with `this-server` or the server's own address. The suites make their traffic that way.
- **The names asked for most are of those that were answered**: a name that does not exist is in no list, and a blocked one is in the blocked list.

### Making and changing zones and scopes

Kept by `TestZoneChanges` and `TestDHCP` in the integration suite.

- **An SOA is set whole**: every field is sent, the serial as it stands, which the server then counts on from itself.
- **A list of a zone's options is cleared with `false`**, not with an empty value.
- **Only a copy is resynced**: a primary is refused.
- **A scope set while it is switched off stays off**; only a scope that is made is switched on by being set.

### A zone's options

Kept by `TestZoneOptionsAndExport` in the integration suite.

- **A new primary lets its own name servers transfer it and tells them of a change**, lets anyone ask for its names, and takes no updates.
- **`zones/options/set` changes the options it is sent and leaves the rest**, like the settings and unlike a record.
- **A policy it does not know is passed over without a word**: it answers ok and changes nothing, so a change to a zone's options is only known by reading them back.
- **A zone is exported as text**, a zone file with each record's comment after a semicolon, where every other answer is JSON.
- **The list of sessions gives part of each token.** The client has no field for it.

### The log of queries

Kept by `TestQueryLog` in the integration suite, on servers given the Query Logs (Sqlite) app.

- **A server keeps no searchable log by itself.** An app does, and `logs/query` is asked by the app's name and the class of its part that keeps the log, which `apps/list` gives.
- **A query is in the log a moment after it is asked**, where the statistics take a minute.
- **A name is matched whole**, whatever its case, with a `*` for any run of characters; a `?` is no wildcard. `log_search` puts a `*` at each end of a name given with none.
- **A client is one address, exactly**: a network is refused.
- **The answer is text**: each record as its type and value, a chain in order (`CNAME a.example.com., A 10.0.0.4`), and null for an answer with no records.
- **How much the log keeps is in the app's configuration**, which `apps/config/get` gives as text: seven days and ten thousand queries, as it is installed.

### DHCP

Found by having real machines ask a 15.6 server for leases - a DHCP client run on the test servers' own network - and kept by `TestDHCP` in the integration suite.

- **A scope made with `dhcp/scopes/set` is switched on at once.** Set again with less, it keeps what was left out, its reservations among it: unlike a record's update.
- **The server takes nearly any reservation.** An address outside the scope's network, one already reserved for another machine, one another machine holds a lease on: all accepted without a word. Only a second reservation for the same machine in the scope is refused. `dhcp_reservation_set` refuses the rest itself.
- **A reservation nobody holds is in no list of leases.** `dhcp/leases/list` gives only what machines have taken; the reservations are in the scope. `dhcp_leases` puts the two together.
- **With `dnsUpdates` on, the server writes to its own zones**: an A under the scope's domain and its PTR for each lease with a host name, and for each reservation with one the moment it is made, lease or no lease. Each has the comment `Via '<scope>' DHCP scope`. It makes the zone for the domain itself when no zone holds it.
- **A reservation's name is written over a record already at that name; a lease's is not.** A record made by hand at `printer.lan` is replaced when a reservation named `printer` is added. A machine that asks for a name a record made by hand has keeps the name in its lease and gets no record.
- **A reserved lease has the reservation's name**, whatever name the machine gave.
- **A reservation removed takes its records with it at once**, though the machine may hold the address for the rest of its lease, which the server goes on listing as `Reserved`.
- **A reserved lease removed takes its reservation with it.** `dhcp_lease_delete` puts the reservation back.
- **A scope deleted takes its leases and their records, and leaves the records of its reservations behind.** `audit_dhcp` finds them by their comment.
- **Hardware addresses are taken with colons or dashes, in either case, and given back as `00-11-22-AA-BB-CC`.** One that is none is refused with "The input string ... was not in a correct format."
- **Deleting a scope that is not there answers ok.**

### In a cluster

Found by making a cluster of two 15.6 servers through the API, which the live suites do on every run.

- **A server made a cluster's primary renames itself** under the cluster's domain (`ns1` becomes `ns1.cluster.test`) and turns HTTPS on for its console, which takes it a few seconds: until then it refuses a joining server's connection.
- **A joining server cuts the connection it was asked on.** It turns its own HTTPS on first, so the first `admin/cluster/initJoin` sent to a fresh server gets no answer at all; asked again, it joins.
- **Joining needs an administrator's password on the primary**, not a token.
- **Joining writes the primary's accounts and tokens over the joining server's.** The token it had stops working, and the primary's works on both from then on.
- **A node that has just joined holds the cluster's two zones empty** (serial 0, expired) for a few seconds before the first transfer.
- **A zone is shared by being a member of the cluster's catalog** (`catalog` on `zones/create`); the other node makes itself a secondary of it about ten seconds later. A zone made without it stays on the node it was made on, primary or secondary.
- **A secondary's copy holds the records and nothing beside them**: no comment, no expiry, and no time a record was last changed. A record the primary has disabled is not in the copy at all.
- **A copy refuses a change** with "Cannot add record in Secondary zone."
- **A copy the catalog made names no primary of its own.** Its options give the catalog and how it transfers, and an empty list of primary addresses: where it transfers from is the catalog's to say.
- **A cluster makes itself a TSIG key**, named for its catalog zone, which every node then has in its settings.
- **`clusterNodes` gives each node's `ipAddresses`, a list**, where the document's example for the state call shows `ipAddress`.

## What the document gets wrong

The reader allows for these, and its tests keep them:

- Two sections write their marker `URL\:` rather than `URL:\` (the two Get Metrics calls).
- Three example addresses have no closing backtick (Unsign Zone, Get DS Info, Get User Details).
- One example address is not on `localhost` (Initialize And Join Cluster).
- A call's `WHERE:` list sometimes misses a parameter its example address carries (`value` for Delete Record), so both are read.
- One parameter's name is closed a space late (`primaryZoneTransferProtocol ` for Set Zone Options), which used to end the list there.
