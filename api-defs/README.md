# api-defs

The Technitium API document, vendored, and what the server does that the document does not say.

## The document

Technitium publishes no machine-readable description of its HTTP API: no OpenAPI document, in its repository or served by a running server. What it has is `APIDOCS.md`, written for people. So `sdk/technitium` is written by hand rather than generated, and the document is vendored here as the thing the client is held against.

| File | Source | Version vendored |
|---|---|---|
| `technitium-apidocs-15.6.0.md` | <https://github.com/TechnitiumSoftware/DnsServer/blob/v15.6.0/APIDOCS.md>, at the release tag | Technitium DNS Server 15.6.0 - 139 calls |
| `unwrapped.txt` | kept by hand | the calls in the document that `sdk/technitium` has no method for: none |
| `unsent.txt` | kept by hand | the parameters in the document that no test of the client sends, each with why: five names the server no longer reads |

The file is named for the server version it describes. The highest version here is the one read, and `technitium.APIVersion` says which the client was written against; `server_info` reports it beside each server's own.

## How the client is held against it

`sdk/apidoc` reads the document: every call's path, the paths it went by in older versions, and the parameters it takes. A section it cannot read is an error, never a call quietly left out, so a document whose layout changed cannot pass for one fully covered. Four checks use it, all in `make test`:

- **Every path the client calls is in the document, at its current spelling.** The paths are read out of the client's source, where each is written out as a string, so the list is exact. A typo, an obsolete path, or a call a new version renamed fails.
- **Every call in the document is wrapped or listed in `unwrapped.txt`.** A call a new document adds fails until it is wrapped or listed on purpose; a listed call that has since been wrapped, or that the document dropped, fails too, so the list cannot rot.
- **Every parameter the client sends is one the document gives that call.** The canned server every unit test runs against (`sdk/technitium/technitiumtest`) checks each request it gets, and every client method must have a test, so a misspelled or dropped parameter fails where it is sent.

- **Every parameter the document gives a call is sent by some test of the client, or is listed in `unsent.txt` with why.** The canned servers note what they are sent, and a whole run of the client's tests ends by holding that against the document. Wrapping a call is not covering it: before this check the client wrapped all 139 calls and could not send a third of what they take, among it whole record types and most of a DHCP scope's options. A parameter a new document adds to a call fails here until the client sends it.

`make apicheck` prints how much of the API is wrapped, by area.

The document is a description, not the server. The integration suite (`integration/`) is what proves the client against real servers, and every client method must be called there too.

## Refreshing it

1. Download `APIDOCS.md` at the new release's tag and save it here as `technitium-apidocs-<version>.md`; delete the old one, which git keeps.
2. Run `make test`. New calls fail until wrapped or added to `unwrapped.txt`; renamed or removed calls the client uses fail by name.
3. Parameters added to calls the client already wraps fail the same run by name: give the client a way to send each, with a test, or list it in `unsent.txt` with why.
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
- **A scope with a network smaller than a /24 gets a reverse zone per address.** Seen on a real 15.5 server, not reproduced in the suites: a /27 scope with `dnsUpdates` on had left eight zones of the shape `162.16.16.172.in-addr.arpa`, one PTR or none in each, where nothing held `16.16.172.in-addr.arpa`. `audit_zones` finds the shape.

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

### Records of every type

Kept by `TestEveryRecordType` in the integration suite, which adds, changes and deletes one of each.

- **A record's data is read under other names than it is sent under**, for most of the newer types. An SSHFP is read as `algorithm`, `fingerprintType` and `fingerprint` and sent as `sshfpAlgorithm`, `sshfpFingerprintType` and `sshfpFingerprint`; a TLSA, a NAPTR and a URI likewise, each parameter with its type before it; a forwarder's `priority` is sent as `forwarderPriority`; an APP record's `data` is sent as `recordData`. The client keeps one table of both names for every type.
- **An NS record's glue is given beside its data**, as `glueRecords` on the record, and taken as `glue`.
- **A change to a record resets what it does not send.** A forwarder record changed without its priority, its DNSSEC validation or its proxy goes back to none of them; an NS record changed without its glue loses it. So a change sends every option the record has.
- **A proxy's password is never given back**, so a forwarder record that goes through a proxy with one has to be given it again whenever it is changed.
- **A forwarder record has no TTL**: the server keeps it at 0 whatever it is sent.
- **A forwarder record goes only in a forwarder zone**: a primary refuses one with "The record type is not supported by primary zones."
- **A TXT record split into strings is read back with its text joined**, the line ends gone, beside `characterStrings` and `characterStringsBase64`. Its text alone no longer says where the strings part, so the client names such a record by its strings in base64 when it changes or deletes it.
- **An SVCB or HTTPS record's parameters are read as an object and sent as a list with bars** between every key and value, `false` for none; a target that is the root is sent as a dot and read back as nothing.
- **A DS record is read with the numbers of its algorithm and digest type beside their names**, and takes the names.
- **A type the server has no layout for is taken by its name**, as LOC or NULL, with its data as bytes in hex with colons between (`rdata`), and read back under `value`. A type given as a number is not taken: 65280 is answered with "Parameter 'aname' missing."
- **An APP record is taken whatever the app's name and class are**: the server does not check that the app is installed or has such a part.

### Zones of every type

Kept by `TestZonesWhole` and `TestForwardersAndImports`.

- **A secondary zone is not made unless its primary answers**: the server asks the primary as it makes the zone, and refuses with "Connection refused" or the like. A copy cannot be made ahead of its primary.
- **A copy told to transfer over TLS or QUIC is given its primary's addresses back with the port for it**, `10.0.0.2:853` for an address set as `10.0.0.2`.
- **A zone made with `useSoaSerialDateScheme` has a serial of the day and a count**, 2026101001, and the SOA carries `useSerialDateScheme`. A change to the SOA that does not send it switches it off, so the client always sends it.
- **A forwarder zone is made with one FWD record at its own name** unless `initializeForwarder` is false, which makes it empty.
- **A zone's keys are named, not held**: a transfer key or an update policy takes the name of any key, and the options give the keys the server has (`availableTsigKeyNames`) when asked to.
- **`zones/enable` and `zones/disable` need the right to modify a zone**, where `zones/options/set`, which also takes `disabled`, needs the right to delete it.
- **A question put with `import` writes the answer's records over the ones of that type at the name**, in the closest primary or forwarder zone the server holds for it; it makes a primary zone named for the name when it holds none. The comments of the records written over are lost.

### Asking through another name server

Kept by `TestAuditFindsAForwarderThatIsNotThere` in the acceptance suite.

- **A question for the root's name servers (`.`, NS) is taken**, and any resolver that is up answers it in a few tens of milliseconds.
- **A name server that is not there is given up on after about twenty seconds**, with "request timed out for name server".

### Walking a list

Kept by `TestWalksAndCounts`.

- **`blocked/list`, `allowed/list` and `cache/list` answer for another name than the one asked** when nothing is at it and one name is under it: the first name below that holds something or branches, or with `direction=up` the nearest above. A name that holds something, or branches, or that the list knows nothing of, is answered for itself either way.
- **They give names whole under `zones`**, not labels, and a listed name carries records of its own.

### Accounts, tokens and permissions

Kept by `TestAccountLife`, `TestGroups`, `TestPermissions` and `TestSSO`.

- **`user/createSingleUseToken` puts the token under `response`**, where the other calls that make a token put it beside `status`.
- **Switching an account off keeps its API tokens.** They are refused while it is off and work again when it is switched back on.
- **`zones/list` gives only the zones the account may view**, with no word that others exist. A new account is in Everyone, which may view the Zones and Logs sections and nothing in Settings.
- **The permission lists are set whole**: a section's or a zone's users and groups each go as one table, and whoever is left out is taken off.
- **The single sign-on calls for one user answer "Cluster is not initialized" outside a cluster**: they are for a cluster's nodes to keep each other's users in step. The group map is a list of a remote group and a local one, and an empty one clears it.

### DNSSEC

Kept by `TestDNSSEC`.

- **An unsigned zone's DNSSEC properties are read without error**: status Unsigned, and no keys.
- **A new key signing key stays Published for hours**, until the zone's DNSKEY TTL has passed, before it is Ready for its DS record.
- **The DNSKEY TTL is changed only while every key is Ready or Active**, and a key is retired only once another of its kind is Active ("no successor key").
- **A rollover leaves the old key in the zone, retiring**: the server takes it out when that is safe.

### Logs, statistics and apps

Kept by `TestLogFiles`, `TestQueryLogExport`, `TestMetricsAndStatsDeleted` and `TestAppsInstalledAndRemoved`.

- **Deleting a log file that is not there, and uninstalling an app that is not installed, give no error.**
- **The export of the log of queries is CSV that starts with a byte order mark**, with the headings `RowNumber,Timestamp,ClientIpAddress,Protocol,ResponseType,ResponseRtt,RCODE,Domain,Type,Class,Answer`.
- **The Prometheus metrics are named `queries_total` and the like**, where the document's example has `total_queries`.
- **An app that fails to install leaves a folder behind.** A file that is no zip is refused, but its folder stays under the server's apps, is not listed, and is not cleared by uninstalling; a server with one cannot have another join it as a cluster ("Central Directory corrupt"). Installing a real app under the same name and uninstalling it clears it. The client refuses a file that is no zip before it is sent.

### Settings and backups

Kept by `TestAllSettings` and `TestBackupAndRestore`.

- **The transfer keys are one setting, set whole and with their secrets**: adding one key means sending them all. A cluster refuses to lose the key of its own catalog ("Cannot remove TSIG key").
- **`settings/set` takes names it never gives back**: the certificate passwords and the proxy's parts, which `settings/get` gives under one `proxy` object.
- **A setting a later version brought is passed over without a word**: sent to a server that does not have it, `settings/set` answers ok and changes nothing. 15.5 has no `enableCachePrefetch`, which 15.6 brought. Apart from the names above, every setting a server has is in what `settings/get` gives, so one missing from it is one the server lacks: the client makes that an error once the server has answered, and `settings_set` refuses it before anything is sent.
- **A backup is of what the server has written to disk**, which lags a change to a zone or a list by a few seconds.
- **A restore on a cluster's primary reaches the other nodes when they next fetch the configuration**, not at once.

### In a cluster, the rest

Kept by `TestOnNode` and `TestClusterTakenApart`.

- **A secondary asked to fetch the whole configuration again answers at once and fetches afterwards**, which takes it a second or a few. A call that needs the same part of it, a notify say, waits behind the fetch; its log says "Server configuration was synced from the Primary node successfully" when it is done, which is the only place that does.
- **A secondary told of new times for the cluster can stop answering cluster calls, and why is not known.** With a secondary in the cluster, setting the cluster's times on the primary (`admin/cluster/primary/setOptions`) was followed some seconds later by the secondary logging that it was told of the change and never that it fetched it; from then on a notify, a resync, `updatePrimary` and the primary's request that it leave all waited on it without end, while every other call it has went on answering, and a node cut off so is left half in the cluster. It was seen on two 15.6 servers eight times, by hand with `curl` among them, so it is not the client's doing; most surely on servers that had been through the suite's earlier stages, and once on a cluster made fresh. It is not every time: the tool suite sets the same times with a secondary in the cluster on every run and has not met it. `TestClusterTakenApart` therefore sets the times while the primary is the only node, and checks them on a node that joins afterwards.
- **The server sends nothing of an answer until a call is done**, so a client that gives up on an answer that has not begun gives up on slow calls. The client waits two minutes.
- **`node` is ignored by a server in no cluster**: the call is answered by the server asked.
- **The calls the nodes make of each other are taken from an administrator too**: the transfer of the configuration answers with the whole of it as a zip, some megabytes, and a secondary admitted with a certificate that is none is refused with "ASN1 corrupted data".
- **A secondary that has just joined gives no time it last fetched the configuration** until it has fetched once.
- **A secondary that has just joined is refused promotion for a few seconds**, with "the Cluster Secondary zone does not exist" or "could not resolve DANE TLSA record for host", until it has transferred the cluster's own zone, where the primary's certificate record is.
- **Of the 139 calls, 69 are passed on with `node`**, and the list of zones, the settings and everything of DHCP are not among them: a node reached only through another could answer only part of what is asked of a server.

## What the document gets wrong

The reader allows for these, and its tests keep them:

- Two sections write their marker `URL\:` rather than `URL:\` (the two Get Metrics calls).
- Three example addresses have no closing backtick (Unsign Zone, Get DS Info, Get User Details).
- One example address is not on `localhost` (Initialize And Join Cluster).
- A call's `WHERE:` list sometimes misses a parameter its example address carries (`value` for Delete Record), so both are read.
- One parameter's name is closed a space late (`primaryZoneTransferProtocol` and then a space, for Set Zone Options), which used to end the list there.
- One example address has a parameter with no name (`&=pageNumber=1` for Query Logs), which the reader passes over.
- Five names in example addresses are ones the server no longer reads and no call's list gives: `allowRecursion`, `allowRecursionOnlyForPrivateNetworks`, `preferIPv6` and `useNxDomainForBlocking` for Set DNS Settings, and `zoneTransferNameServers` for Set Zone Options. They are the whole of `unsent.txt`.
