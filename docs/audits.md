# The audits

Each audit sweeps every zone on every server for one kind of problem. Every finding names what is wrong, where, and how to fix it. All audits only read.

The short names under each audit are the kinds of finding it reports. Pass them as `problems` to ask for some kinds only.

## `audit_all`

Every audit in one reading of the servers, counts only: where to look first. It runs every audit below but `audit_split`, which asks other people's name servers, and `audit_names`, which checks a list you give it.

## `audit_servers`

Where servers meant to hold the same do not: a zone one lacks (and, in a cluster, that it is not in the catalog the other node follows), a zone two servers each hold as their own primary, the records that differ, a copy behind its primary or whose transfer failed or that has expired.

- `zone_missing`: a zone some of the servers hold and others do not
- `two_primaries`: a zone two servers each hold as their own primary: nothing carries a change from one to the other
- `records_differ`: a zone whose records are not the same on every server holding it
- `copy_behind`: a secondary whose serial is not its primary's: it has not taken the primary's last changes
- `sync_failed`: a secondary whose last transfer from its primary failed
- `copy_expired`: a secondary that has expired: it has gone without a transfer for so long the server no longer answers from it
- `notify_failed`: a primary that could not tell a secondary of its last change

## `audit_targets`

Records that point at a name and end nowhere: a CNAME to a name with no record, a loop, a long chain, a CNAME at a zone's own name or beside other records, an MX, SRV or NS whose target is missing or is a CNAME.

- `dangling`: a CNAME or ANAME whose target, or a name further down its chain, has no record in the zone it belongs in
- `loop`: a chain of CNAMEs that comes back to a name it has passed
- `long_chain`: a name that takes more than four CNAMEs to reach an address
- `cname_at_apex`: a CNAME at a zone's own name, which a zone's SOA and NS records cannot share
- `cname_with_others`: a CNAME beside other records at one name, which a CNAME cannot share
- `target_missing`: an MX, SRV or NS whose target has no record in the zone it belongs in
- `target_is_cname`: an MX, SRV or NS whose target is a CNAME, which those may not point at

## `audit_reverse`

Addresses and PTRs that disagree: an address with no PTR (with the call that adds it), a PTR naming a host that does not hold the address, several PTRs for one address, a network with addresses in use and no reverse zone.

- `no_ptr`: an address a name holds, with a reverse zone for it on the server and no PTR record in it
- `ptr_stale`: a PTR naming a host that the server's zones say does not hold that address, or has no record
- `ptr_elsewhere`: an address whose PTR names a host other than any that holds it
- `several_ptrs`: an address with more than one PTR record
- `no_reverse_zone`: a subnet with addresses in use for which the server holds no reverse zone

## `audit_overlaps`

Records never served because a zone further down on the same server answers for the name; one name with addresses in two networks; the odd public address in a zone of private ones, or the reverse; and every wildcard, which makes a mistyped name resolve.

- `shadowed`: a record at a name that belongs to a zone further down on the same server, which answers instead
- `addresses_apart`: one name with addresses in different networks
- `wildcard`: a wildcard record: every name under it with no record of its own gets its answer
- `address_out_of_place`: one or two public addresses in a zone of private ones, or private in a zone of public

## `audit_naming`

Probable slips: a stray space or invisible character, an underscore in a host name, two names a typing slip apart, a TTL under a minute, over a week, or far from the one the rest of its zone has, and one host's names written two ways (`emby-dock` beside `jf.dock`).

- `space`: a space out of place, or an invisible character, in a name, a value or a comment
- `underscore`: an underscore in the name of a record that holds an address or a CNAME: a host's name may not have one
- `near_duplicate`: two names in one zone that differ by a slip of the keyboard
- `ttl_short`: a TTL under a minute
- `ttl_long`: a TTL over a week
- `ttl_outlier`: a TTL ten times, or a tenth of, the one nearly all the zone's records have
- `named_two_ways`: a name written with a hyphen beside the same host's names written under it with a dot

## `audit_state`

What is switched off or set to vanish: disabled zones and records, records set to delete themselves.

- `zone_disabled`: a zone that is disabled: the server holds it and answers nothing from it
- `record_disabled`: a record that is disabled
- `record_expires`: a record set to delete itself a while after its last change

## `audit_dhcp`

DHCP against itself and against the zones: one server leasing alone, two leasing the same addresses, a scope running out, naming name servers that are not these or naming one server twice, reservations that cannot work (an address outside the network, a hardware address of all zeros) or have no name in DNS, a record made by hand at an address a scope gives out or has given to another machine, and records the server wrote for a lease that is gone.

- `dhcp_one_server`: one server alone leases addresses, with another asked that could and does not
- `ranges_overlap`: two servers leasing the same addresses, which do not tell each other what they have given
- `pool_low`: a scope with a tenth or less of its addresses free
- `scope_domain_unknown`: a scope whose domain no server asked holds a zone for
- `scope_dns_unknown`: a scope telling machines to resolve through an address that is no server asked, none configured here and no node of their cluster
- `scope_dns_same`: a scope telling machines to resolve through one server twice, as this server and by its address
- `scope_dns_missing`: a scope whose name servers leave out a server asked
- `reservation_outside`: a reservation for an address outside its scope's network
- `reservation_no_mac`: a reservation for a hardware address of all zeros, which no machine has
- `reservation_shared`: one address reserved for more than one machine
- `reservation_leased_away`: a reserved address that another machine holds a lease on
- `reservation_no_record`: a reservation with no address record for its name, or with no name and no record naming its address
- `reservation_record_elsewhere`: a reservation whose name holds another address in DNS
- `static_in_pool`: a record made by hand at an address a scope gives out by itself, with no reservation
- `address_leased_elsewhere`: a record made by hand at an address a scope has leased to another machine
- `lease_name_taken`: a lease under a name that a record made by hand holds for another address
- `record_left_behind`: a record the server wrote for a lease or a reservation that is no longer there

## `audit_blocking`

What the servers block: blocking switched off or paused with lists still set, block lists not fetched or holding nothing, a blocked name that blocks nothing because a zone on the server answers for it or an allowed entry wins, an entry another already stands for, and servers that do not block alike.

- `blocking_off`: blocking switched off on a server that has lists or names to block
- `blocking_paused`: blocking paused: off for a while, coming back on by itself
- `lists_not_fetched`: block lists more than an hour past the time they were due to be fetched, or not fetched since they were set
- `lists_empty`: block lists that hold no names between them: none has loaded
- `entry_never_applies`: a blocked name that a zone on the server answers for, or that the server refuses itself, before any list is looked at
- `entry_overridden`: a blocked name that is on the allowed list too, which wins
- `entry_redundant`: an entry with another above it on the same list, which already stands for it
- `blocking_differs`: servers that do not block alike: on and off, other lists, or names on one's own lists and not the other's

## `audit_zones`

A zone's own records and options against the servers that hold it: a name server it names that is none of them and no node of their cluster, a holder none of its NS records names, an SOA naming a primary that is not the server holding it as one - what a renamed server leaves behind - and a primary that gives its copies no transfer or no word of a change; reverse zones of one address each, and ones with no PTR in them.

- `ns_unknown`: an NS record at a zone's own name for a server that is none of those asked, and no node of their cluster
- `reverse_zone_per_address`: reverse zones of one address each under a /24 no zone holds, as the server makes for a scope smaller than a /24
- `reverse_zone_empty`: a reverse zone with no PTR record in it
- `ns_missing`: a server holding a zone, as its primary or as a copy, that none of the zone's NS records names
- `soa_primary`: an SOA record naming a primary other than the server that holds the zone as its primary
- `transfer_denied`: a primary that lets nobody transfer a zone another server asked holds a copy of
- `notify_none`: a primary that tells nobody when a zone changes, with a copy on another server asked

## `audit_security`

What is left open: a server resolving for anyone, a console over plain HTTP alone, the password a server ships with, a zone anyone may transfer or change with no key, an API token unused for ninety days, a server behind the version that is out.

- `default_password`: the admin account still has the password the server ships with
- `recursion_open`: a server that resolves any name for anyone who can reach it
- `console_plain`: a web console and API that answer over plain HTTP alone
- `transfer_open`: a zone anyone who can reach the server may transfer whole
- `update_open`: a zone that may be changed by a DNS update with no key asked for
- `token_unused`: an API token not used in ninety days
- `update_available`: a server behind the version that is out

## `audit_cluster`

A cluster that is not whole: a node the others cannot reach, nodes that do not agree who the nodes are, a secondary that has stopped fetching the configuration, nodes on different versions, a cluster of one, a node that is not configured here and so was read by no audit, and a server left outside a cluster the others are in.

- `node_unreachable`: a node of the cluster that another node cannot reach
- `nodes_disagree`: nodes of one cluster that list different nodes: one was dropped and still thinks it is in
- `config_stale`: a secondary node that has not fetched the primary's configuration for more than twice as long as it is set to
- `versions_differ`: nodes of one cluster on different versions of the server
- `single_node`: a cluster with its primary and no other node
- `node_not_configured`: a node of the cluster that is not among the servers configured here, so no audit read it
- `outside_cluster`: a server in no cluster, while others asked are in one

## `audit_access`

Accounts and permissions that make a server easier to take than it need be: an administrator who signs in with a password alone, an account nobody has ever used, a switched-off account whose tokens are still there, the admin account the server ships with left on beside another administrator, a section every account may change.

- `admin_no_two_factor`: an account in the Administrators group with no second factor
- `account_never_used`: an account that is switched on, has never signed in and has no token
- `disabled_with_tokens`: an account that is switched off and still has API tokens, which work again when it is switched back on
- `everyone_may_change`: a section the Everyone group may modify or delete in
- `stock_admin`: the admin account the server ships with switched on beside another administrator

## `audit_dnssec`

What the keys of the signed zones are waiting for or leave weak: a key that waits for its DS record at the parent zone, a key made and never put in the zone, a zone whose names anyone can list, a zone signing key the server never replaces, an algorithm no longer trusted, signatures the server has let expire.

- `ds_wanted_at_parent`: a key signing key that is Ready: its DS record is to be given to the parent zone
- `key_not_published`: a key that was generated and never put in the zone
- `nsec_walkable`: a zone signed with NSEC, whose names anyone can list
- `key_never_replaced`: a zone signing key in use that the server is set never to replace
- `weak_algorithm`: a key of an algorithm with MD5 or SHA-1 in it
- `signature_expired`: a signed zone holding signatures past their expiration, which the server should have renewed

## `audit_queries`

What the servers' resolving and the last day of queries say is wrong: a server that cannot resolve a name right now, a forwarder of its that does not answer, fails or is slow (each is asked), a server with no log of queries, one answering too much with a failure, one client asking for most of everything, a busy client with no name, a name asked for far more often than its TTL allows, and the names in the servers' own zones that clients keep asking for and that do not exist.

- `not_resolving`: a server that could not resolve a name for itself when asked
- `forwarder_unanswering`: a forwarder that gave the server no answer when asked for the root's name servers
- `forwarder_failing`: a forwarder that answered that with a failure or a refusal
- `forwarder_slow`: a forwarder that took half a second or more to answer
- `no_query_log`: a server with no app keeping a log of queries
- `failing`: a server that answered five or more in every hundred of the last day's queries with a server failure
- `one_client`: one client that asked sixty or more in every hundred of the last day's queries
- `name_not_found`: a name under a zone the servers hold that was asked for five or more times in the last day and does not exist
- `client_unnamed`: a client that asked a thousand or more queries in the last day and has no name
- `client_not_caching`: a name the servers hold asked for ten times more in the last day than its TTL lets a client that caches ask

## `audit_apps`

The DNS apps the servers run: an app behind the version the store has, an app one server runs and another does not, and one they run at different versions or configured differently.

- `app_update`: an installed app the store has a newer version of
- `app_only_on`: an app installed on some of the servers asked and not on others
- `app_versions_differ`: an app that is not at one version on every server
- `app_config_differs`: an app that is not configured alike on every server

## `audit_split`

The inside and the outside of a split horizon, by asking a resolver you name for every name the zones hold: an override whose public name is gone, a private address the outside is given, a name that resolves outside and has no record here, and a parallel domain that does not answer as the zone it mirrors. Not part of `audit_all`: it asks other people's name servers.

- `public_gone`: a name with an address here, in a zone whose other names resolve outside, that the outside no longer has: an override left behind, or a name never published
- `private_outside`: a name the outside is given a private address for: the inside's addressing, published
- `no_override`: a name given in names that resolves outside and has no record here: a client inside is sent round by the outside address
- `mirror_differs`: a name under a mirror's other domain that ends somewhere else than the name it mirrors, or nowhere

## `audit_names`

A list of host names - every name a reverse proxy routes - each said to have records and where it ends, or why not. It is in the `core` toolset, so it is always loaded.
