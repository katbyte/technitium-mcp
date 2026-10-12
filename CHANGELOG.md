# Changelog

## 0.2.1 (2026-10-12)

- **A restore that would stop a server is refused.** Technitium 15.6.1 fails, and then will not start again, when a backup's zone is put back onto a server that no longer holds it. `settings_restore` now refuses that on 15.6.1, names the zones, and says to make each as an empty zone first and restore again. Restoring the accounts with the zones is not affected.

- **One home for the tests that run against real servers.** They are all under `acceptance/`, the client's and the tools' side by side, and the code checks now read them as they read everything else.

## 0.2.0 (2026-10-10)

- **A record of every change.** With `TECHNITIUM_LOG=info`, each call of a tool that changes or deletes something is logged in one line: which tool, what it was sent, and whether it worked, was refused or failed. Passwords, one-time codes, key secrets and app configuration are blanked, and a dry run is marked as one.

- **Installing an app says what it is.** `app_install` tells the client that it has the server fetch something from outside and run it.

- **A first setup, start to finish, as a test.** One live test builds a whole setup with the tools alone, checks that every audit finds nothing wrong with it, takes it all down again, and checks the server is left exactly as it was.

- **Nothing secret is shown.** The live tests read everything every tool says, all run long, and fail if a password, token or key appears.

- **go-kt v0.6.2**, from v0.5.1.

## 0.1.0 (2026-10-10)

The first release: an MCP server, a command line and a Go client for Technitium DNS Server.

- **Several servers as one.** Any number of servers are configured by name, with a token each or one for all. A read asks every server and sets the answers side by side, saying where they differ; a change names the server it is for. Clusters are understood: which node is the primary, and where a zone can be changed.

- **Safe by default.** Every tool only reads unless `--enable-write` is given, and none deletes without `--enable-delete` as well. Every change has a dry run, and reads back what it did. No password, token or secret is ever read back, and the tools refuse to lock themselves out.

- **Reading.** What each server is and what its token may do; its zones and their records as one table; every setting; what it really answers for a name, with the chain, beside what other resolvers say; what its cache holds; who asked for what in its query logs; and what it did over a window of time.

- **Finding things.** One search across every zone: what holds an address, what points at a name, or any record by name, value, type or comment. A list of host names can be checked at once, saying which have records and why the rest do not.

- **Audits.** Seventeen of them, each giving findings with a fix, and one that runs them all: servers that do not hold the same; records that lead nowhere; addresses and their reverse entries that disagree; records never served; probable typing slips and odd lifetimes; zones whose own records do not name their servers; DHCP and DNS that do not agree; blocking that is off or blocks nothing; what is left open to the network; weak accounts and permissions; signing keys that wait on something or are weak; a cluster that is not whole; forwarders that fail or are slow; apps out of date; and a zone held against what the outside world is told.

- **Records.** Records of every type the server has are set, deleted and repointed from one line each, with the matching reverse entry kept in step and the comments the server would drop kept.

- **Zones.** Zones of every type are made, changed, copied, converted, imported from a zone file, exported, resynced and deleted, with who may ask, transfer and update each one.

- **DNSSEC.** A zone is signed and unsigned, its keys added, published, rolled over and retired, and the records its parent needs are given.

- **DHCP.** Scopes with everything they hand out, leases, and reservations. A change that the server would accept and that could not work is refused, such as a range another server already leases.

- **Blocking.** Whether a name is blocked and by which list; names blocked and allowed one at a time or in bulk; blocking switched on, off or paused; and the lists that are fetched.

- **Clusters.** A cluster is made, joined, changed, has a secondary promoted, and is shrunk or ended.

- **Accounts and permissions.** Users, groups, sessions and API tokens, who may do what in each section and zone, single sign-on, and the tool's own account.

- **Settings and upkeep.** Any setting is changed, with one a server's version does not have refused rather than silently passed over. Transfer keys are added and removed one at a time. A server is backed up to a file only its owner can read, and parts are put back. Logs are listed, read, exported and deleted, and statistics cleared.

- **Apps.** Apps are listed with what the store offers, installed, configured and removed.

- **The Go client.** `sdk/technitium` covers every one of the 139 calls in Technitium's API document and every parameter it gives them. The document is kept in the repository, and the tests fail when the client stops matching it.

- **Running it.** The `serve`, `tools`, `info` and `version` commands; settings from flags, `TECHNITIUM_*` environment variables or a `.technitium-mcp` file; toolsets to offer only some of the tools; and a container image.

- **Tested on real servers.** Every tool and every client call is run against throwaway Technitium servers, alone, as a pair and as a cluster, along with the built program itself.
