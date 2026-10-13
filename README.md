# technitium-mcp - a Technitium DNS Server MCP server, CLI and Go SDK

[![GitHub release](https://img.shields.io/github/v/release/katbyte/technitium-mcp?color=blueviolet)](https://github.com/katbyte/technitium-mcp/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/katbyte/technitium-mcp?color=00ADD8)](https://github.com/katbyte/technitium-mcp/blob/main/go.mod)
[![License](https://img.shields.io/github/license/katbyte/technitium-mcp?color=blue)](https://github.com/katbyte/technitium-mcp/blob/main/LICENSE)
![build](https://github.com/katbyte/technitium-mcp/actions/workflows/build.yaml/badge.svg)
![tests](https://github.com/katbyte/technitium-mcp/actions/workflows/pr-tests.yaml/badge.svg)
![lint](https://github.com/katbyte/technitium-mcp/actions/workflows/pr-golangci-lint.yaml/badge.svg)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/katbyte/technitium-mcp/badges/coverage.json)](https://github.com/katbyte/technitium-mcp/actions/workflows/coverage.yaml)

Lets an AI assistant read, check and manage [Technitium DNS Server](https://technitium.com/dns/). It is an [MCP](https://modelcontextprotocol.io) server, a command line and a Go client.

**Finding a problem is code. Fixing it is a decision.** The audits sweep every zone on every server and return a list of what is wrong, each with its fix. Nothing changes until you turn changes on and a tool is called.

```bash
go install github.com/katbyte/technitium-mcp@latest
```

Make an API token on the server (web console, Administration, Sessions, Create Token) and put it in `~/.technitium-mcp`:

```sh
SERVER=http://nas:5380
TOKEN=<token>
```

Register it with Claude Code in `.mcp.json`:

```json
{ "mcpServers": { "technitium": { "command": "technitium-mcp", "args": ["serve"] } } }
```

Then ask for `audit_all`. Needs Technitium DNS Server 15.0 or newer.

## What it does

- **Works on several servers at once.** A read asks every server and shows the answers side by side, so differences stand out.
- **Only reads, until told otherwise.** Changing needs `--enable-write`. Deleting needs `--enable-delete` as well.
- **Shows a change first.** Every change takes `dry_run`, and reads back what it did afterwards.
- **Covers the whole server.** 106 tools: zones, records, cache, blocking, DHCP, DNSSEC, clusters, accounts, apps, settings, backups and logs.
- **Keeps secrets out.** No password, token or key is shown in an answer or a log.

## The audits

Every audit only reads. The full rules for each are in [docs/audits.md](docs/audits.md).

| audit | what it catches |
|---|---|
| [`audit_all`](docs/audits.md#audit_all) | Runs the audits below in one pass and gives counts. Start here. |
| [`audit_servers`](docs/audits.md#audit_servers) | Zones and records that differ between servers. Fix with `zone_resync` or `record_set`. |
| [`audit_targets`](docs/audits.md#audit_targets) | Records that point at a name and end nowhere. Fix with `record_set` or `record_delete`. |
| [`audit_reverse`](docs/audits.md#audit_reverse) | Addresses and reverse entries that disagree. Fix with `record_set`. |
| [`audit_overlaps`](docs/audits.md#audit_overlaps) | Records never served, and every wildcard. Fix with `record_delete`. |
| [`audit_naming`](docs/audits.md#audit_naming) | Probable typing slips and odd lifetimes. Fix with `record_set`. |
| [`audit_state`](docs/audits.md#audit_state) | What is switched off or set to delete itself. Fix with `zone_edit` or `record_set`. |
| [`audit_zones`](docs/audits.md#audit_zones) | Zones whose own records do not name their servers. Fix with `zone_edit` or `record_set`. |
| [`audit_security`](docs/audits.md#audit_security) | What is left open to the network. Fix with `settings_set` or `zone_edit`. |
| [`audit_access`](docs/audits.md#audit_access) | Weak accounts and permissions. Fix with `user_set` or `session_delete`. |
| [`audit_cluster`](docs/audits.md#audit_cluster) | A cluster that is not whole. Fix with `cluster_edit`. |
| [`audit_dnssec`](docs/audits.md#audit_dnssec) | Signing keys that wait on something or are weak. Fix with `dnssec_key_edit`. |
| [`audit_queries`](docs/audits.md#audit_queries) | Failing forwarders and odd patterns in a day of queries. Fix with `settings_set`. |
| [`audit_apps`](docs/audits.md#audit_apps) | Apps out of date or not alike across servers. Fix with `app_install`. |
| [`audit_blocking`](docs/audits.md#audit_blocking) | Blocking that is off, empty or uneven. Fix with `block_switch` or `block_lists_set`. |
| [`audit_dhcp`](docs/audits.md#audit_dhcp) | Where DHCP and DNS do not agree. Fix with `dhcp_scope_set` or `dhcp_reservation_set`. |
| [`audit_split`](docs/audits.md#audit_split) | Inside against outside, by asking a resolver you name. Not in `audit_all`. Fix with `record_set`. |
| [`audit_names`](docs/audits.md#audit_names) | Checks a list of host names you give it. Fix with `record_set`. |

## Tools

Tools are named for what they act on, such as `zone_list` or `record_set`, and grouped into toolsets. Only `core` loads by default, to keep a session small.

| toolset | what it is for | tools |
|---|---|---|
| `core` | See what the servers are and hold. Always loaded. | 7 |
| `audit` | Find what is wrong. | 17 |
| `ops` | Settings, statistics, logs and backups. | 17 |
| `edit` | Change zones and records. | 12 |
| `block` | What the servers refuse to resolve. | 9 |
| `dhcp` | Scopes, leases and reservations. | 8 |
| `dnssec` | Sign zones and manage keys. | 7 |
| `cluster` | Make, grow, shrink and end a cluster. | 8 |
| `admin` | Accounts, groups, tokens and permissions. | 16 |
| `apps` | The DNS apps a server runs. | 5 |

```sh
TECHNITIUM_TOOLSETS=audit                                    # find what is wrong
TECHNITIUM_TOOLSETS=edit,dhcp TECHNITIUM_ENABLE_WRITE=true   # change records and reservations
```

## More

- [docs/tools.md](docs/tools.md): every tool, choosing which load, and what a change does before it is made.
- [docs/configuration.md](docs/configuration.md): every flag and setting, several servers, running over HTTP, and Docker.
- [docs/audits.md](docs/audits.md): what each audit looks for.
- [docs/client.md](docs/client.md): using the Go client on its own.
- [docs/development.md](docs/development.md): building, the folders, and how the tests run.
- [docs/ROADMAP.md](docs/ROADMAP.md): the design rules, known limits and what is not built.
- [api-defs/README.md](api-defs/README.md): where the server differs from its own API document.
- [CONTRIBUTING.md](CONTRIBUTING.md): how changes and releases are made.

## How this is built

- The code is written with Claude Code. I review it, and prune or rework it until it has the shape I want.
- I set the design, the scope and the audit rules, and decide what stays.
- Every tool and every client method must have a live test against a real Technitium server in Docker. CI fails if one is missing.
- The live tests run three ways: on one server, on two, and on the two joined as a cluster.
- CI also runs unit tests, golangci-lint, CodeQL, govulncheck, a Trivy vulnerability scan of the built binary, and a check that vendored dependencies match.
- Workflows are checked with actionlint, yamllint and zizmor. Scripts are checked with shellcheck, and docs with typos and markdownlint.
