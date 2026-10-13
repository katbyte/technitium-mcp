# Configuration

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

## Configuration file

A `.technitium-mcp` file in `$HOME`, and one in the working directory read over it key by key, so a project's file needs only the settings it changes. Keys are the environment variable names, with or without the `TECHNITIUM_` prefix. A flag or an environment variable beats either file.

```sh
# one server
SERVER=http://nas:5380
TOKEN=<token>
```

```sh
# several, each under a name the tools take
SERVER=ns1=http://192.168.1.2:5380,ns2=http://192.168.1.3:5380
TOKEN=ns1=<token>,ns2=<token>
```

Every node of a cluster is configured by its own address. The API has a way to ask one node through another, and the SDK wraps it (`OnNode`), but the servers pass on only half their calls that way - not the list of zones, the settings or anything of DHCP - so a node reached through another could answer only some of the tools.

## Running as a service

`serve --listen :8080` serves the MCP Streamable HTTP transport at `/mcp` (and `GET /healthz`) instead of stdio. Clients must send `Authorization: Bearer <token>` with the token `TECHNITIUM_AUTH_TOKEN` holds, and the server refuses to start without one unless `--allow-no-auth` says anyone who can reach the port may use every tool.

```bash
claude mcp add --transport http technitium http://nas:8080/mcp --header "Authorization: Bearer $TECHNITIUM_AUTH_TOKEN"
```

## Docker

`docker-compose.yml` runs the released image as an always-on HTTP server, reading its secrets from a gitignored `.env`; see `.env.example`. `make docker` builds the same image from source.
