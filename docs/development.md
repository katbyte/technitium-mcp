# Development

```bash
make tools      # build the pinned dev tools into .tools/bin
make build      # compile, with the version from git
make test       # unit tests with the race detector: canned servers, and the client against the API document
make testacc    # both live suites on real Technitium servers in Docker: one, then two, then the two as a cluster
make lint       # golangci-lint with the azproviderlint plugin
make apicheck   # how much of the Technitium API the SDK wraps
make check-all  # everything
```

| where | what |
|---|---|
| `sdk/technitium` | the client: one server, typed calls |
| `sdk/technitium/technitiumtest` | a canned server for tests, which holds every request against the API document |
| `sdk/apidoc`, `api-defs/` | the vendored API document and its reader |
| `lib/servers` | the named servers one process works on |
| `tools/` | the MCP tools |
| `cli/` | the commands and settings |
| `acceptance/` | everything that runs against real servers: the SDK in `technitium/`, the tools in `tools/` |

## Tests

`make test` needs no server. The client is tested against a canned one that refuses any request the API document does not describe, and the tools end to end over an in-memory MCP session against two canned servers.

Everything else runs against **real Technitium servers in Docker**, because a canned server can only confirm what was already believed.

| | covers | command |
|---|---|---|
| `acceptance/technitium/` | the `sdk/technitium` client: every method, against a real server | `make testacc-sdk` |
| `acceptance/tools/` | the tools: every one of them, the journeys, and the built binary | `make testacc-tools` |

The live suites run on servers `.scripts/testenv.sh` starts, and refuse any others. Each suite runs three times on the same servers, in order: one server (`up single`), a second started beside it (`add`), and the two made a cluster, which the suite does itself through `sdk/technitium`. A last pass then runs the tests that take the cluster apart - a node leaving, a secondary promoted, the cluster deleted - alone, since nothing else can run beside them. `make testacc TOPOLOGIES=cluster` goes straight to the cluster; `TECHNITIUM_TEST_IMAGE=technitium/dns-server:15.5.0 make testacc` runs another version. The script gives each server the Query Logs (Sqlite) app, which the log search reads, from the file the server's own app store names: fetched once and kept in `.tools/cache`. For the DHCP tests it also hands the suites a small image with a DHCP client in it (busybox), which they run on the servers' network for a moment as a machine asking for a lease; nothing outside that network hears it.

Each run of the tool suite records every tool it calls and fails if a registered tool was never seen to answer. The SDK suite fails if a client method has no live test.

The journeys (`acceptance/tools/journey_*_test.go`) chain the tools the way a session does and read the server back through the client after every write, because a tool's own answer is not proof: a first setup made from nothing with the tools alone, audited to nothing of its own, taken down again, and the server found holding exactly what it held before; a host moved to a new address with everything that pointed at it; every finding an audit can fix, fixed, audited again and put back; a zone's whole life from made to signed to deleted; a mistake undone from a backup; a token that may only look, held to that across every tool; an administrator's token without the write switches; many calls at once; every write done twice; every read leaving the servers unchanged; and two servers that differ brought into line.

`acceptance/tools/binary_test.go` builds the real binary and speaks to it as a client does, which the rest never touches: `serve` over stdio saying nothing on stdout but the protocol, the flags registering what they say they do, the configuration file in the working directory read, `serve --listen` over HTTP with its bearer token, a start that cannot be made refused with the reason, and the `info` and `tools` commands.
