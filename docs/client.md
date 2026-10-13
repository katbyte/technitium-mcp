# The Go client

`sdk/technitium` is a plain Go client for the Technitium API with no knowledge of MCP. Beneath it are the standard library and [go-kt's HTTP package](https://github.com/katbyte/go-kt/tree/main/chttp), which itself uses only the standard library. To talk to a Technitium server from Go, take it and ignore the rest:

```go
import "github.com/katbyte/technitium-mcp/sdk/technitium"

client, err := technitium.New("http://nas:5380", os.Getenv("TECHNITIUM_TOKEN"))
zones, err := client.Zones(ctx, technitium.ZoneFilter{})
```

It has 160 methods covering **every one of the 139 calls in Technitium's API document, and every parameter the document gives them**. `make apicheck` reads the calls out of the vendored document and says how many are wrapped. The unit tests fail when a call the client makes is not the document's, when a parameter it sends is not one the document gives the call, when a secret is sent in an address rather than a body, when a method has no test - and when a parameter the document gives a call is sent by no test, unless it is listed with why in `api-defs/unsent.txt`, which holds five names the server no longer reads. Every method is also run against a real server.

Records of every type are written from one line, as a zone file writes them:

```go
data, err := technitium.ParseValue("HTTPS", "1 . alpn=h2,h3")
rec, err := client.AddRecord(ctx, technitium.NewRecord{Zone: "example.com", Name: "www.example.com", Type: "HTTPS", TTL: 300, Data: data})
```

A read is asked for again when the connection dropped or a gateway in front of the server could not reach it; a write is sent once. A call is given two minutes: the server sends nothing of an answer until the call is done, and a server joining a cluster or a backup being restored takes as long as there is to do. A redirect is refused rather than followed, since following one turns a write into a read with nothing in it. Nothing is logged unless the client is handed a logger, and then every request and answer is traced with the token, passwords and keys blanked.

What the document gets wrong or leaves out, found by running against real servers, is written down in [api-defs/README.md](../api-defs/README.md).
