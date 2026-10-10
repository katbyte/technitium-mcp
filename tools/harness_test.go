package tools

import (
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	mcpregistry "github.com/katbyte/go-kt/mcp/registry"
	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The tools end to end against canned Technitium servers: the requests a
// handler makes and the answer it projects, without a container. There are
// two servers, dock and rpi, because every tool is about several: what one
// holds and the other lacks is what most of these tests are about. The
// canned servers hold every request against the API document; the acceptance
// suite proves the canned answers match servers that are running.

// everything is the options that register every tool: the ones that change a
// server, and the ones that delete.
var everything = Options{EnableWrite: true, EnableDelete: true}

// pair is two canned servers and the set a session is given for them.
type pair struct {
	dock, rpi *technitiumtest.Server
	set       *servers.Set
}

func newPair(t *testing.T) *pair {
	t.Helper()

	p := &pair{dock: technitiumtest.New(t), rpi: technitiumtest.New(t)}
	set, err := servers.New([]string{"dock=" + p.dock.URL, "rpi=" + p.rpi.URL}, []string{technitiumtest.Token})
	if err != nil {
		t.Fatal(err)
	}
	p.set = set

	return p
}

// both gives the two servers the same answer to a call.
func (p *pair) both(path, response string) {
	p.dock.Answer(path, response)
	p.rpi.Answer(path, response)
}

// session connects an in-memory MCP client to a server registering every
// tool against the pair, with the given options.
func (p *pair) session(t *testing.T, opts Options) *acctest.Suite {
	t.Helper()

	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	opts.Toolsets = []string{mcpregistry.All}
	if _, err := RegisterAll(srv, p.set, opts); err != nil {
		t.Fatal(err)
	}

	return connect(t, srv)
}

// unreachable is a set whose servers are never called, for the tests of
// which tools are registered.
func unreachable(t *testing.T) *servers.Set {
	t.Helper()

	set, err := servers.New([]string{"dock=http://127.0.0.1:1", "rpi=http://127.0.0.1:2"}, []string{technitiumtest.Token})
	if err != nil {
		t.Fatal(err)
	}

	return set
}

// register is the names RegisterAll registers for the options.
func register(t *testing.T, opts Options) []string {
	t.Helper()

	names, err := RegisterAll(mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil), unreachable(t), opts)
	if err != nil {
		t.Fatal(err)
	}

	return names
}

// refused is what RegisterAll refuses the options with.
func refused(t *testing.T, opts Options) string {
	t.Helper()

	_, err := RegisterAll(mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil), unreachable(t), opts)
	if err == nil {
		t.Errorf("%+v was accepted", opts)

		return ""
	}

	return err.Error()
}

// hostRegistry registers the tools queued on a registry the test built by
// hand, for what RegisterAll does not reach: a tool of the test's own.
func hostRegistry(t *testing.T, r *registry) *acctest.Suite {
	t.Helper()

	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	if _, err := r.queued().Register(srv, mcpregistry.Selection{EnableDelete: true}); err != nil {
		t.Fatal(err)
	}

	return connect(t, srv)
}

// connect opens an in-memory MCP client on a server, as go-kt's suite: every
// call goes through the protocol, as a client's does.
func connect(t *testing.T, srv *mcp.Server) *acctest.Suite {
	t.Helper()

	suite, err := acctest.Connect(t.Context(), srv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = suite.Session.Close() })

	return suite
}

// listed is every tool a session was given, as a client sees them.
func listed(t *testing.T, suite *acctest.Suite) []*mcp.Tool {
	t.Helper()

	res, err := suite.Session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}

	return res.Tools
}
