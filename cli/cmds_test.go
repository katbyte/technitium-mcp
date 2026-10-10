package cli

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
	"github.com/katbyte/technitium-mcp/tools"
	"github.com/spf13/viper"
)

// viper is global, so none of these can run in parallel.
const (
	coreTool   = "zone_list"
	cmdServe   = "serve"
	flagServer = "--server"
	flagToken  = "--token"
)

// isolate keeps a developer's own settings out of a run: with real servers
// configured in ~/.technitium-mcp or the environment, info would connect to
// them.
func isolate(t *testing.T) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	for _, env := range envNames {
		t.Setenv(env, "")
	}
}

// run executes the command tree the binary builds and returns what it printed.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()

	isolate(t)

	root, err := Make()
	if err != nil {
		t.Fatalf("Make: %v", err)
	}
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err = root.Execute()

	return out.String(), err
}

//nolint:paralleltest // viper is global state; Make mutates it
func TestMakeBuildsTheCommands(t *testing.T) {
	out, err := run(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}
	for _, want := range []string{cmdServe, "info", "version", "tools"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing from --help:\n%s", want, out)
		}
	}

	out, err = run(t)
	if err != nil || !strings.Contains(out, "technitium-mcp help") {
		t.Errorf("bare invocation = %q, %v", out, err)
	}
}

//nolint:paralleltest // viper is global state; Make mutates it
func TestVersionCommand(t *testing.T) {
	out, err := run(t, "version")
	if err != nil || !strings.HasPrefix(out, "technitium-mcp ") {
		t.Errorf("version = %q, %v", out, err)
	}
}

// A command that talks to the servers refuses to start without one and a
// token for each, before any connection is attempted, and says which is
// missing.
//
//nolint:paralleltest // viper is global state; Make mutates it
func TestCommandsNeedServers(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"info with nothing":              {[]string{"info"}, "no server is configured"},
		"serve with nothing":             {[]string{cmdServe}, "no server is configured"},
		"serve with no token":            {[]string{cmdServe, flagServer, testServer}, "server default has no API token"},
		"serve with one server unnamed":  {[]string{cmdServe, flagServer, "dock=http://10.0.0.2:5380", flagServer, "http://10.0.0.3:5380", flagToken, "t"}, "has no name"},
		"serve with a token for nobody":  {[]string{cmdServe, flagServer, "dock=http://10.0.0.2:5380", flagToken, "rpi=t"}, `named for server "rpi"`},
		"serve over http with no bearer": {[]string{cmdServe, flagServer, testServer, flagToken, "t", "--listen", "127.0.0.1:0"}, "TECHNITIUM_AUTH_TOKEN"},
		"serve with an unknown toolset":  {[]string{cmdServe, flagServer, testServer, flagToken, "t", "--toolsets", "nope"}, `unknown toolset "nope"`},
		"serve deleting without writing": {[]string{cmdServe, flagServer, testServer, flagToken, "t", "--enable-delete"}, "--enable-delete needs --enable-write"},
		"serve read-only and writing":    {[]string{cmdServe, flagServer, testServer, flagToken, "t", "--read-only", "--enable-write"}, "contradict"},
	} {
		if _, err := run(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s = %v, want an error saying %q", name, err, tc.want)
		}
	}
}

// info asks each configured server who it is, and fails when one cannot be
// asked - having printed the ones that could.
//
//nolint:paralleltest // viper is global state; Make mutates it
func TestInfoCommand(t *testing.T) {
	dock, rpi := technitiumtest.New(t), technitiumtest.New(t)
	dock.AnswerWhole("user/session/get", `{"username":"admin","info":{"version":"15.6","dnsServerDomain":"dock.example"},"status":"ok"}`)
	rpi.AnswerWhole("user/session/get", `{"username":"reader","info":{"version":"15.5","dnsServerDomain":"rpi.example"},"status":"ok"}`)
	servers := "dock=" + dock.URL + ",rpi=" + rpi.URL

	out, err := run(t, "info", flagServer, servers, flagToken, technitiumtest.Token)
	if err != nil {
		t.Fatalf("info: %v\n%s", err, out)
	}
	for _, want := range []string{"dock at " + dock.URL + ": Technitium 15.6, dock.example, as admin", "rpi at " + rpi.URL + ": Technitium 15.5, rpi.example, as reader"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from info:\n%s", want, out)
		}
	}
	if strings.Contains(out, technitiumtest.Token) {
		t.Errorf("info printed the token:\n%s", out)
	}

	rpi.Fail("user/session/get", "invalid-token", "Invalid token or session expired.")
	out, err = run(t, "info", flagServer, servers, flagToken, technitiumtest.Token)
	if err == nil || !strings.Contains(err.Error(), "1 of the 2 configured servers could not be asked") {
		t.Errorf("info with one server refusing = %v", err)
	}
	if !strings.Contains(out, "dock.example") || !strings.Contains(out, "rpi at "+rpi.URL+": user/session/get: Invalid token") {
		t.Errorf("info with one server refusing printed:\n%s", out)
	}
}

// `technitium-mcp tools` needs no server, so it has to work with nothing
// configured.
//
//nolint:paralleltest // viper is global state; Make mutates it
func TestToolsCommand(t *testing.T) {
	out, err := run(t, "tools")
	if err != nil {
		t.Fatalf("tools: %v", err)
	}

	// the default is core, so its tools are listed, every one a read, and
	// counted
	core := tools.Toolsets["core"]
	for _, want := range append([]string{fmt.Sprintf("core (%d)", len(core)), fmt.Sprintf("%d tools: %d read, 0 write, 0 delete", len(core), len(core))}, core...) {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from `tools`:\n%s", want, out)
		}
	}
	// and it says how to get more
	for _, want := range []string{"toolsets: all, ", "families: ", "--toolsets all", "only tools that read are listed; --enable-write registers the ones that change a server", "--enable-delete", "TECHNITIUM_TOOLSETS"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from the footer:\n%s", want, out)
		}
	}
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(line, "families: ") && (!strings.Contains(line, "server") || !strings.Contains(line, "zone")) {
			t.Errorf("the families listed = %q", line)
		}
	}
	// one line a tool: its name, its kind and its first sentence
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, coreTool) && (!strings.Contains(line, " read ") || strings.Count(line, ". ") > 0) {
			t.Errorf("the line for %s is not its name, kind and one sentence: %q", coreTool, line)
		}
	}
}

//nolint:paralleltest // viper is global state; Make mutates it
func TestToolsCommandSelections(t *testing.T) {
	out, err := run(t, "tools", "--toolsets", "zone", "-q")
	if err != nil {
		t.Fatalf("tools --toolsets zone: %v", err)
	}
	// -q prints names only: the family asked for, and core beside it
	listed := strings.Fields(out)
	for _, name := range listed {
		if !strings.HasPrefix(name, "zone_") && !slices.Contains(tools.Toolsets["core"], name) {
			t.Errorf("tools --toolsets zone -q lists %s, which is neither a zone tool nor core's", name)
		}
	}
	if !slices.Contains(listed, coreTool) || !slices.Contains(listed, "server_info") || strings.Contains(out, " read ") {
		t.Errorf("tools --toolsets zone -q = %q", out)
	}

	// an allow list with no toolsets chooses from every tool
	out, err = run(t, "tools", "--allow-tools", "zone_*", "--deny-tools", "*_records,zone_get,zone_export", "-q")
	if err != nil || strings.TrimSpace(out) != coreTool {
		t.Errorf("tools --allow-tools zone_* --deny-tools *_records,zone_get,zone_export -q = %q, %v", out, err)
	}

	// beside a toolset it adds what it names to the set, and core comes with the set
	out, err = run(t, "tools", "--toolsets", "dhcp", "--allow-tools", "zone_get", "-q")
	if listed = strings.Fields(out); err != nil || !slices.Contains(listed, "zone_get") || !slices.Contains(listed, "dhcp_scopes") || !slices.Contains(listed, coreTool) || slices.Contains(listed, "zone_export") {
		t.Errorf("tools --toolsets dhcp --allow-tools zone_get -q = %q, %v", out, err)
	}

	// what the listing says is held back follows what was enabled
	out, err = run(t, "tools", "--toolsets", "all", "--enable-write")
	if err != nil || !strings.Contains(out, "delete tools are hidden; --enable-delete registers them") || strings.Contains(out, "only tools that read") {
		t.Errorf("with --enable-write: %v\n%s", err, out)
	}
	out, err = run(t, "tools", "--toolsets", "all", "--enable-write", "--enable-delete")
	if err != nil || strings.Contains(out, "hidden") || strings.Contains(out, "only tools that read") {
		t.Errorf("with everything enabled the listing still says something is held back: %v\n%s", err, out)
	}
	// a delete is a change, and --read-only is the opposite of --enable-write
	if _, err = run(t, "tools", "--enable-delete"); err == nil || !strings.Contains(err.Error(), "--enable-delete needs --enable-write") {
		t.Errorf("tools --enable-delete alone = %v", err)
	}
	if _, err = run(t, "tools", "--read-only", "--enable-write"); err == nil || !strings.Contains(err.Error(), "contradict") {
		t.Errorf("tools --read-only --enable-write = %v", err)
	}

	if _, err = run(t, "tools", "--toolsets", "nope"); err == nil || !strings.Contains(err.Error(), "core") || !strings.Contains(err.Error(), "zone") {
		t.Errorf("an unknown toolset = %v, want an error naming the sets and families", err)
	}
}

func TestFirstSentence(t *testing.T) {
	t.Parallel()

	for _, c := range []struct{ in, want string }{
		{"One thing. And then another.", "One thing."},
		{"No full stop at all", "No full stop at all"},
		{"Trailing full stop.", "Trailing full stop."},
		{"A type, e.g. Primary. Then more.", "A type, e.g. Primary."},
		{"Ends in etc. and goes on", "Ends in etc. and goes on"},
		{"", ""},
	} {
		if got := firstSentence(c.in); got != c.want {
			t.Errorf("firstSentence(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
