//go:build acceptance

// The binary, not the package. Everything else in this suite drives
// tools.RegisterAll in process, which is every line of tool code the binary
// runs; what it never touches is the thin layer around it - stdio framing,
// the flags and environment reaching the server, the HTTP routes, and what a
// bad start says. Those break silently: a stray line on stdout corrupts the
// protocol and a client simply fails to connect, with every other test green.
//
// So this is a smoke test: the real binary, built from this checkout, spoken
// to the way a client speaks to it, against the same servers.
package tools_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	binOnce   sync.Once
	binPath   string
	binDir    string
	errBinary error
)

// removeBinary deletes the binary the smoke test built, at the end of the
// run: it is built once for the suite, so no one test can clean it up.
func removeBinary() {
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
}

// builtBinary builds technitium-mcp from this checkout, once per run, so the test
// speaks to the code in the tree rather than to whatever is installed.
func builtBinary(t *testing.T) string {
	t.Helper()

	names(t)
	binOnce.Do(func() {
		// not t.TempDir: the binary is built once and outlives the test that built it
		binDir, errBinary = os.MkdirTemp("", "technitium-mcp-binary") //nolint:usetesting // removed by removeBinary at the end of the run
		if errBinary != nil {
			return
		}
		binPath = filepath.Join(binDir, "technitium-mcp")
		args := []string{"build", "-o", binPath}
		if coverDir() != "" {
			// the main package too: without it the binary registers no exit
			// hook and writes no counters at all
			args = append(args, "-cover", "-coverpkg=.,./tools/...,./lib/...,./cli/...,./sdk/...")
		}
		build := exec.CommandContext(context.Background(), "go", append(args, ".")...) //nolint:gosec // G204: the binary this test built, or the go tool building it, with the test's own arguments
		build.Dir = "../.."
		out, err := build.CombinedOutput()
		if err != nil {
			errBinary = fmt.Errorf("building technitium-mcp: %w\n%s", err, out)
		}
	})
	if errBinary != nil {
		t.Fatal(errBinary)
	}

	return binPath
}

// firstServer is the first server's address and a token it takes: what the
// binary is given, as one server with no name. In a cluster the token the
// script made for the second server no longer works there, so the binary is
// not given the pair as the environment has them.
func firstServer(t *testing.T) (address, token string) {
	t.Helper()

	token = os.Getenv("TECHNITIUM_TOKEN")
	for named := range strings.SplitSeq(token, ",") {
		if name, value, isNamed := strings.Cut(named, "="); isNamed && name == world.First {
			token = value
		}
	}

	return mustClient(t, world.First).BaseURL(), token
}

// serverEnv is the environment a client would give the binary: the first
// server and its token, and nothing else of ours, so a stray TECHNITIUM_* in
// the shell running the tests cannot change what is registered. HOME is an
// empty directory, so a real ~/.technitium-mcp cannot either.
func serverEnv(t *testing.T, extra ...string) []string {
	t.Helper()

	address, token := firstServer(t)
	env := make([]string, 0, 4+len(extra))
	env = append(env, "PATH="+os.Getenv("PATH"), "HOME="+t.TempDir(), "TECHNITIUM_SERVER="+address, "TECHNITIUM_TOKEN="+token)

	return append(env, extra...)
}

// syncBuffer collects output a process writes while a test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// teeReadCloser is a reader that also closes the process's stdout.
type teeReadCloser struct {
	io.Reader
	io.Closer
}

// stdio starts "technitium-mcp serve" as a client does, connects an MCP
// session over its stdin and stdout, and keeps everything the process wrote
// to each stream so a test can assert on them. dir is the working directory,
// for the config file lookup.
func stdio(t *testing.T, dir string, env []string, args ...string) (session *mcp.ClientSession, wrote, wroteErr *syncBuffer) {
	t.Helper()

	ctx := context.WithoutCancel(t.Context())
	cmd := exec.CommandContext(ctx, builtBinary(t), append([]string{"serve"}, args...)...) //nolint:gosec // G204: the binary this test built, or the go tool building it, with the test's own arguments
	cmd.Env = withCover(env)
	cmd.Dir = dir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, errOut := &syncBuffer{}, &syncBuffer{}
	cmd.Stderr = errOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	session, err = mcp.NewClient(&mcp.Implementation{Name: "binary-test", Version: "0"}, nil).Connect(ctx, &mcp.IOTransport{Reader: teeReadCloser{Reader: io.TeeReader(stdout, out), Closer: stdout}, Writer: stdin}, nil)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("connecting to the binary over stdio: %v\nstderr: %s", err, errOut)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	return session, out, errOut
}

// toolNamesOf lists the tools a session's server registered.
func toolNamesOf(t *testing.T, session *mcp.ClientSession) []string {
	t.Helper()

	res, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	listed := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		listed = append(listed, tool.Name)
	}
	slices.Sort(listed)

	return listed
}

// serverThrough calls a read-only tool over the session and returns what the
// one server says of itself, which proves the server url and token reached
// the client the binary built.
func serverThrough(t *testing.T, session *mcp.ClientSession) map[string]any {
	t.Helper()

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "server_info"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("server_info through the binary: %v", res.Content)
	}
	out, isObject := res.StructuredContent.(map[string]any)
	if !isObject {
		t.Fatalf("server_info through the binary answered %v", res.StructuredContent)
	}
	rows := acctest.Rows(t, out["servers"], "servers")
	if len(rows) != 1 {
		t.Fatalf("server_info through the binary = %v, want the one server it was given", rows)
	}

	return rows[0]
}

// MCP over stdio uses stdout for the protocol: one line of anything else -
// a print, a log line, a cobra message - corrupts the stream, and the client
// fails to connect with every test still green. So the binary is run at the
// most verbose log level and every line it writes to stdout is checked.
//
//nolint:paralleltest // it builds the binary and starts it, once at a time
func TestBinaryStdioSpeaksOnlyTheProtocol(t *testing.T) {
	session, out, errOut := stdio(t, t.TempDir(), serverEnv(t, "TECHNITIUM_LOG=trace"), "--toolsets", "all")

	if row := serverThrough(t, session); row["domain"] != world.Domain(world.First) || row["version"] == nil || row["error"] != nil {
		t.Errorf("the server through the binary = %v", row)
	}
	if err := session.Close(); err != nil {
		t.Errorf("closing the session: %v", err)
	}

	for i, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var msg struct {
			JSONRPC string `json:"jsonrpc"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err != nil || msg.JSONRPC != "2.0" {
			t.Fatalf("stdout line %d is not a protocol message, which breaks the stream: %q", i+1, line)
		}
	}
	// the logging that must not be on stdout does happen, on stderr: the start, and the traffic at trace - with no token in it
	logged := errOut.String()
	if !strings.Contains(logged, "registered") || !strings.Contains(logged, "/api/user/session/get") {
		t.Errorf("stderr has no startup line and no traffic at trace level: %q", logged)
	}
	if _, token := firstServer(t); strings.Contains(logged, token) || strings.Contains(out.String(), token) {
		t.Error("the server's token is in what the binary wrote")
	}
}

// The flags and the environment have to reach the running server, not just
// parse: what a client lists is what was asked for.
//
//nolint:paralleltest // it builds the binary and starts it, once at a time
func TestBinaryRegistersWhatTheFlagsAsk(t *testing.T) {
	for _, c := range []struct {
		name     string
		env      []string
		args     []string
		want     []string // tools that must be registered
		unwanted []string // tools that must not be
	}{
		{name: "the default set is core", want: []string{"server_info", "zone_list", "zone_records", "record_find", "dns_resolve"}, unwanted: []string{"record_set", "audit_all", "zone_get", "user_list"}},
		{name: "a toolset from the environment", env: []string{"TECHNITIUM_TOOLSETS=audit"}, want: []string{"audit_all", "audit_cluster", "zone_list"}, unwanted: []string{"zone_get"}},
		{name: "nothing writes unless it is said to", args: []string{"--toolsets", "all"}, want: []string{"audit_all", "dhcp_scopes", "user_list", "settings_backup"}, unwanted: []string{"record_set", "zone_create", "zone_delete", "settings_set", "user_set"}},
		{name: "--read-only says the same out loud", args: []string{"--toolsets", "all", "--read-only"}, want: []string{"audit_all"}, unwanted: []string{"record_set", "zone_delete"}},
		{name: "--enable-write registers what changes and nothing that deletes", args: []string{"--toolsets", "all", "--enable-write"}, want: []string{"record_set", "zone_create", "settings_set", "cluster_join"}, unwanted: []string{"record_delete", "zone_delete", "user_delete", "settings_restore", "cluster_delete"}},
		{name: "both from the environment register what deletes too", env: []string{"TECHNITIUM_TOOLSETS=all", "TECHNITIUM_ENABLE_WRITE=true", "TECHNITIUM_ENABLE_DELETE=true"}, want: []string{"record_delete", "zone_delete", "user_delete", "settings_restore", "cluster_delete"}},
		{name: "--allow-tools alone is only the tools it names", args: []string{"--allow-tools", "zone_*"}, want: []string{"zone_list", "zone_records", "zone_get", "zone_export"}, unwanted: []string{"server_info", "record_find", "zone_create"}},
		{name: "--allow-tools beside a toolset adds to it", args: []string{"--toolsets", "core", "--allow-tools", "zone_get"}, want: []string{"zone_get", "server_info", "zone_list"}, unwanted: []string{"audit_all", "zone_export"}},
		{name: "and gets nothing past the write switch", args: []string{"--toolsets", "core", "--allow-tools", "record_set"}, want: []string{"server_info"}, unwanted: []string{"record_set"}},
		{name: "--deny-tools removes from it", args: []string{"--toolsets", "audit", "--deny-tools", "audit_*"}, want: []string{"zone_list"}, unwanted: []string{"audit_all", "audit_names"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			// an empty working directory: only the flags and the environment
			// under test decide what is registered
			session, _, _ := stdio(t, t.TempDir(), serverEnv(t, c.env...), c.args...)
			listed := toolNamesOf(t, session)
			for _, want := range c.want {
				if !slices.Contains(listed, want) {
					t.Errorf("%s is not registered, of the %d that are", want, len(listed))
				}
			}
			for _, unwanted := range c.unwanted {
				if slices.Contains(listed, unwanted) {
					t.Errorf("%s is registered, of the %d that are", unwanted, len(listed))
				}
			}
		})
	}
}

// A .technitium-mcp in the working directory is how a project configures the
// binary without putting a token in .mcp.json, and it is read before $HOME's.
//
//nolint:paralleltest // it builds the binary and starts it, once at a time
func TestBinaryReadsTheConfigFileInTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	address, token := firstServer(t)
	if err := os.WriteFile(filepath.Join(dir, ".technitium-mcp"), fmt.Appendf(nil, "server=%s\ntoken=%s\ntoolsets=audit\n", address, token), 0o600); err != nil {
		t.Fatal(err)
	}

	// nothing in the environment: the file is all it has
	session, _, _ := stdio(t, dir, []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()})

	if listed := toolNamesOf(t, session); !slices.Contains(listed, "audit_all") || slices.Contains(listed, "zone_get") {
		t.Errorf("the toolset in the config file was not used: %v", listed)
	}
	if row := serverThrough(t, session); row["domain"] != world.Domain(world.First) {
		t.Errorf("the server and token in the config file did not reach the client: %v", row)
	}
}

// --listen has to serve the protocol at /mcp behind the bearer check, answer
// the health probe a container watches, stay up, and shut down when asked.
//
//nolint:paralleltest // it builds the binary and starts it, once at a time
func TestBinaryServesHTTP(t *testing.T) {
	const token = "zzyzx-binary-token" //nolint:gosec // G101: a token made up for the test

	ctx := context.WithoutCancel(t.Context())
	addr := freePort(t)
	cmd := exec.CommandContext(ctx, builtBinary(t), "serve", "--listen", addr, "--auth-token", token, "--toolsets", "all") //nolint:gosec // G204: the binary this test built, or the go tool building it, with the test's own arguments
	cmd.Env = withCover(serverEnv(t))
	errOut := &syncBuffer{}
	cmd.Stderr, cmd.Stdout = errOut, errOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	base := "http://" + addr
	waitHealthy(t, base, exited, errOut)

	// get answers the status and the challenge, if any
	get := func(path, auth string) (status int, challenge string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}

		return res.StatusCode, res.Header.Get("WWW-Authenticate")
	}

	t.Run("the endpoint is behind the bearer check", func(t *testing.T) {
		if status, challenge := get("/mcp", ""); status != http.StatusUnauthorized {
			t.Errorf("GET /mcp with no token = %d, want 401", status)
		} else if !strings.Contains(challenge, "Bearer") {
			t.Errorf("no Bearer challenge: %q", challenge)
		}
		if status, _ := get("/mcp", "Bearer nope"); status != http.StatusUnauthorized {
			t.Errorf("GET /mcp with the wrong token = %d, want 401", status)
		}
		if status, _ := get("/nope", "Bearer "+token); status != http.StatusNotFound {
			t.Errorf("GET /nope = %d, want 404", status)
		}
	})

	// the session stays open through the shutdown below, as a client that is
	// still connected when the container is stopped would
	var session *mcp.ClientSession
	t.Run("and serves the protocol with it", func(t *testing.T) {
		var err error
		session, err = mcp.NewClient(&mcp.Implementation{Name: "binary-test", Version: "0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: base + "/mcp", HTTPClient: &http.Client{Transport: bearer(token)}}, nil)
		if err != nil {
			t.Fatalf("connecting over HTTP: %v\n%s", err, errOut)
		}
		t.Cleanup(func() { _ = session.Close() })

		if listed := toolNamesOf(t, session); !slices.Contains(listed, "audit_all") { //nolint:contextcheck // the helper asks under the test's own context, which is the one that ends with it
			t.Errorf("tools over HTTP = %v", listed)
		}
		if row := serverThrough(t, session); row["domain"] != world.Domain(world.First) { //nolint:contextcheck // the helper asks under the test's own context, which is the one that ends with it
			t.Errorf("the server over HTTP = %v", row)
		}
	})

	t.Run("and shuts down when asked, with a client still connected", func(t *testing.T) {
		if session == nil {
			t.Skip("no session to hold open")
		}
		asked := time.Now()
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-exited:
			if err != nil {
				t.Errorf("exit after SIGTERM: %v\n%s", err, errOut)
			}
			// a container gets ten seconds to stop before it is killed
			if took := time.Since(asked); took > 5*time.Second {
				t.Errorf("took %s to stop with a client connected", took.Round(time.Millisecond))
			}
		case <-time.After(shutdownGrace):
			t.Errorf("still running %s after SIGTERM", shutdownGrace)
		}
	})
}

// coverDir is where a coverage run (make cover) writes its counters, or ""
// outside one. The binary is then built with coverage on and writes beside
// the suite, so what the process ran counts too: the serve path is only ever
// run by these tests.
func coverDir() string {
	if f := flag.Lookup("test.gocoverdir"); f != nil {
		return f.Value.String()
	}

	return ""
}

// withCover points a binary at the coverage directory during a coverage run.
func withCover(env []string) []string {
	if dir := coverDir(); dir != "" {
		return append(env, "GOCOVERDIR="+dir)
	}

	return env
}

// shutdownGrace is how long the binary gets to drain and exit.
const shutdownGrace = 15 * time.Second

// bearer adds the HTTP endpoint's token to every request.
func bearer(token string) http.RoundTripper {
	return roundTripper(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("Authorization", "Bearer "+token)

		return http.DefaultTransport.RoundTrip(r)
	})
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// freePort is an address nothing is listening on, for --listen.
func freePort(t *testing.T) string {
	t.Helper()

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	return l.Addr().String()
}

// waitHealthy polls the health probe until the server answers it, failing
// with whatever the process said if it exits first.
func waitHealthy(t *testing.T, base string, exited <-chan error, out *syncBuffer) {
	t.Helper()

	for range 100 {
		select {
		case err := <-exited:
			t.Fatalf("the server exited before serving: %v\n%s", err, out)
		default:
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/healthz", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if res, err := http.DefaultClient.Do(req); err == nil {
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == "ok" {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no health response from the server\n%s", out)
}

// A start that cannot work has to say so and stop. A client waiting on stdio
// sees nothing at all otherwise, and a container restarts in a loop.
//
//nolint:paralleltest // it builds the binary and starts it, once at a time
func TestBinaryRefusesAStartItCannotMake(t *testing.T) {
	address, token := firstServer(t)
	bare := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	for _, c := range []struct {
		name string
		env  []string
		args []string
		says string
	}{
		{name: "no server", env: append(slices.Clone(bare), "TECHNITIUM_TOKEN="+token), says: "no server is configured"},
		{name: "no token", env: append(slices.Clone(bare), "TECHNITIUM_SERVER="+address), says: "token"},
		{name: "--listen with no auth token", args: []string{"--listen", "127.0.0.1:0"}, says: "--auth-token"},
		{name: "a toolset that does not exist", args: []string{"--toolsets", "zzyzx"}, says: "zzyzx"},
		{name: "an allow pattern matching nothing", args: []string{"--allow-tools", "zzyzx_*"}, says: "zzyzx_*"},
		{name: "deleting with no leave to change", args: []string{"--enable-delete"}, says: "--enable-delete needs --enable-write"},
		{name: "reading only and changing at once", args: []string{"--read-only", "--enable-write"}, says: "contradict each other"},
		{name: "two servers and one of them unnamed", env: append(slices.Clone(bare), "TECHNITIUM_SERVER=ns1="+address+","+address, "TECHNITIUM_TOKEN="+token), says: "has no name"},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := c.env
			if env == nil {
				env = serverEnv(t)
			}
			cmd := exec.CommandContext(context.WithoutCancel(t.Context()), builtBinary(t), append([]string{"serve"}, c.args...)...) //nolint:gosec // G204: the binary this test built, or the go tool building it, with the test's own arguments
			cmd.Env = withCover(env)
			cmd.Dir = t.TempDir() // no .technitium-mcp to fall back on
			out := &syncBuffer{}
			cmd.Stdout, cmd.Stderr = out, out

			done := make(chan error, 1)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			go func() { done <- cmd.Wait() }()

			select {
			case err := <-done:
				if err == nil {
					t.Errorf("exited 0, want a refusal: %s", out)
				}
			case <-time.After(shutdownGrace):
				_ = cmd.Process.Kill()
				t.Fatalf("still running: a bad start has to fail, not hang\n%s", out)
			}
			if got := out.String(); !strings.Contains(got, c.says) {
				t.Errorf("said %q, want it to name %q", got, c.says)
			}
			if strings.Contains(out.String(), token) {
				t.Error("the refusal has the server's token in it")
			}
		})
	}
}

// The commands a person runs to check an install, rather than a client.
//
//nolint:paralleltest // it builds the binary and runs it, once at a time
func TestBinaryCommands(t *testing.T) {
	run := func(t *testing.T, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(context.WithoutCancel(t.Context()), builtBinary(t), args...) //nolint:gosec // G204: the binary this test built, or the go tool building it, with the test's own arguments
		cmd.Env = withCover(serverEnv(t))
		cmd.Dir = t.TempDir()
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}

		return string(out)
	}

	if got := run(t, "version"); !strings.HasPrefix(got, "technitium-mcp ") {
		t.Errorf("version = %q", got)
	}
	// tools needs no server, and says what it would register
	if got := run(t, "tools", "-q", "--toolsets", "all", "--enable-write", "--enable-delete"); !strings.Contains(got, "zone_delete\n") || len(strings.Fields(got)) != len(suite.ToolNames(t)) {
		t.Errorf("tools -q listed %d tools, and the server registers %d", len(strings.Fields(got)), len(suite.ToolNames(t)))
	}
	if got := run(t, "info"); !strings.Contains(got, "Technitium ") || !strings.Contains(got, world.Domain(world.First)) || !strings.Contains(got, "as admin") {
		t.Errorf("info = %q", got)
	}
}
