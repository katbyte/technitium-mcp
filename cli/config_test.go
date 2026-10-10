package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/tools"
	"github.com/spf13/cobra"
)

// viper is global, so none of these can run in parallel and each resets it.
const (
	testServer = "http://nas:5380"
	testUse    = "technitium-mcp"
	// on is how a boolean is switched on from the environment or a file
	on = "true"
	// two named servers, as a list of them is written, and a pattern for tools
	dockEntry = "dock=http://10.0.0.2:5380"
	rpiEntry  = "rpi=http://10.0.0.3:5380"
	zoneGlob  = "zone_*"
)

// load drives the real flag wiring against a temporary home and working
// directory, with command-line arguments parsed as well.
func load(t *testing.T, home, wd string, args ...string) *FlagData {
	t.Helper()

	isolate(t)
	t.Setenv("HOME", home)
	t.Chdir(wd)

	root := &cobra.Command{Use: testUse}
	if err := configureFlags(root); err != nil {
		t.Fatalf("configureFlags: %v", err)
	}
	if err := root.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}

	return GetFlags()
}

func write(t *testing.T, dir, body string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, configName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ~/.technitium-mcp holds the global settings and a project's own file
// changes the ones it names: the two are merged key by key, so a project
// file that sets one thing keeps the servers and tokens from home.
//
//nolint:paralleltest // viper is global state; these mutate it
func TestConfigFiles(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	write(t, home, "SERVER="+dockEntry+","+rpiEntry+"\nTOKEN=dock=aaa,rpi=bbb\nTOOLSETS=all\n")

	t.Run("home alone", func(t *testing.T) {
		f := load(t, home, t.TempDir())
		if !slices.Equal(f.Server, []string{dockEntry, rpiEntry}) || !slices.Equal(f.Token, []string{"dock=aaa", "rpi=bbb"}) || !slices.Equal(f.Toolsets, []string{"all"}) {
			t.Errorf("flags = %+v", f)
		}
		set, err := f.Servers()
		if err != nil || !slices.Equal(set.Names(), []string{"dock", "rpi"}) {
			t.Errorf("servers = %v, %v", set, err)
		}
	})

	t.Run("a project file changes what it names", func(t *testing.T) {
		write(t, project, "TOOLSETS=core\nREAD_ONLY=true\n")
		f := load(t, home, project)
		if !slices.Equal(f.Toolsets, []string{"core"}) || !f.ReadOnly {
			t.Errorf("the project's settings were not read: %+v", f)
		}
		if len(f.Server) != 2 || len(f.Token) != 2 {
			t.Errorf("the project file lost the servers and tokens from home: %+v", f)
		}
	})

	t.Run("no config at all is not an error", func(t *testing.T) {
		if f := load(t, t.TempDir(), t.TempDir()); len(f.Server) != 0 || len(f.Token) != 0 || f.ReadOnly {
			t.Errorf("flags = %+v, want nothing set", f)
		}
	})

	t.Run("home is the working directory", func(t *testing.T) {
		if f := load(t, home, home); len(f.Server) != 2 {
			t.Errorf("one file read as both = %+v", f)
		}
	})
}

// A flag beats the environment, and the environment a config file, so a
// container can override what is baked into an image.
func TestPrecedence(t *testing.T) {
	home := t.TempDir()
	write(t, home, "SERVER=http://from-file:5380\nTOKEN=from-file\nLISTEN=:1\n")

	f := load(t, home, t.TempDir())
	if !slices.Equal(f.Server, []string{"http://from-file:5380"}) || f.Listen != ":1" {
		t.Errorf("from the file alone = %+v", f)
	}

	isolate(t)
	t.Setenv("TECHNITIUM_SERVER", "a=http://from-env:5380,b=http://also-env:5380")
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	root := &cobra.Command{Use: testUse}
	if err := configureFlags(root); err != nil {
		t.Fatal(err)
	}
	f = GetFlags()
	if !slices.Equal(f.Server, []string{"a=http://from-env:5380", "b=http://also-env:5380"}) {
		t.Errorf("server = %v, want the environment's, split at the commas", f.Server)
	}
	// and a key the environment did not set still comes from the file
	if !slices.Equal(f.Token, []string{"from-file"}) {
		t.Errorf("token = %v, want the config file's", f.Token)
	}

	if err := root.ParseFlags([]string{flagServer, "x=http://from-flag:5380", flagServer, "y=http://flag-too:5380"}); err != nil {
		t.Fatal(err)
	}
	if f = GetFlags(); !slices.Equal(f.Server, []string{"x=http://from-flag:5380", "y=http://flag-too:5380"}) {
		t.Errorf("server = %v, want the flags', each one given", f.Server)
	}
}

// A config file names a setting the way the environment does, with or
// without the prefix: READ_ONLY or TECHNITIUM_READ_ONLY for --read-only.
// viper matches a file's keys against the flags' own spelling, so every
// two-word setting in a file would be ignored without a word.
func TestConfigFileTwoWordKeys(t *testing.T) {
	for name, body := range map[string]string{
		"without the prefix": "SERVER=" + testServer + "\nENABLE_WRITE=true\nENABLE_DELETE=true\nALLOW_TOOLS=zone_*,server_info\nDENY_TOOLS=*_records\nAUTH_TOKEN=s3cret\nALLOW_NO_AUTH=true\n",
		"with the prefix":    "TECHNITIUM_SERVER=" + testServer + "\nTECHNITIUM_ENABLE_WRITE=true\nTECHNITIUM_ENABLE_DELETE=true\nTECHNITIUM_ALLOW_TOOLS=zone_*,server_info\nTECHNITIUM_DENY_TOOLS=*_records\nTECHNITIUM_AUTH_TOKEN=s3cret\nTECHNITIUM_ALLOW_NO_AUTH=true\n",
	} {
		home := t.TempDir()
		write(t, home, body)
		f := load(t, home, t.TempDir())
		if !slices.Equal(f.Server, []string{testServer}) || !f.EnableWrite || !f.EnableDelete || !f.AllowNoAuth || f.AuthToken != "s3cret" || !slices.Equal(f.AllowTools, []string{zoneGlob, "server_info"}) || !slices.Equal(f.DenyTools, []string{"*_records"}) {
			t.Errorf("%s: flags = %+v", name, f)
		}
	}

	// and each still loses to the environment
	home := t.TempDir()
	write(t, home, "AUTH_TOKEN=from-file\n")
	isolate(t)
	t.Setenv("TECHNITIUM_AUTH_TOKEN", "from-env")
	t.Setenv("TECHNITIUM_READ_ONLY", on)
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	if err := configureFlags(&cobra.Command{Use: testUse}); err != nil {
		t.Fatal(err)
	}
	if f := GetFlags(); f.AuthToken != "from-env" || !f.ReadOnly {
		t.Errorf("flags = %+v, want the environment's", f)
	}
}

// options is the tool options the flags given come to; it fails the test
// when they are refused.
func options(t *testing.T, args ...string) tools.Options {
	t.Helper()

	opts, err := load(t, t.TempDir(), t.TempDir(), args...).ToolOptions()
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}

	return opts
}

// The binary registers core unless told otherwise, with nothing that changes
// a server, and an allow list given with no toolsets chooses from every tool.
//
//nolint:paralleltest // viper is global state; these mutate it
func TestToolOptions(t *testing.T) {
	opts := options(t)
	if !slices.Equal(opts.Toolsets, DefaultToolsets) || opts.EnableWrite || opts.EnableDelete || len(opts.Allow) != 0 {
		t.Errorf("with nothing asked for = %+v", opts)
	}

	opts = options(t, "--allow-tools", zoneGlob)
	if len(opts.Toolsets) != 0 || !slices.Equal(opts.Allow, []string{zoneGlob}) {
		t.Errorf("an allow list alone = %+v, want it to choose from every tool", opts)
	}

	opts = options(t, "--toolsets", "zone,all", "--allow-tools", zoneGlob, "--deny-tools", "*_records", "--enable-write", "--enable-delete")
	if !slices.Equal(opts.Toolsets, []string{"zone", "all"}) || !slices.Equal(opts.Allow, []string{zoneGlob}) || !slices.Equal(opts.Deny, []string{"*_records"}) || !opts.EnableWrite || !opts.EnableDelete {
		t.Errorf("everything asked for = %+v", opts)
	}
}

// A session only reads unless writes are enabled. --read-only is taken, as
// the other servers are started with it, and says what is already so; beside
// --enable-write it is a contradiction.
func TestTheWriteSwitch(t *testing.T) {
	if opts := options(t, "--read-only"); opts.EnableWrite || opts.EnableDelete {
		t.Errorf("--read-only = %+v", opts)
	}
	if opts := options(t, "--enable-write"); !opts.EnableWrite || opts.EnableDelete {
		t.Errorf("--enable-write = %+v, want writes and no deletes", opts)
	}

	if _, err := load(t, t.TempDir(), t.TempDir(), "--read-only", "--enable-write").ToolOptions(); err == nil || !strings.Contains(err.Error(), "contradict") {
		t.Errorf("--read-only beside --enable-write = %v", err)
	}

	// from the environment and from a file, as every setting
	isolate(t)
	t.Setenv("TECHNITIUM_ENABLE_WRITE", on)
	if err := configureFlags(&cobra.Command{Use: testUse}); err != nil {
		t.Fatal(err)
	}
	if f := GetFlags(); !f.EnableWrite {
		t.Error("TECHNITIUM_ENABLE_WRITE=true did not enable writes")
	}
	home := t.TempDir()
	write(t, home, "ENABLE_WRITE=true\n")
	if f := load(t, home, t.TempDir()); !f.EnableWrite {
		t.Error("ENABLE_WRITE=true in the config file did not enable writes")
	}
}
