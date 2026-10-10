package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/katbyte/go-kt/clog"
	"github.com/katbyte/technitium-mcp/lib/servers"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/tools"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type FlagData struct {
	Server       []string `mapstructure:"server"`
	Token        []string `mapstructure:"token"`
	ReadOnly     bool     `mapstructure:"read-only"`
	EnableWrite  bool     `mapstructure:"enable-write"`
	EnableDelete bool     `mapstructure:"enable-delete"`
	Toolsets     []string `mapstructure:"toolsets"`
	AllowTools   []string `mapstructure:"allow-tools"`
	DenyTools    []string `mapstructure:"deny-tools"`
	Listen       string   `mapstructure:"listen"`
	AuthToken    string   `mapstructure:"auth-token"`
	AllowNoAuth  bool     `mapstructure:"allow-no-auth"`
}

// configName is the settings file read from $HOME and from the working
// directory.
const configName = ".technitium-mcp"

// envNames binds each flag to its environment variable.
var envNames = map[string]string{ //nolint:gosec // G101: these are env var names, not credentials
	"server":        "TECHNITIUM_SERVER",
	"token":         "TECHNITIUM_TOKEN",
	"read-only":     "TECHNITIUM_READ_ONLY",
	"enable-write":  "TECHNITIUM_ENABLE_WRITE",
	"enable-delete": "TECHNITIUM_ENABLE_DELETE",
	"toolsets":      "TECHNITIUM_TOOLSETS",
	"allow-tools":   "TECHNITIUM_ALLOW_TOOLS",
	"deny-tools":    "TECHNITIUM_DENY_TOOLS",
	"listen":        "TECHNITIUM_LISTEN",
	"auth-token":    "TECHNITIUM_AUTH_TOKEN",
	"allow-no-auth": "TECHNITIUM_ALLOW_NO_AUTH",
}

func configureFlags(root *cobra.Command) error {
	pflags := root.PersistentFlags()

	pflags.StringSliceP("server", "s", nil, "the address a Technitium web console answers on, e.g. http://nas:5380; several servers are each given a name, as ns1=http://192.168.1.2:5380,ns2=http://192.168.1.3:5380")
	pflags.StringSliceP("token", "t", nil, "a Technitium API token for every server, or one each as ns1=<token>,ns2=<token> (consider exporting to TECHNITIUM_TOKEN instead)")
	pflags.Bool("enable-write", false, "register the tools that change a server; without it every tool only reads")
	pflags.Bool("enable-delete", false, "register the tools that delete as well; needs --enable-write")
	pflags.Bool("read-only", false, "register only tools that never change a server: the default, said out loud, and refused beside --enable-write")
	pflags.StringSlice("toolsets", nil, "groups of tools to register: all, "+strings.Join(tools.ToolsetOrder, ", ")+" (core is the default and always included), or a resource family like zone")
	pflags.StringSlice("allow-tools", nil, "tools to register by name, prefix globs like zone_*, or the essential preset: added to the --toolsets given, or with no --toolsets the only tools registered")
	pflags.StringSlice("deny-tools", nil, "never register these tools: names or prefix globs like *_delete; it is how a toolset is narrowed")
	pflags.String("listen", "", "serve MCP over HTTP on this address (e.g. :8080) instead of stdio")
	pflags.String("auth-token", "", "bearer token required on the HTTP endpoint (consider exporting to TECHNITIUM_AUTH_TOKEN instead)")
	pflags.Bool("allow-no-auth", false, "serve HTTP with no bearer token: anyone who can reach the port can use every tool")

	for name, env := range envNames {
		if err := viper.BindPFlag(name, pflags.Lookup(name)); err != nil {
			return fmt.Errorf("error binding '%s' flag: %w", name, err)
		}

		if err := viper.BindEnv(name, env); err != nil {
			return fmt.Errorf("error binding '%s' to env '%s' : %w", name, env, err)
		}
	}

	readConfigFiles()

	// a config file spells a setting the way the environment does, with or
	// without the prefix - READ_ONLY or TECHNITIUM_READ_ONLY for --read-only -
	// and viper only matches a key spelled as the flag is, so every two-word
	// setting would be ignored. Carried across as defaults, they still lose
	// to a flag or the environment.
	for name, env := range envNames {
		for _, alt := range []string{strings.ReplaceAll(name, "-", "_"), strings.ToLower(env)} {
			if alt != name && viper.InConfig(alt) {
				viper.SetDefault(name, viper.Get(alt))

				break
			}
		}
	}

	return nil
}

// readConfigFiles reads ~/.technitium-mcp and then ./.technitium-mcp over it,
// key by key: the home file holds the global settings and a project's file
// changes the ones it names. viper on its own reads only the first file it
// finds, so a project file that set one thing would lose the servers and
// tokens from home.
func readConfigFiles() {
	viper.SetConfigType("env")

	var files []string
	if home, err := os.UserHomeDir(); err == nil {
		files = append(files, filepath.Join(home, configName))
	}
	if wd, err := os.Getwd(); err == nil && (len(files) == 0 || filepath.Join(wd, configName) != files[0]) {
		files = append(files, filepath.Join(wd, configName))
	}

	read := false
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		viper.SetConfigFile(f)
		merge := viper.ReadInConfig
		if read {
			merge = viper.MergeInConfig
		}
		if err := merge(); err != nil {
			clog.Log.Errorf("Error reading config file %s: %v", f, err)

			continue
		}
		read = true
	}
}

// GetFlags returns the fully populated FlagData.
// We must unmarshal from Viper instead of using globally bound pflags variables
// because pflags only parses command-line arguments. Viper merges environment
// variables (and config files) on top of the CLI flags.
func GetFlags() *FlagData {
	var f FlagData
	if err := viper.Unmarshal(&f); err != nil {
		clog.Log.Fatalf("failed to unmarshal configuration: %v", err)
	}

	return &f
}

// Servers builds the configured servers, each with a client for it.
func (f *FlagData) Servers() (*servers.Set, error) {
	// the clients say what they send and are sent to the process's log, at the level TECHNITIUM_LOG sets
	return servers.New(f.Server, f.Token, technitium.WithLog(clog.Log))
}

// DefaultToolsets is what the binary registers when neither --toolsets nor
// --allow-tools is given: enough to see what the servers are and read what
// they hold, and nothing that writes. Every tool's definition is spent from a
// client's context before a question is asked, which is a poor thing to spend
// it on by default. Ask for more with --toolsets, or --toolsets all for
// everything.
var DefaultToolsets = []string{"core"}

// ToolOptions maps the flags onto the tool registration options. An allow
// list with no --toolsets is the whole choice: it already says which tools
// to load, so the default set is not added to it. Beside --toolsets it adds
// its tools to the sets.
//
// A session only reads unless --enable-write says otherwise. --read-only is
// taken because the other katbyte MCP servers are started with it, and here
// says what is already so: beside --enable-write it is a contradiction, and
// refused.
func (f *FlagData) ToolOptions() (tools.Options, error) {
	if f.ReadOnly && f.EnableWrite {
		return tools.Options{}, errors.New("--read-only and --enable-write contradict each other: give one")
	}
	sets := f.Toolsets
	if len(sets) == 0 && len(f.AllowTools) == 0 {
		sets = DefaultToolsets
	}

	return tools.Options{
		EnableWrite:  f.EnableWrite,
		EnableDelete: f.EnableDelete,
		Toolsets:     sets,
		Allow:        f.AllowTools,
		Deny:         f.DenyTools,
	}, nil
}
