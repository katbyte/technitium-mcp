package cli

import (
	"strings"

	"github.com/katbyte/go-kt/clog"
	"github.com/katbyte/go-kt/mcp/server"
	"github.com/katbyte/go-kt/version"
	"github.com/katbyte/technitium-mcp/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP server (stdio by default, HTTP with --listen)",
		Long: `Runs the MCP server for AI clients such as Claude Code.

Without --listen it speaks MCP over stdio: register it in .mcp.json with the TECHNITIUM_*
environment variables set. With --listen (TECHNITIUM_LISTEN, e.g. :8080) it serves the
Streamable HTTP transport at /mcp instead, for an always-on deployment such as the
docker-compose.yml in this repo. --auth-token (TECHNITIUM_AUTH_TOKEN) is then required, and
clients must send "Authorization: Bearer <token>"; to serve with no token at all, which
lets anyone who can reach the port use every tool, say so with --allow-no-auth
(TECHNITIUM_ALLOW_NO_AUTH=true).

Every tool only reads unless --enable-write (TECHNITIUM_ENABLE_WRITE=true) is given, and
none deletes without --enable-delete beside it.

No server is contacted at start: a DNS server that is down is something the tools report,
not a reason to have no tools.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true

			f := GetFlags()
			set, err := f.Servers()
			if err != nil {
				return err
			}

			srv := mcp.NewServer(&mcp.Implementation{
				Name:    "technitium",
				Title:   "Technitium DNS Server",
				Version: version.Version,
			}, nil)

			opts, err := f.ToolOptions()
			if err != nil {
				return err
			}
			registered, err := tools.RegisterAll(srv, set, opts)
			if err != nil {
				return err
			}
			clog.Log.Infof("registered %d tools for %s", len(registered), strings.Join(set.Names(), ", "))

			return server.Run(cmd.Context(), srv, f.serveOptions())
		},
	}
}

// serveOptions is how this tool serves: stdio, or HTTP at --listen behind
// --auth-token, with the health probe a container asks outside the check.
func (f *FlagData) serveOptions() server.Options {
	return server.Options{
		Listen:      f.Listen,
		AuthToken:   f.AuthToken,
		AllowNoAuth: f.AllowNoAuth,
		Name:        "technitium-mcp",
		EnvPrefix:   "TECHNITIUM",
	}
}
