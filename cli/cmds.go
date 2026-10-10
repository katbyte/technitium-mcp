// Package cli implements the technitium-mcp command line interface: the cobra commands, flag and
// config handling, and the MCP server exposing Technitium DNS server tools to AI clients.
package cli

import (
	"fmt"
	"strings"

	"github.com/katbyte/go-kt/version"
	"github.com/katbyte/technitium-mcp/tools"
	"github.com/spf13/cobra"
)

// firstSentence trims a tool description to its opening sentence, so the list
// stays one line per tool. A full stop that ends an abbreviation ends no
// sentence.
func firstSentence(s string) string {
	for from := 0; ; {
		i := strings.Index(s[from:], ". ")
		if i < 0 {
			return s
		}
		end := from + i
		if !endsInAbbreviation(s[:end+1]) {
			return s[:end+1]
		}
		from = end + 2
	}
}

// endsInAbbreviation reports whether a stretch of text ends in a dotted
// abbreviation rather than a sentence.
func endsInAbbreviation(s string) bool {
	lower := strings.ToLower(s)
	for _, abbr := range []string{"e.g.", "i.e.", "etc.", "vs."} {
		if strings.HasSuffix(lower, abbr) {
			return true
		}
	}

	return false
}

func Make() (*cobra.Command, error) {
	root := &cobra.Command{
		Use:   "technitium-mcp [command]",
		Short: "technitium-mcp is an MCP server and CLI for running and auditing Technitium DNS servers",
		Long: `An MCP server (and CLI) for Technitium DNS servers: read zones and records, compare
servers that are meant to agree, and find what is wrong with them, from an AI client such
as Claude Code. One process works on several servers, each under a name.
Complete documentation is available at https://github.com/katbyte/technitium-mcp`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Run \"technitium-mcp help\" for more information about available technitium-mcp commands.")

			return nil
		},
	}

	root.AddCommand(&cobra.Command{
		Use:           "version",
		Short:         "Print the version number of technitium-mcp",
		Long:          `Print the version number of technitium-mcp`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		Run: func(cmd *cobra.Command, _ []string) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "technitium-mcp "+version.Version)
		},
	})

	root.AddCommand(toolsCmd())
	root.AddCommand(infoCmd())
	root.AddCommand(serveCmd())

	if err := configureFlags(root); err != nil {
		return nil, fmt.Errorf("unable to configure flags: %w", err)
	}

	return root, nil
}

func toolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "List the tools and toolsets, and what the current flags would register",
		Long: `Lists every tool technitium-mcp would register with the current flags, grouped by toolset,
with its kind (read, write or delete) and what it does.

Needs no server: it reports what would be registered, not what a server accepts.

  technitium-mcp tools                               # the default set (core), reads only
  technitium-mcp tools --toolsets all                # every tool that only reads
  technitium-mcp tools --toolsets all --enable-write # and the ones that change a server
  technitium-mcp tools -q                            # names only`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			out := cmd.OutOrStdout()
			quiet, _ := cmd.Flags().GetBool("quiet")

			f := GetFlags()
			opts, err := f.ToolOptions()
			if err != nil {
				return err
			}
			list, err := tools.Describe(opts)
			if err != nil {
				return err
			}

			if quiet {
				for _, t := range list {
					_, _ = fmt.Fprintln(out, t.Name)
				}

				return nil
			}

			byset := map[string][]tools.ToolInfo{}
			counts := map[string]int{}
			for _, t := range list {
				byset[t.Toolset] = append(byset[t.Toolset], t)
				counts[t.Kind]++
			}

			for _, set := range tools.ToolsetOrder {
				in := byset[set]
				if len(in) == 0 {
					continue
				}
				_, _ = fmt.Fprintf(out, "\n%s (%d)\n", set, len(in))
				for _, t := range in {
					_, _ = fmt.Fprintf(out, "  %-32s %-6s %s\n", t.Name, t.Kind, firstSentence(t.Description))
				}
			}
			_, _ = fmt.Fprintf(out, "\n%d tools: %d read, %d write, %d delete\n", len(list), counts["read"], counts["write"], counts["delete"])
			switch {
			case !f.EnableWrite:
				_, _ = fmt.Fprintln(out, "only tools that read are listed; --enable-write registers the ones that change a server, and --enable-delete beside it the ones that delete")
			case !f.EnableDelete:
				_, _ = fmt.Fprintln(out, "delete tools are hidden; --enable-delete registers them")
			default:
			}
			_, _ = fmt.Fprintf(out, "\ntoolsets: all, %s\n", strings.Join(tools.ToolsetNames(), ", "))
			_, _ = fmt.Fprintf(out, "families: %s\n", strings.Join(tools.FamilyNames(), ", "))
			_, _ = fmt.Fprintf(out, "select with --toolsets / TECHNITIUM_TOOLSETS; core is always included. Default is %s - use --toolsets all for every tool. --allow-tools adds tools to the sets by name, and with no --toolsets registers only the tools it names; --deny-tools takes tools away.\n", strings.Join(DefaultToolsets, ","))

			return nil
		},
	}
	cmd.Flags().BoolP("quiet", "q", false, "print tool names only")

	return cmd
}

func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "info",
		Short:         "Check connectivity and print each configured server's name and version",
		Long:          `Connects to each configured Technitium server and prints the name it is configured under, its address, its own domain name and version, and the account the API token acts as. A server that cannot be asked is printed with the reason, and the command fails.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			out := cmd.OutOrStdout()

			set, err := GetFlags().Servers()
			if err != nil {
				return err
			}

			failed := 0
			for _, srv := range set.Every() {
				session, err := srv.Client.Session(cmd.Context())
				if err != nil {
					failed++
					_, _ = fmt.Fprintf(out, "%s at %s: %v\n", srv.Name, srv.Client.BaseURL(), err)

					continue
				}
				_, _ = fmt.Fprintf(out, "%s at %s: Technitium %s, %s, as %s\n", srv.Name, srv.Client.BaseURL(), session.Info.Version, session.Info.Domain, session.Username)
			}
			if failed > 0 {
				return fmt.Errorf("%d of the %d configured servers could not be asked", failed, set.Len())
			}

			return nil
		},
	}
}
