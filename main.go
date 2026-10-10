// Package main implements technitium-mcp, an MCP server and CLI for running and auditing Technitium DNS servers.
package main

import (
	"os"

	c "github.com/gookit/color"
	"github.com/katbyte/go-kt/clog"
	"github.com/katbyte/technitium-mcp/cli"
)

func main() {
	// the log level comes from TECHNITIUM_LOG; read it once here, before anything logs
	clog.SetLevelFromEnv("TECHNITIUM_LOG")

	cmd, err := cli.Make()
	if err != nil {
		clog.Log.Error(c.Sprintf("<red>technitium-mcp: building cmd</> %v", err))

		os.Exit(1)
	}

	if err := cmd.Execute(); err != nil {
		clog.Log.Error(c.Sprintf("<red>technitium-mcp:</> %v", err))

		os.Exit(1)
	}

	os.Exit(0)
}
