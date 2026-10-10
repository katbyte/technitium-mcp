//go:build integration

// Package integration runs the client in sdk/technitium against Technitium
// servers running in Docker. It tests one thing: that every request the
// client builds is one a real server accepts, and that what the server
// answers decodes into the client's types without losing what it carries.
// The unit tests hold the client against the API document; this holds it
// against the server, which is what the document is only a description of.
// Nothing here is about the tools; ../acceptance covers those.
//
// The suite runs three times on the same servers, because the client is used
// three ways: on one server, on two that know nothing of each other, and on
// two that are a cluster. TECHNITIUM_TEST_TOPOLOGY says which a run is, and
// the cluster is made by the run that asks for it, through the client.
//
// Every test makes the zones it needs, named for itself under .test, and
// deletes them when it ends.
//
//	make testacc-integration                 # all three, servers started and torn down
//
//	eval "$(scripts/testenv.sh up single)"   # or drive it by hand: one server,
//	go test -tags integration ./integration/...
//	eval "$(scripts/testenv.sh add)"         # a second beside it,
//	go test -tags integration ./integration/...
//	TECHNITIUM_TEST_TOPOLOGY=cluster go test -tags integration ./integration/...   # and the two as a cluster
//	scripts/testenv.sh down
package integration

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/katbyte/technitium-mcp/lib/testenv"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// world is the servers under test and how they are arranged, nil when the
// environment names none and every test skips.
var world *testenv.World

func TestMain(m *testing.M) { os.Exit(runSuite(m)) }

// runSuite finds the servers under test, arranges them as the environment
// asks - which for a cluster is making one - and runs the tests, returning
// the code to exit with.
func runSuite(m *testing.M) int {
	if testenv.Configured() {
		var err error
		if world, err = testenv.Open(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr, "integration setup:", err)

			return 1
		}
	}

	return m.Run()
}

// ready skips the test when the environment names no servers.
func ready(t *testing.T) {
	t.Helper()

	if world == nil {
		t.Skip(testenv.NotConfigured)
	}
}

// server is the client for one of the servers by name.
func server(t *testing.T, name string) *technitium.Client {
	t.Helper()

	ready(t)
	c, err := world.Client(name)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

// first is the client for the server the suite makes its zones on: the only
// one, or the first of two, which in a cluster is its primary node.
func first(t *testing.T) *technitium.Client {
	t.Helper()

	ready(t)

	return server(t, world.First)
}

// zone makes a primary zone on a server for the length of a test, held by
// that server alone.
func zone(t *testing.T, c *technitium.Client, name string) {
	t.Helper()

	makeZone(t, c, technitium.NewZone{Name: name, Type: technitium.ZonePrimary})
}

// makeZone makes a zone on a server for the length of a test.
func makeZone(t *testing.T, c *technitium.Client, z technitium.NewZone) {
	t.Helper()

	// a run that was cut short may have left it behind
	_ = c.DeleteZone(t.Context(), z.Name)
	if _, err := c.CreateZone(t.Context(), z); err != nil {
		t.Fatalf("creating %s: %v", z.Name, err)
	}
	// a test's own context is cancelled before its clean-ups run
	ctx := context.WithoutCancel(t.Context())
	t.Cleanup(func() {
		if err := c.DeleteZone(ctx, z.Name); err != nil {
			t.Errorf("deleting %s: %v", z.Name, err)
		}
	})
}
