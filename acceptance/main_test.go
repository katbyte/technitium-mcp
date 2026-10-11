//go:build integration

// Package acceptance covers every tool against real Technitium servers
// running in Docker, so the shapes the tools read, the parameters they send
// and the permissions they need are checked against the thing technitium-mcp
// actually talks to rather than a stub.
//
// The suite runs three times on the same servers, because the tools are used
// three ways: on one server, on two that know nothing of each other, and on
// two that are a cluster. TECHNITIUM_TEST_TOPOLOGY says which a run is, and
// the cluster is made by the run that asks for it. The fixtures are a zone
// every server holds - one server's own, two servers' copies that differ a
// little, or a cluster's zone and the copy it gives its other node - and a
// zone only the first server holds, which is what the answers set side by
// side.
//
// Each run fails when a registered tool was never seen to answer in it.
//
//	make testacc-acceptance                  # all three, servers started and torn down
//
//	eval "$(.scripts/testenv.sh up single)"   # or drive it by hand: one server,
//	go test -tags integration ./acceptance/...
//	eval "$(.scripts/testenv.sh add)"         # a second beside it,
//	go test -tags integration ./acceptance/...
//	TECHNITIUM_TEST_TOPOLOGY=cluster go test -tags integration ./acceptance/...   # and the two as a cluster
//	.scripts/testenv.sh down
package acceptance

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(runSuite(m)) }
