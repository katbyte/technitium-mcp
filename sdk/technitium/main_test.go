package technitium_test

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	apidefs "github.com/katbyte/technitium-mcp/api-defs"
	"github.com/katbyte/technitium-mcp/sdk/apidoc"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// TestMain runs the package's tests and then holds what they sent against
// the API document: every parameter the document gives a call was sent by
// some test, or is in api-defs/unsent.txt with why. A client that wraps a
// call and cannot send half of what the call takes is otherwise counted as
// covering it. Only a whole run is checked: one narrowed with -run sends
// only what it runs.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 && flag.Lookup("test.run").Value.String() == "" && flag.Lookup("test.skip").Value.String() == "" {
		if problems := unsentParameters(); len(problems) > 0 {
			fmt.Println("--- FAIL: every parameter in the API document is sent by a test, or is in api-defs/unsent.txt")
			for _, problem := range problems {
				fmt.Println("    " + problem)
			}
			code = 1
		}
	}
	os.Exit(code)
}

// unsentParameters is what is wrong between the document, what the tests
// sent and the list of exceptions.
func unsentParameters() []string {
	doc, err := apidoc.Vendored()
	if err != nil {
		return []string{err.Error()}
	}
	var listed []string
	for line := range strings.SplitSeq(apidefs.Unsent, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			listed = append(listed, line)
		}
	}

	var problems []string
	if !slices.IsSorted(listed) {
		problems = append(problems, "api-defs/unsent.txt is not sorted")
	}
	for _, line := range listed {
		path, param, _ := strings.Cut(line, " ")
		switch call := doc.Call(path); {
		case call == nil || !call.Takes(param):
			problems = append(problems, fmt.Sprintf("api-defs/unsent.txt lists %s, which %s does not have: take the line out", line, doc.File))
		case technitiumtest.Sent(path, param):
			problems = append(problems, fmt.Sprintf("api-defs/unsent.txt lists %s, which a test now sends: take the line out", line))
		default:
		}
	}
	for _, path := range doc.Paths() {
		var missing []string
		for _, param := range doc.Call(path).Params {
			if param != "token" && param != "node" && !technitiumtest.Sent(path, param) && !slices.Contains(listed, path+" "+param) {
				missing = append(missing, param)
			}
		}
		if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf("%s: no test sends %s", path, strings.Join(missing, ", ")))
		}
	}

	return problems
}
