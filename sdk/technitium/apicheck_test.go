package technitium_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	apidefs "github.com/katbyte/technitium-mcp/api-defs"
	"github.com/katbyte/technitium-mcp/sdk/apidoc"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

// callers are the client's own methods that make an API call, each taking
// the call's path as its second argument.
var callers = []string{"read", "readWhole", "readText", "write"}

// parsePackage reads this package's own source: the files the client is
// built from, or its tests.
func parsePackage(t *testing.T, tests bool) []*ast.File {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") != tests {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("none of the package's source was found: the test runs in the package's own directory")
	}

	return files
}

// wrappedPaths are the API paths the client calls, read out of its source:
// every call it makes goes through one of callers with the path written out,
// so the list is exact. A path that is not written out fails the test.
func wrappedPaths(t *testing.T) []string {
	t.Helper()

	var paths []string
	for _, f := range parsePackage(t, false) {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !slices.Contains(callers, sel.Sel.Name) || len(call.Args) < 2 {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("a call to %s in %s does not write its path out as a string: the check against the API document reads the paths from the source", sel.Sel.Name, f.Name.Name)

				return true
			}
			path, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(paths, path) {
				paths = append(paths, path)
			}

			return true
		})
	}
	slices.Sort(paths)
	if len(paths) == 0 {
		t.Fatal("no API call was found in the client's source: has how it makes one changed?")
	}

	return paths
}

// The client is written by hand from a document written for people, so the
// two are held together here, both ways. Every path the client calls is one
// the document has, at its current spelling: a typo or a call a new version
// renamed fails. And every call the document has is either wrapped or named
// in api-defs/unwrapped.txt: a call a new document adds fails until it is
// wrapped or listed on purpose, and the list cannot keep a call that has
// since been wrapped or dropped.
func TestAPICallsAreTheDocuments(t *testing.T) {
	t.Parallel()

	doc, err := apidoc.Vendored()
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != technitium.APIVersion {
		t.Errorf("the client says it was written against %s and the vendored document is for %s: bring APIVersion in line once the client has been read against the new document", technitium.APIVersion, doc.Version)
	}

	wrapped := wrappedPaths(t)
	for _, path := range wrapped {
		if doc.Call(path) != nil {
			continue
		}
		if now := doc.ReplacedBy(path); now != nil {
			t.Errorf("the client calls %s, an obsolete path: the call is %s now", path, now.Path)

			continue
		}
		t.Errorf("the client calls %s, which %s does not have", path, doc.File)
	}

	var listed []string
	for line := range strings.SplitSeq(apidefs.Unwrapped, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			listed = append(listed, line)
		}
	}
	if !slices.IsSorted(listed) {
		t.Error("api-defs/unwrapped.txt is not sorted")
	}
	for _, path := range listed {
		switch {
		case slices.Contains(wrapped, path):
			t.Errorf("api-defs/unwrapped.txt lists %s, which the client now wraps: take the line out", path)
		case doc.Call(path) == nil:
			t.Errorf("api-defs/unwrapped.txt lists %s, which %s does not have: take the line out", path, doc.File)
		default:
		}
	}
	for _, path := range doc.Paths() {
		if !slices.Contains(wrapped, path) && !slices.Contains(listed, path) {
			t.Errorf("%s (%s) is in the API document and the client has no method for it: write one, or add the path to api-defs/unwrapped.txt", path, doc.Call(path).Title)
		}
	}
}

// TestAPICoverage says how much of the API the client wraps, for make
// apicheck: it fails nothing, since what is missing is the list
// TestAPICallsAreTheDocuments keeps honest.
func TestAPICoverage(t *testing.T) {
	t.Parallel()

	doc, err := apidoc.Vendored()
	if err != nil {
		t.Fatal(err)
	}
	wrapped := wrappedPaths(t)

	areas := map[string][2]int{}
	for _, path := range doc.Paths() {
		area, _, _ := strings.Cut(path, "/")
		n := areas[area]
		n[1]++
		if slices.Contains(wrapped, path) {
			n[0]++
		}
		areas[area] = n
	}
	names := make([]string, 0, len(areas))
	for area := range areas {
		names = append(names, area)
	}
	slices.Sort(names)

	var report strings.Builder
	fmt.Fprintf(&report, "sdk/technitium wraps %d of the %d API calls in %s\n", len(wrapped), len(doc.Calls), doc.File)
	for _, area := range names {
		fmt.Fprintf(&report, "  %-12s %3d of %3d\n", area, areas[area][0], areas[area][1])
	}
	t.Log("\n" + report.String())
}

// Every method the client offers is called by a test in this package, so its
// call and its parameters have been held against the API document by the
// canned server, which checks every request it gets. A method added with no
// test would send whatever it liked.
func TestEveryMethodHasATest(t *testing.T) {
	t.Parallel()

	var methods []string
	for _, f := range parsePackage(t, false) {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() || len(fn.Recv.List) != 1 {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			if recv, ok := star.X.(*ast.Ident); ok && recv.Name == "Client" {
				methods = append(methods, fn.Name.Name)
			}
		}
	}
	if len(methods) == 0 {
		t.Fatal("the client has no methods: has its type been renamed?")
	}

	called := map[string]bool{}
	for _, f := range parsePackage(t, true) {
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					called[sel.Sel.Name] = true
				}
			}

			return true
		})
	}
	for _, m := range methods {
		if !called[m] {
			t.Errorf("Client.%s is called by no test in this package", m)
		}
	}
}
