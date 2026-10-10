// Package apidoc reads the Technitium API document vendored under api-defs:
// the calls it describes, by path, with the parameters each takes. Technitium
// publishes no machine-readable description of its API, only this document
// written for people, so this is what the client in sdk/technitium is held
// against - which calls exist, and what each is sent.
//
// The document is regular enough to read: every call is a "###" section
// holding a "URL:" line with an example address, an optional "OBSOLETE PATH:"
// list, and a "WHERE:" list of parameters before its "RESPONSE:". A call that
// is sent a body says so under "REQUEST:", where a form's fields are shown as
// they are posted. A section that does not read that way is an error, never
// a call quietly left out: a document whose layout changed must not pass for
// one fully covered.
package apidoc

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	apidefs "github.com/katbyte/technitium-mcp/api-defs"
)

// Call is one API call as the document describes it.
type Call struct {
	// Title is the section's heading: List Zones
	Title string
	// Path is the call's path under /api/: zones/list
	Path string
	// Obsolete are the paths the call went by in older versions, which a
	// current client must not use
	Obsolete []string
	// Params are the names of the parameters the call takes: those its
	// WHERE list gives, those its example address carries, and the fields of
	// a form its REQUEST shows
	Params []string
	// Upload is the call taking a file, posted as a form's
	Upload bool
}

// Takes reports whether the call is documented as taking a parameter.
func (c *Call) Takes(param string) bool {
	return slices.Contains(c.Params, param)
}

// Doc is the document read.
type Doc struct {
	// Version is the server version the document is for, from its file name
	Version string
	// File is the document's file name
	File  string
	Calls []Call
}

// Call is the call at a path, nil when the document has none there.
func (d *Doc) Call(path string) *Call {
	for i := range d.Calls {
		if d.Calls[i].Path == path {
			return &d.Calls[i]
		}
	}

	return nil
}

// ReplacedBy is the call that now stands where an obsolete path did, nil
// when the path is no call's old one.
func (d *Doc) ReplacedBy(obsolete string) *Call {
	for i := range d.Calls {
		if slices.Contains(d.Calls[i].Obsolete, obsolete) {
			return &d.Calls[i]
		}
	}

	return nil
}

// Paths are every call's path, sorted.
func (d *Doc) Paths() []string {
	out := make([]string, 0, len(d.Calls))
	for i := range d.Calls {
		out = append(out, d.Calls[i].Path)
	}
	slices.Sort(out)

	return out
}

// filePattern is how a vendored document is named: by the server version it
// is for.
var filePattern = regexp.MustCompile(`^technitium-apidocs-(\d+(?:\.\d+)*)\.md$`)

// Vendored reads the document vendored in this repository, for the highest
// server version there.
func Vendored() (*Doc, error) {
	return Load(apidefs.Docs)
}

// Load reads the document in a directory for the highest server version
// there.
func Load(dir fs.FS) (*Doc, error) {
	entries, err := fs.ReadDir(dir, ".")
	if err != nil {
		return nil, err
	}

	best, bestVersion := "", ""
	for _, e := range entries {
		m := filePattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		if best == "" || newer(m[1], bestVersion) {
			best, bestVersion = e.Name(), m[1]
		}
	}
	if best == "" {
		return nil, errors.New("there is no technitium-apidocs-<version>.md to read")
	}

	raw, err := fs.ReadFile(dir, best)
	if err != nil {
		return nil, err
	}
	doc, err := Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", best, err)
	}
	doc.Version, doc.File = bestVersion, best

	return doc, nil
}

// newer reports whether version a is above b, number by number.
func newer(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(as), len(bs)) {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return x > y
		}
	}

	return false
}

var (
	// an example address: any host, then the call's path under /api/. The
	// document leaves the closing backtick off a few, so it is not asked for
	exampleURL = regexp.MustCompile("^`https?://[^/`]+/api/([^`?]+)(?:\\?([^`]*))?`?$")
	// an old path, as the lists under OBSOLETE PATH give them
	obsoletePath = regexp.MustCompile("^`/api/([^`]+)`")
	// a parameter in a WHERE list; the document closes one name's backticks a space late
	paramLine = regexp.MustCompile("^- `([A-Za-z0-9_]+) ?`")
	// a form's field as a REQUEST shows one posted: config=...
	formField = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_]*)=\S`)
)

// sendsFile reports whether a line of a REQUEST says the call takes a file.
func sendsFile(line string) bool {
	line = strings.ToLower(line)

	return strings.Contains(line, "multi-part") || strings.Contains(line, "multipart")
}

// Parse reads the calls out of the document's text.
func Parse(text string) (*Doc, error) {
	doc := &Doc{}
	var (
		cur      *Call
		fenced   bool
		section  string // what the lines being read are part of: url, obsolete, where
		answered bool   // the section's RESPONSE has begun, so a WHERE after it describes the answer
		problems []error
	)
	finish := func() {
		if cur == nil {
			return
		}
		if cur.Path == "" {
			problems = append(problems, fmt.Errorf("the section %q gives no address under its URL marker", cur.Title))
		} else {
			doc.Calls = append(doc.Calls, *cur)
		}
		cur = nil
	}

	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimRight(line, " \r")
		if strings.HasPrefix(line, "```") {
			fenced = !fenced

			continue
		}
		if fenced {
			// what a REQUEST shows posted is a form's fields, each a parameter
			if m := formField.FindStringSubmatch(line); m != nil && cur != nil && section == "request" {
				addParam(cur, m[1])
			}

			continue
		}

		if title, ok := strings.CutPrefix(line, "### "); ok {
			finish()
			cur, section, answered = &Call{Title: strings.TrimSpace(title)}, "", false

			continue
		}
		if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "# ") {
			finish()

			continue
		}
		if cur == nil {
			continue
		}

		// a marker ends a line with a backslash, and the document writes two
		// of them with the backslash before the colon
		marker := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(line), `\`, ""))
		switch {
		case marker == "URL:":
			section = "url"
		case marker == "OBSOLETE PATH:":
			section = "obsolete"
		case marker == "WHERE:" && !answered:
			section = "where"
		case marker == "RESPONSE:" || strings.HasPrefix(marker, "RESPONSE HEADERS:"):
			section, answered = "", true
		case strings.HasPrefix(marker, "REQUEST:") && !answered:
			section = "request"
			cur.Upload = cur.Upload || sendsFile(line)
		case section == "request":
			cur.Upload = cur.Upload || sendsFile(line)
		case section == "url":
			if m := exampleURL.FindStringSubmatch(line); m != nil {
				cur.Path = m[1]
				query, err := url.ParseQuery(m[2])
				if err != nil {
					problems = append(problems, fmt.Errorf("the section %q has an example address whose query cannot be read: %w", cur.Title, err))
				}
				for name := range query {
					addParam(cur, name)
				}
			}
			if line != "" {
				section = ""
			}
		case section == "obsolete":
			if m := obsoletePath.FindStringSubmatch(line); m != nil {
				cur.Obsolete = append(cur.Obsolete, m[1])
			} else if line != "" {
				section = ""
			}
		case section == "where":
			// an entry that does not read as a parameter is passed over, and the list goes on after it
			if m := paramLine.FindStringSubmatch(line); m != nil {
				addParam(cur, m[1])
			} else if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "- ") {
				section = ""
			}
		default:
		}
	}
	finish()

	if len(doc.Calls) == 0 {
		problems = append(problems, errors.New("no API call could be read out of it: has the document's layout changed?"))
	}
	seen := map[string]string{}
	for i := range doc.Calls {
		c := &doc.Calls[i]
		if other, dup := seen[c.Path]; dup {
			problems = append(problems, fmt.Errorf("the sections %q and %q both describe %s", other, c.Title, c.Path))
		}
		seen[c.Path] = c.Title
		slices.Sort(c.Params)
	}
	if err := errors.Join(problems...); err != nil {
		return nil, err
	}

	return doc, nil
}

// addParam adds a parameter to a call once.
func addParam(c *Call, name string) {
	// an example address with a slip in it, &=pageNumber=1, gives a parameter with no name
	if name != "" && !slices.Contains(c.Params, name) {
		c.Params = append(c.Params, name)
	}
}
