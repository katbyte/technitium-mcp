package apidoc

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// fence opens and closes a block of example text, as the document does.
const fence = "```"

// A small document in the real one's layout, with the slips the real one
// makes: a marker written "URL\:", an address missing its closing backtick,
// a call with no parameters, and a list of an answer's fields under a second
// WHERE that is not the call's parameters.
var sample = strings.Join([]string{
	"# API Documentation",
	"",
	"## API Response Format",
	"",
	fence,
	"### not a call: this is inside an example",
	"URL:\\",
	"`http://localhost:5380/api/not/a/call`",
	fence,
	"",
	"## Zone API Calls",
	"",
	"### List Zones",
	"",
	"URL:\\",
	"`http://localhost:5380/api/zones/list?pageNumber=1&zonesPerPage=10`",
	"",
	"OBSOLETE PATH:\\",
	"`/api/zone/list`\\",
	"`/api/listZones`",
	"",
	"PERMISSIONS:\\",
	"Zones: View",
	"",
	"WHERE:",
	"- `token`: The session token.",
	"- `filterName` (optional): A filter.",
	"",
	"RESPONSE:",
	fence,
	`{"status": "ok"}`,
	fence,
	"",
	"WHERE:",
	"- `totalZones`: A field of the answer, not a parameter.",
	"",
	"### Unsign Zone",
	"",
	"URL\\:",
	"`http://server2.home:5380/api/zones/dnssec/unsign?zone=example.com",
	"",
	"WHERE:",
	"- `token`: The session token.",
	"",
	"### Status",
	"",
	"URL: ",
	"`http://localhost:5380/api/status`",
	"",
	"Response:",
	fence,
	"{}",
	fence,
}, "\n")

func TestParse(t *testing.T) {
	t.Parallel()

	doc, err := Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Paths(); !slices.Equal(got, []string{"status", "zones/dnssec/unsign", "zones/list"}) {
		t.Fatalf("the calls read = %v", got)
	}

	list := doc.Call("zones/list")
	if list.Title != "List Zones" || !slices.Equal(list.Obsolete, []string{"zone/list", "listZones"}) {
		t.Errorf("zones/list = %+v", list)
	}
	// its parameters are the WHERE list's and the example address's, and
	// nothing from the answer's own WHERE
	if !slices.Equal(list.Params, []string{"filterName", "pageNumber", "token", "zonesPerPage"}) {
		t.Errorf("zones/list takes %v", list.Params)
	}
	if !list.Takes("filterName") || list.Takes("totalZones") {
		t.Error("Takes does not follow the call's parameters")
	}

	if unsign := doc.Call("zones/dnssec/unsign"); unsign == nil || !slices.Equal(unsign.Params, []string{"token", "zone"}) {
		t.Errorf("a call whose marker and address are miswritten the way the document miswrites them = %+v", unsign)
	}
	if status := doc.Call("status"); status == nil || len(status.Params) != 0 {
		t.Errorf("a call with no parameters = %+v", status)
	}

	if now := doc.ReplacedBy("listZones"); now == nil || now.Path != "zones/list" {
		t.Errorf("ReplacedBy(listZones) = %+v", now)
	}
	if doc.ReplacedBy("zones/list") != nil || doc.Call("not/a/call") != nil || doc.Call("nope") != nil {
		t.Error("a path that is no call's read as one")
	}
}

// A document that cannot be read as expected is an error, never a shorter
// list of calls: one whose layout changed must not pass for one fully
// covered.
func TestParseRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct{ text, want string }{
		"nothing":            {"# A document\n\nwith no calls in it\n", "no API call could be read"},
		"a call with no url": {"### List Zones\n\nPERMISSIONS:\\\nZones: View\n", `the section "List Zones" gives no address under its URL marker`},
		"a call twice":       {"### One\nURL:\\\n`http://h/api/a/b`\n### Two\nURL:\\\n`http://h/api/a/b`\n", `"One" and "Two" both describe a/b`},
	} {
		if _, err := Parse(tc.text); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Parse = %v, want an error saying %q", name, err, tc.want)
		}
	}
}

// The document read is the one for the highest server version vendored,
// compared number by number: 15.10 is above 15.6.
func TestLoadTakesTheHighestVersion(t *testing.T) {
	t.Parallel()

	call := func(path string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("### A Call\nURL:\\\n`http://h/api/" + path + "`\n")}
	}
	doc, err := Load(fstest.MapFS{
		"technitium-apidocs-15.6.0.md":  call("old"),
		"technitium-apidocs-15.10.0.md": call("new"),
		"technitium-apidocs-9.md":       call("older"),
		"README.md":                     call("readme"),
		"unwrapped.txt":                 {Data: []byte("old\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != "15.10.0" || doc.File != "technitium-apidocs-15.10.0.md" || doc.Call("new") == nil {
		t.Errorf("Load read %s (%s): %v", doc.File, doc.Version, doc.Paths())
	}

	if _, err := Load(fstest.MapFS{"README.md": call("readme")}); err == nil {
		t.Error("a directory with no document in it was read")
	}
	if _, err := Load(fstest.MapFS{"technitium-apidocs-1.0.md": {Data: []byte("nothing here")}}); err == nil || !strings.Contains(err.Error(), "technitium-apidocs-1.0.md") {
		t.Errorf("a document with no calls = %v, want an error naming the file", err)
	}
}

// The vendored document reads whole: every call the server has, each with
// the token it is documented to take but one.
func TestTheVendoredDocument(t *testing.T) {
	t.Parallel()

	doc, err := Vendored()
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Calls) < 130 {
		t.Errorf("%s reads as %d calls, where 15.6 has 139: has its layout changed?", doc.File, len(doc.Calls))
	}
	for _, path := range []string{"status", "user/session/get", "zones/list", "zones/records/get", "zones/records/add", "cache/flush", "dnsClient/resolve", "logs/query", "dhcp/leases/list", "admin/cluster/state"} {
		if doc.Call(path) == nil {
			t.Errorf("%s has no %s", doc.File, path)
		}
	}
	for i := range doc.Calls {
		c := &doc.Calls[i]
		if c.Path != "status" && !c.Takes("token") && !c.Takes("user") {
			t.Errorf("%s (%s) reads as taking no token: its parameters were not read (%v)", c.Path, c.Title, c.Params)
		}
	}
	if add := doc.Call("zones/records/add"); add == nil || !add.Takes("ipAddress") || !add.Takes("cname") || !add.Takes("overwrite") || add.Takes("addedRecord") {
		t.Errorf("zones/records/add takes %v", add)
	}
	// one parameter's name is closed a space late, and the ones listed after it are still the call's
	if set := doc.Call("zones/options/set"); set == nil || !set.Takes("primaryZoneTransferProtocol") || !set.Takes("update") || !set.Takes("updateSecurityPolicies") {
		t.Errorf("zones/options/set takes %v", set)
	}
}
