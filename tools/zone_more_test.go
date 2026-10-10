package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// morePair is zonePair with what the calls on a whole zone answer.
func morePair(t *testing.T) *pair {
	t.Helper()

	p := zonePair(t)
	for _, path := range []string{"zones/delete", "zones/clone", "zones/convert", "zones/import"} {
		p.both(path, `{}`)
	}

	return p
}

// A zone is deleted with what it holds said first, and nothing is sent by a
// dry run or for a zone the server does not hold.
func TestZoneDelete(t *testing.T) {
	t.Parallel()

	p := morePair(t)
	suite := p.session(t, everything)

	dry := suite.Call(t, "zone_delete", map[string]any{"server": "dock", "zone": "Only.example.", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have deleted the Primary zone only.example on dock with its 4 records"}) || dry["type"] != "Primary" || acctest.Num(t, dry["records"], "records") != 4 || len(p.dock.Requests("zones/delete")) != 0 {
		t.Errorf("a dry run = %v", dry)
	}

	// deleted, the server no longer lists it, which the tool reads back
	p.dock.Then("zones/delete", func(technitiumtest.Request) {
		p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7}]}`)
	})
	out := suite.Call(t, "zone_delete", map[string]any{"server": "dock", "zone": "only.example"})
	if !acctest.BoolOf(out["changed"]) || out["zone"] != "only.example" || !strings.Contains(acctest.Str(out["note"]), "can empty the server's whole cache") || p.dock.Last("zones/delete").Params.Get("zone") != "only.example" {
		t.Errorf("deleted = %v, asked with %v", out, p.dock.Last("zones/delete").Params)
	}
	if msg := suite.CallErr(t, "zone_delete", map[string]any{"server": "dock", "zone": "only.example"}); !strings.Contains(msg, "dock holds no zone named only.example") || len(p.dock.Requests("zones/delete")) != 1 {
		t.Errorf("a zone that is not there = %q", msg)
	}
	if msg := suite.CallErr(t, "zone_delete", map[string]any{"server": "dock", "zone": " "}); !strings.Contains(msg, "which zone") {
		t.Errorf("no zone = %q", msg)
	}
	// a change is made on one server, which must be named when there are two
	if msg := suite.CallErr(t, "zone_delete", map[string]any{"zone": "example.com"}); !strings.Contains(msg, "server") {
		t.Errorf("no server named = %q", msg)
	}

	// a server that says ok and still holds the zone is not believed
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Secondary","soaSerial":6}]}`)
	if msg := suite.CallErr(t, "zone_delete", map[string]any{"server": "rpi", "zone": "example.com"}); !strings.Contains(msg, "the server said ok and rpi still holds example.com") {
		t.Errorf("a deletion that did not take = %q", msg)
	}
}

func TestZoneCloneAndConvert(t *testing.T) {
	t.Parallel()

	p := morePair(t)
	suite := p.session(t, everything)

	dry := suite.Call(t, "zone_clone", map[string]any{"server": "dock", "zone": "new.example", "source": "example.com", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have made new.example on dock as a copy of example.com"}) || dry["after"] != nil || len(p.dock.Requests("zones/clone")) != 0 {
		t.Errorf("a dry run of a clone = %v", dry)
	}
	p.dock.Then("zones/clone", func(technitiumtest.Request) {
		p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"new.example","type":"Primary","soaSerial":1}]}`)
	})
	cloned := suite.Call(t, "zone_clone", map[string]any{"server": "dock", "zone": "New.example.", "source": "example.com"})
	if asked := p.dock.Last("zones/clone"); asked.Params.Get("zone") != "new.example" || asked.Params.Get("sourceZone") != "example.com" || acctest.Object(t, cloned["after"], "after")["type"] != "Primary" {
		t.Errorf("cloned = %v, asked with %v", cloned, asked.Params)
	}
	for msg, args := range map[string]map[string]any{
		"dock holds new.example already":             {"server": "dock", "zone": "new.example", "source": "example.com"},
		"the zone to copy: dock holds no zone named": {"server": "dock", "zone": "other.example", "source": "nothing.example"},
		"is no zone name":                            {"server": "dock", "zone": "two words", "source": "example.com"},
	} {
		if got := suite.CallErr(t, "zone_clone", args); !strings.Contains(got, msg) {
			t.Errorf("zone_clone %v = %q, want %q in it", args, got, msg)
		}
	}
	if len(p.dock.Requests("zones/clone")) != 1 {
		t.Errorf("%d clones reached the server, want the one", len(p.dock.Requests("zones/clone")))
	}

	// a conversion: the type is read in any case, a zone of that type already is left alone, and a server that does not turn it is not believed
	dry = suite.Call(t, "zone_convert", map[string]any{"server": "dock", "zone": "example.com", "type": "forwarder", "dry_run": true})
	if !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have turned example.com on dock from a Primary zone into a Forwarder zone"}) || len(p.dock.Requests("zones/convert")) != 0 {
		t.Errorf("a dry run of a conversion = %v", dry)
	}
	if same := suite.Call(t, "zone_convert", map[string]any{"server": "dock", "zone": "example.com", "type": "PRIMARY"}); acctest.BoolOf(same["changed"]) || len(acctest.Strs(t, same["changes"], "changes")) != 0 || len(p.dock.Requests("zones/convert")) != 0 {
		t.Errorf("converted to what it is = %v", same)
	}
	if msg := suite.CallErr(t, "zone_convert", map[string]any{"server": "dock", "zone": "example.com", "type": "Forwarder"}); !strings.Contains(msg, "the server said ok and example.com on dock is still a Primary zone") || p.dock.Last("zones/convert").Params.Get("type") != "Forwarder" {
		t.Errorf("a conversion the server did not make = %q", msg)
	}
	p.dock.Then("zones/convert", func(technitiumtest.Request) {
		p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Forwarder","soaSerial":7}]}`)
		p.dock.Answer("zones/options/get", `{"name":"example.com","type":"Forwarder","queryAccess":"Allow","zoneTransfer":"Deny","notify":"None","update":"Deny"}`)
	})
	if done := suite.Call(t, "zone_convert", map[string]any{"server": "dock", "zone": "example.com", "type": "Forwarder"}); acctest.Object(t, done["after"], "after")["type"] != "Forwarder" || !acctest.BoolOf(done["changed"]) {
		t.Errorf("converted = %v", done)
	}
	if msg := suite.CallErr(t, "zone_convert", map[string]any{"server": "dock", "zone": "example.com", "type": "Tertiary"}); !strings.Contains(msg, `type "Tertiary": a zone is one of Primary, Secondary`) {
		t.Errorf("a type that is none = %q", msg)
	}
}

// A zone file is counted before it is sent, sent as a file with how it is to
// be taken in the address, and never sent to a copy.
func TestZoneImport(t *testing.T) {
	t.Parallel()

	p := morePair(t)
	suite := p.session(t, everything)
	const file = "$ORIGIN example.com.\n; a comment\n\nwww 300 IN A 10.0.0.9\nmail 300 IN A 10.0.0.10\n"

	dry := suite.Call(t, "zone_import", map[string]any{"server": "dock", "zone": "example.com", "zone_file": file, "dry_run": true})
	if acctest.Num(t, dry["in_file"], "in_file") != 2 || acctest.Num(t, dry["before"], "before") != 4 || dry["records"] != nil || !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have imported the file's 2 records into example.com on dock, replacing the records it has at the same names and types"}) || len(p.dock.Requests("zones/import")) != 0 {
		t.Errorf("a dry run = %v", dry)
	}
	out := suite.Call(t, "zone_import", map[string]any{"server": "dock", "zone": "example.com", "zone_file": file})
	asked := p.dock.Last("zones/import")
	if string(asked.File) != file || len(asked.Params) != 1 || asked.Params.Get("zone") != "example.com" || acctest.Num(t, out["records"], "records") != 4 {
		t.Errorf("imported = %v, sent %q with %v", out, asked.File, asked.Params)
	}
	kept := suite.Call(t, "zone_import", map[string]any{"server": "dock", "zone": "example.com", "zone_file": file, "keep_existing": true, "overwrite_soa_serial": true})
	if asked = p.dock.Last("zones/import"); asked.Params.Get("overwrite") != "false" || asked.Params.Get("overwriteSoaSerial") != "true" || asked.Params.Has("overwriteZone") || !strings.HasSuffix(acctest.Strs(t, kept["changes"], "changes")[0], "beside the records it has") {
		t.Errorf("imported keeping what was there = %v, with %v", kept["changes"], asked.Params)
	}
	replaced := suite.Call(t, "zone_import", map[string]any{"server": "dock", "zone": "example.com", "zone_file": file, "replace_zone": true})
	if asked = p.dock.Last("zones/import"); asked.Params.Get("overwriteZone") != "true" || !strings.HasSuffix(acctest.Strs(t, replaced["changes"], "changes")[0], "in place of the 4 records it had") {
		t.Errorf("imported in place of the zone = %v, with %v", replaced["changes"], asked.Params)
	}

	sent := len(p.dock.Requests("zones/import")) + len(p.rpi.Requests("zones/import"))
	for msg, args := range map[string]map[string]any{
		"the zone file holds no records":            {"server": "dock", "zone": "example.com", "zone_file": "; nothing\n$TTL 300\n"},
		"ask for opposite things":                   {"server": "dock", "zone": "example.com", "zone_file": file, "keep_existing": true, "replace_zone": true},
		"rpi holds example.com as a Secondary zone": {"server": "rpi", "zone": "example.com", "zone_file": file},
		"dock holds no zone named nothing.example":  {"server": "dock", "zone": "nothing.example", "zone_file": file},
	} {
		if got := suite.CallErr(t, "zone_import", args); !strings.Contains(got, msg) {
			t.Errorf("zone_import %v = %q, want %q in it", args["zone"], got, msg)
		}
	}
	if now := len(p.dock.Requests("zones/import")) + len(p.rpi.Requests("zones/import")); now != sent {
		t.Errorf("%d refused imports reached a server", now-sent)
	}
}

// A zone file's records are its lines that are not blank, a comment or a
// directive.
func TestRecordLines(t *testing.T) {
	t.Parallel()

	if got := recordLines("a 1 IN A 10.0.0.1\n\n; c\n$ORIGIN x.\n b 1 IN A 10.0.0.2\n"); got != 2 {
		t.Errorf("recordLines = %d, want 2", got)
	}
}
