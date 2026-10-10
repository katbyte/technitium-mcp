package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// writePair is two servers for the writes: dock holds a zone and the reverse
// zone for its addresses as its own, and rpi holds the zone as a copy.
func writePair(t *testing.T) *pair {
	t.Helper()

	p := newPair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"0.0.10.in-addr.arpa","type":"Primary","soaSerial":2}]}`)
	p.rpi.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Secondary","soaSerial":7}]}`)
	// what each call answers when a test does not say otherwise
	p.dock.Answer("zones/records/get", `{"zone":{"name":"example.com"},"records":[]}`)
	p.dock.Answer("zones/records/add", `{"addedRecord":{"name":"x","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.1"}}}`)
	p.dock.Answer("zones/records/update", `{"updatedRecord":{"name":"x","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.1"}}}`)
	p.dock.Answer("zones/records/delete", `{}`)

	return p
}

// at makes a server answer with these records for a name.
func at(server *technitiumtest.Server, name string, records ...string) {
	server.AnswerWhen("zones/records/get", "domain", name, `{"zone":{"name":"example.com"},"records":[`+strings.Join(records, ",")+`]}`)
}

const (
	embyA    = `{"name":"emby.example.com","type":"A","ttl":300,"comments":"the emby vm","rData":{"ipAddress":"10.0.0.4"}}`
	embyAt7  = `{"name":"emby.example.com","type":"A","ttl":300,"comments":"the emby vm","rData":{"ipAddress":"10.0.0.7"}}`
	embyAt5  = `{"name":"emby.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.5"}}`
	embyTXT  = `{"name":"emby.example.com","type":"TXT","ttl":3600,"rData":{"text":"hello"}}`
	embyPTR  = `{"name":"4.0.0.10.in-addr.arpa","type":"PTR","ttl":300,"rData":{"ptrName":"emby.example.com"}}`
	otherPTR = `{"name":"7.0.0.10.in-addr.arpa","type":"PTR","ttl":300,"rData":{"ptrName":"mac.example.com"}}`
	mCNAME   = `{"name":"m.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"emby.example.com"}}`
)

// writes are the calls a server was sent that change it.
func writes(server *technitiumtest.Server) []string {
	var out []string
	for _, path := range []string{"zones/records/add", "zones/records/update", "zones/records/delete", "zones/create", "zones/delete"} {
		for _, req := range server.Requests(path) {
			out = append(out, strings.TrimPrefix(path, "zones/records/")+" "+req.Params.Get("type")+" "+req.Params.Get("domain"))
		}
	}

	return out
}

// A record that is not there is added, and the answer is the records before
// and after, read back; one that is there already is left alone, and one
// whose TTL or comment differ is changed in place with the rest kept.
func TestRecordSet(t *testing.T) {
	t.Parallel()

	p := writePair(t)
	suite := p.session(t, everything)

	// added: the server is read, written to, and read back
	p.dock.Then("zones/records/add", func(technitiumtest.Request) { at(p.dock, "emby.example.com", embyA) })
	out := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "Emby.example.com.", "type": "a", "value": "10.0.0.4", "ttl": 300, "comment": "the emby vm"})
	if out["server"] != "dock" || out["zone"] != "example.com" || !acctest.BoolOf(out["changed"]) || !slices.Equal(acctest.Strs(t, out["changes"], "changes"), []string{"added A 10.0.0.4 at emby.example.com"}) || len(acctest.Rows(t, out["before"], "before")) != 0 || out["note"] != nil {
		t.Errorf("the answer = %v", out)
	}
	if after := acctest.Rows(t, out["after"], "after"); len(after) != 1 || after[0]["value"] != "10.0.0.4" || after[0]["comment"] != "the emby vm" || acctest.Num(t, after[0]["ttl"], "ttl") != 300 {
		t.Errorf("after = %v", out["after"])
	}
	if asked := p.dock.Last("zones/records/add"); asked.Params.Get("domain") != "emby.example.com" || asked.Params.Get("zone") != "example.com" || asked.Params.Get("ipAddress") != "10.0.0.4" || asked.Params.Get("ttl") != "300" || asked.Params.Get("comments") != "the emby vm" || asked.Params.Has("overwrite") || asked.Params.Has("ptr") {
		t.Errorf("the record was added with %v", asked.Params)
	}

	// asked again, it is so already: nothing is written
	sent := len(writes(p.dock))
	again := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.4"})
	if acctest.BoolOf(again["changed"]) || len(acctest.Strs(t, again["changes"], "changes")) != 0 || len(writes(p.dock)) != sent {
		t.Errorf("a record already so = %v, with %d writes", again, len(writes(p.dock))-sent)
	}

	// a TTL alone: changed in place, and what was not given is kept and sent
	out = suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.4", "ttl": 600, "disabled": true})
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, []string{"changed the A record at emby.example.com: its TTL from 300 to 600, it to disabled"}) {
		t.Errorf("changes = %v", got)
	}
	if asked := p.dock.Last("zones/records/update"); asked.Params.Get("ipAddress") != "10.0.0.4" || asked.Params.Get("newIpAddress") != "10.0.0.4" || asked.Params.Get("ttl") != "600" || asked.Params.Get("comments") != "the emby vm" || asked.Params.Get("disable") != "true" {
		t.Errorf("the TTL was changed with %v", asked.Params)
	}
	// a comment cleared is given empty, where one left out is kept
	suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.4", "comment": ""})
	if asked := p.dock.Last("zones/records/update"); asked.Params.Get("comments") != "" || asked.Params.Get("ttl") != "300" {
		t.Errorf("the comment was cleared with %v", asked.Params)
	}
}

// replaces changes the record named into the new one, keeping its TTL and
// comment, and with ptr moves the address's PTR with it; only makes the
// record the single one of its type.
func TestRecordSetReplacesAndOnly(t *testing.T) {
	t.Parallel()

	p := writePair(t)
	at(p.dock, "emby.example.com", embyA, embyAt5, embyTXT)
	at(p.dock, "4.0.0.10.in-addr.arpa", embyPTR)
	at(p.dock, "7.0.0.10.in-addr.arpa", otherPTR)
	p.dock.Then("zones/records/update", func(req technitiumtest.Request) {
		if req.Params.Get("type") == "A" {
			at(p.dock, "emby.example.com", embyAt7, embyAt5, embyTXT)
		}
	})
	suite := p.session(t, everything)

	out := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.7", "replaces": "10.0.0.4", "ptr": true})
	want := []string{
		"changed the A record at emby.example.com: its value from 10.0.0.4 to 10.0.0.7",
		// the new address had a PTR naming another host, which is changed; the old address's is removed
		"changed the PTR at 7.0.0.10.in-addr.arpa from mac.example.com to emby.example.com",
		"removed PTR emby.example.com at 4.0.0.10.in-addr.arpa",
	}
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, want) {
		t.Errorf("changes =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	if before, after := acctest.Rows(t, out["before"], "before"), acctest.Rows(t, out["after"], "after"); len(before) != 2 || before[0]["value"] != "10.0.0.4" || len(after) != 2 || after[1]["value"] != "10.0.0.7" || after[1]["comment"] != "the emby vm" {
		t.Errorf("before = %v, after = %v", before, after)
	}
	updates := p.dock.Requests("zones/records/update")
	if a := updates[0]; a.Params.Get("ipAddress") != "10.0.0.4" || a.Params.Get("newIpAddress") != "10.0.0.7" || a.Params.Get("ttl") != "300" || a.Params.Get("comments") != "the emby vm" {
		t.Errorf("the address was changed with %v", a.Params)
	}
	if ptr := updates[1]; ptr.Params.Get("domain") != "7.0.0.10.in-addr.arpa" || ptr.Params.Get("zone") != "0.0.10.in-addr.arpa" || ptr.Params.Get("newPtrName") != "emby.example.com" {
		t.Errorf("the PTR was changed with %v", ptr.Params)
	}
	if gone := p.dock.Last("zones/records/delete"); gone.Params.Get("domain") != "4.0.0.10.in-addr.arpa" || gone.Params.Get("ptrName") != "emby.example.com" {
		t.Errorf("the old PTR was removed with %v", gone.Params)
	}

	// only: the record is set and the others of its type go, other types stay
	at(p.dock, "emby.example.com", embyAt7, embyAt5, embyTXT)
	out = suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.7", "only": true})
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, []string{"removed A 10.0.0.5 at emby.example.com"}) {
		t.Errorf("made the only one = %v", got)
	}
	// a value that is not there yet, as the only one, is written over them all
	p.dock.Then("zones/records/add", func(technitiumtest.Request) { at(p.dock, "emby.example.com", embyA, embyTXT) })
	out = suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.4", "only": true})
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, []string{"replaced the 2 A records at emby.example.com with 10.0.0.4"}) || p.dock.Last("zones/records/add").Params.Get("overwrite") != "true" {
		t.Errorf("written over the others = %v with %v", got, p.dock.Last("zones/records/add").Params)
	}

	// a name's one CNAME is changed by setting another
	at(p.dock, "m.example.com", mCNAME)
	p.dock.Then("zones/records/update", func(technitiumtest.Request) {
		at(p.dock, "m.example.com", strings.Replace(mCNAME, `"cname":"emby.example.com"`, `"cname":"plex.example.com"`, 1))
	})
	out = suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "m.example.com", "type": "CNAME", "value": "plex.example.com"})
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, []string{"changed the CNAME record at m.example.com: its value from emby.example.com to plex.example.com"}) {
		t.Errorf("a CNAME set over the one there = %v", got)
	}
}

// A dry run says what would be done and sends nothing that changes the
// server.
func TestRecordSetDryRun(t *testing.T) {
	t.Parallel()

	p := writePair(t)
	at(p.dock, "emby.example.com", embyA)
	at(p.dock, "4.0.0.10.in-addr.arpa", embyPTR)
	at(p.dock, "7.0.0.10.in-addr.arpa")
	suite := p.session(t, everything)

	out := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.7", "replaces": "10.0.0.4", "ptr": true, "dry_run": true})
	want := []string{
		"would have changed the A record at emby.example.com: its value from 10.0.0.4 to 10.0.0.7",
		"would have added PTR emby.example.com at 7.0.0.10.in-addr.arpa",
		"would have removed PTR emby.example.com at 4.0.0.10.in-addr.arpa",
	}
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, want) || !acctest.BoolOf(out["changed"]) || out["after"] != nil || !strings.Contains(acctest.Str(out["note"]), "a dry run: nothing was changed") {
		t.Errorf("a dry run = %v", out)
	}
	if sent := writes(p.dock); len(sent) != 0 {
		t.Errorf("a dry run sent %v", sent)
	}
	if dry := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "new.example.com", "type": "TXT", "value": "hello there", "disabled": true, "dry_run": true}); !slices.Equal(acctest.Strs(t, dry["changes"], "changes"), []string{"would have added TXT hello there at new.example.com", "would have disabled it"}) || len(writes(p.dock)) != 0 {
		t.Errorf("a dry run of a new disabled record = %v", dry)
	}
}

// What cannot be done is refused before anything is changed, saying why and
// what to do: a copy of a zone names the server that holds it as its own.
func TestRecordSetRefusals(t *testing.T) {
	t.Parallel()

	p := writePair(t)
	at(p.dock, "emby.example.com", embyA, embyTXT)
	at(p.dock, "m.example.com", mCNAME)
	suite := p.session(t, everything)

	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"no server, with two":          {map[string]any{"name": "a.example.com", "type": "A", "value": "10.0.0.1"}, "which server: a change is made on one server at a time, so name it (dock, rpi)"},
		"every server":                 {map[string]any{"server": "all", "name": "a.example.com", "type": "A", "value": "10.0.0.1"}, "one server at a time"},
		"a copy of the zone":           {map[string]any{"server": "rpi", "name": "a.example.com", "type": "A", "value": "10.0.0.1"}, "rpi holds example.com as a Secondary zone, a copy that takes no changes: make the change on dock, which holds the zone as its own. Nothing was changed"},
		"no zone for the name":         {map[string]any{"server": "dock", "name": "a.example.net", "type": "A", "value": "10.0.0.1"}, "dock holds no zone that a.example.net is in"},
		"a zone that is not it":        {map[string]any{"server": "dock", "name": "a.example.com", "type": "A", "value": "10.0.0.1", "zone": "example.net"}, "dock holds no zone named example.net that a.example.com is in"},
		"a CNAME beside records":       {map[string]any{"server": "dock", "name": "emby.example.com", "type": "CNAME", "value": "x.example.com"}, "emby.example.com has other records (A 10.0.0.4 at emby.example.com), and a CNAME stands alone"},
		"a record beside a CNAME":      {map[string]any{"server": "dock", "name": "m.example.com", "type": "A", "value": "10.0.0.1"}, "m.example.com is a CNAME to emby.example.com, and a CNAME stands alone at its name: no A record can be added beside it"},
		"nothing to replace":           {map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.7", "replaces": "10.0.0.9"}, "emby.example.com has no A record with the value 10.0.0.9 to replace (it has: 10.0.0.4)"},
		"a PTR with nowhere to go":     {map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "192.168.1.4", "ptr": true}, "the PTR for 192.168.1.4 belongs at 4.1.168.192.in-addr.arpa: dock holds no zone that 4.1.168.192.in-addr.arpa is in"},
		"a PTR for a name":             {map[string]any{"server": "dock", "name": "x.example.com", "type": "TXT", "value": "hello", "ptr": true}, "ptr is for an A or an AAAA record"},
		"an address of the wrong kind": {map[string]any{"server": "dock", "name": "x.example.com", "type": "A", "value": "fd00::4"}, "is not an address an A record holds"},
		"a value that is not one":      {map[string]any{"server": "dock", "name": "x.example.com", "type": "MX", "value": "mail.example.com"}, "a MX record's value is preference exchange"},
		"a type it cannot write":       {map[string]any{"server": "dock", "name": "x.example.com", "type": "SOA", "value": "a b 1 2 3 4 5"}, "cannot write record type SOA"},
		"no name":                      {map[string]any{"server": "dock", "name": "", "type": "A", "value": "10.0.0.1"}, "a record needs a name, a type and a value"},
	} {
		if msg := suite.CallErr(t, "record_set", tc.args); !strings.Contains(msg, tc.want) {
			t.Errorf("%s\n  = %q\n  want it to say %q", name, msg, tc.want)
		}
	}
	if sent := append(writes(p.dock), writes(p.rpi)...); len(sent) != 0 {
		t.Errorf("the refusals sent %v", sent)
	}

	// without --enable-write the tool is not there to call
	if msg := p.session(t, Options{}).CallErr(t, "record_set", map[string]any{"server": "dock", "name": "a.example.com", "type": "A", "value": "10.0.0.1"}); !strings.Contains(msg, "record_set") {
		t.Errorf("record_set with writes not enabled = %q", msg)
	}
}

// Records of one type at a name share one TTL, and the server rewrites them
// all when it changes - dropping their comments. A record added beside others
// takes their TTL unless given one, and when a TTL is given the others'
// comments are put back.
func TestRecordSetKeepsTheOtherRecordsComments(t *testing.T) {
	t.Parallel()

	p := writePair(t)
	at(p.dock, "emby.example.com", embyA)
	suite := p.session(t, everything)

	// with no TTL given, the set's own: nothing is rewritten
	p.dock.Then("zones/records/add", func(req technitiumtest.Request) {
		at(p.dock, "emby.example.com", embyA, `{"name":"emby.example.com","type":"A","ttl":`+req.Params.Get("ttl")+`,"rData":{"ipAddress":"10.0.0.9"}}`)
	})
	out := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.9"})
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, []string{"added A 10.0.0.9 at emby.example.com"}) || p.dock.Last("zones/records/add").Params.Get("ttl") != "300" || len(p.dock.Requests("zones/records/update")) != 0 {
		t.Errorf("added beside another = %v with %v", got, p.dock.Last("zones/records/add").Params)
	}

	// with a TTL given, the server sets it on the other too and drops its
	// comment, which is put back
	at(p.dock, "emby.example.com", embyA)
	p.dock.Then("zones/records/add", func(technitiumtest.Request) {
		at(p.dock, "emby.example.com", `{"name":"emby.example.com","type":"A","ttl":600,"rData":{"ipAddress":"10.0.0.4"}}`, `{"name":"emby.example.com","type":"A","ttl":600,"rData":{"ipAddress":"10.0.0.9"}}`)
	})
	out = suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.9", "ttl": 600})
	want := []string{
		"added A 10.0.0.9 at emby.example.com, and set the TTL of the other 1 A records there from 300 to 600, which share one",
		"kept the comment and state of A 10.0.0.4 at emby.example.com, which the server drops when the TTL its records share changes",
	}
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, want) {
		t.Errorf("changes =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	if back := p.dock.Last("zones/records/update"); back.Params.Get("ipAddress") != "10.0.0.4" || back.Params.Get("comments") != "the emby vm" || back.Params.Get("ttl") != "600" {
		t.Errorf("the comment was put back with %v", back.Params)
	}

	// a dry run says both
	at(p.dock, "emby.example.com", embyA)
	dry := suite.Call(t, "record_set", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.9", "ttl": 600, "dry_run": true})
	if got := acctest.Strs(t, dry["changes"], "changes"); len(got) != 2 || !strings.HasPrefix(got[1], "would have kept the comment and state of A 10.0.0.4") {
		t.Errorf("a dry run = %v", got)
	}
}

// record_delete deletes the record named and answers with it as it was; with
// several of a type it wants to know which, or all of them.
func TestRecordDelete(t *testing.T) {
	t.Parallel()

	p := writePair(t)
	at(p.dock, "emby.example.com", embyA, embyAt5, embyTXT)
	at(p.dock, "4.0.0.10.in-addr.arpa", embyPTR)
	suite := p.session(t, everything)

	// what would go, and nothing sent
	dry := suite.Call(t, "record_delete", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.4", "ptr": true, "dry_run": true})
	if got := acctest.Strs(t, dry["changes"], "changes"); !slices.Equal(got, []string{"would have deleted A 10.0.0.4 at emby.example.com", "would have removed PTR emby.example.com at 4.0.0.10.in-addr.arpa, which the server takes away with the address"}) || len(writes(p.dock)) != 0 || len(acctest.Rows(t, dry["left"], "left")) != 2 || !strings.Contains(acctest.Str(dry["note"]), "a dry run") {
		t.Errorf("a dry run = %v, with %v sent", dry, writes(p.dock))
	}

	// the server takes the address's PTR away with it, which the answer says
	p.dock.Then("zones/records/delete", func(req technitiumtest.Request) {
		if req.Params.Get("type") == "A" {
			at(p.dock, "emby.example.com", embyAt5, embyTXT)
			at(p.dock, "4.0.0.10.in-addr.arpa")
		}
	})
	out := suite.Call(t, "record_delete", map[string]any{"server": "dock", "name": "emby.example.com", "type": "A", "value": "10.0.0.4"})
	deleted := acctest.Rows(t, out["deleted"], "deleted")
	if len(deleted) != 1 || deleted[0]["value"] != "10.0.0.4" || deleted[0]["comment"] != "the emby vm" || acctest.Num(t, deleted[0]["ttl"], "ttl") != 300 {
		t.Errorf("deleted = %v, want the record as it was", deleted)
	}
	if left := acctest.Rows(t, out["left"], "left"); len(left) != 1 || left[0]["value"] != "10.0.0.5" || out["note"] != nil {
		t.Errorf("left = %v (%v)", left, out["note"])
	}
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, []string{"deleted A 10.0.0.4 at emby.example.com", "removed PTR emby.example.com at 4.0.0.10.in-addr.arpa, which the server takes away with the address"}) {
		t.Errorf("changes = %v", got)
	}
	if got := writes(p.dock); !slices.Equal(got, []string{"delete A emby.example.com"}) {
		t.Errorf("sent = %v, want the one delete: the server removed the PTR", got)
	}
	if gone := p.dock.Requests("zones/records/delete")[0]; gone.Params.Get("ipAddress") != "10.0.0.4" || gone.Params.Get("zone") != "example.com" {
		t.Errorf("the record was deleted with %v", gone.Params)
	}

	// a server that leaves the PTR: said, and with ptr removed
	at(p.dock, "left.example.com", strings.ReplaceAll(embyA, "emby.", "left."))
	at(p.dock, "4.0.0.10.in-addr.arpa", strings.ReplaceAll(embyPTR, "emby.", "left."))
	p.dock.Then("zones/records/delete", nil)
	if kept := suite.Call(t, "record_delete", map[string]any{"server": "dock", "name": "left.example.com", "type": "A"}); !strings.Contains(acctest.Str(kept["note"]), "the PTR at 4.0.0.10.in-addr.arpa still names left.example.com: ptr removes it too") || len(acctest.Strs(t, kept["changes"], "changes")) != 1 {
		t.Errorf("a PTR the server left = %v", kept)
	}
	sentBefore := len(p.dock.Requests("zones/records/delete"))
	removed := suite.Call(t, "record_delete", map[string]any{"server": "dock", "name": "left.example.com", "type": "A", "ptr": true})
	if got := acctest.Strs(t, removed["changes"], "changes"); len(got) != 2 || got[1] != "removed PTR left.example.com at 4.0.0.10.in-addr.arpa" || len(p.dock.Requests("zones/records/delete"))-sentBefore != 2 {
		t.Errorf("a PTR the server left, removed = %v", removed)
	}

	// the one record of a type needs no value, and the last at a name leaves nothing to read
	at(p.dock, "m.example.com", mCNAME)
	p.dock.Then("zones/records/delete", func(technitiumtest.Request) {
		p.dock.FailWhen("zones/records/get", "domain", "m.example.com", "error", "No such zone was found: m.example.com")
	})
	out = suite.Call(t, "record_delete", map[string]any{"server": "dock", "name": "m.example.com", "type": "cname"})
	if got := acctest.Rows(t, out["deleted"], "deleted"); len(got) != 1 || got[0]["value"] != "emby.example.com" || len(acctest.Rows(t, out["left"], "left")) != 0 {
		t.Errorf("the one CNAME = %v, left %v", out["deleted"], out["left"])
	}

	at(p.dock, "two.example.com", strings.ReplaceAll(embyA, "emby.", "two."), strings.ReplaceAll(embyAt5, "emby.", "two."))
	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"several, and which is unsaid": {map[string]any{"server": "dock", "name": "two.example.com", "type": "A"}, "two.example.com has 2 A records (10.0.0.4, 10.0.0.5): say which with value, or all"},
		"a value that is not there":    {map[string]any{"server": "dock", "name": "two.example.com", "type": "A", "value": "10.0.0.9"}, "has no A record with the value 10.0.0.9 (it has: 10.0.0.4, 10.0.0.5)"},
		"no record of the type":        {map[string]any{"server": "dock", "name": "two.example.com", "type": "MX"}, "two.example.com has no MX record in example.com on dock"},
		"a value and all":              {map[string]any{"server": "dock", "name": "two.example.com", "type": "A", "value": "10.0.0.4", "all": true}, "not both"},
		"a copy of the zone":           {map[string]any{"server": "rpi", "name": "two.example.com", "type": "A"}, "a copy that takes no changes: make the change on dock"},
		"no server":                    {map[string]any{"name": "two.example.com", "type": "A"}, "which server"},
	} {
		if msg := suite.CallErr(t, "record_delete", tc.args); !strings.Contains(msg, tc.want) {
			t.Errorf("%s\n  = %q\n  want it to say %q", name, msg, tc.want)
		}
	}
	sent := len(writes(p.dock))
	all := suite.Call(t, "record_delete", map[string]any{"server": "dock", "name": "two.example.com", "type": "A", "all": true})
	if len(acctest.Rows(t, all["deleted"], "deleted")) != 2 || len(writes(p.dock))-sent != 2 {
		t.Errorf("all of them = %v", all)
	}

	// a delete tool is not there without --enable-delete, writes or no
	if msg := p.session(t, Options{EnableWrite: true}).CallErr(t, "record_delete", map[string]any{"server": "dock", "name": "two.example.com", "type": "A", "all": true}); !strings.Contains(msg, "record_delete") {
		t.Errorf("record_delete with deletes not enabled = %q", msg)
	}
}
