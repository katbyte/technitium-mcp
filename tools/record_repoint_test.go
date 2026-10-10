package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/go-kt/mcp/acctest"
)

// repointPair is two servers for a move of address: dock holds two zones as
// its own, a third as a copy, and the reverse zone.
func repointPair(t *testing.T) *pair {
	t.Helper()

	p := writePair(t)
	p.dock.Answer("zones/list", `{"zones":[{"name":"example.com","type":"Primary","soaSerial":7},{"name":"example.net","type":"Primary","soaSerial":3},{"name":"copied.example","type":"Secondary","soaSerial":3},{"name":"0.0.10.in-addr.arpa","type":"Primary","soaSerial":2}]}`)
	p.dock.AnswerWhen("zones/records/get", "domain", "example.com", `{"zone":{"name":"example.com"},"records":[
		{"name":"emby.example.com","type":"A","ttl":300,"comments":"the emby vm","rData":{"ipAddress":"10.0.0.4"}},
		{"name":"m.example.com","type":"CNAME","ttl":3600,"rData":{"cname":"emby.example.com"}},
		{"name":"mac.example.com","type":"A","ttl":3600,"rData":{"ipAddress":"10.0.0.9"}},
		{"name":"six.example.com","type":"AAAA","ttl":3600,"rData":{"ipAddress":"fd00::4"}}
	]}`)
	p.dock.AnswerWhen("zones/records/get", "domain", "example.net", `{"zone":{"name":"example.net"},"records":[
		{"name":"jf.example.net","type":"A","ttl":60,"disabled":true,"rData":{"ipAddress":"10.0.0.4"}},
		{"name":"both.example.net","type":"A","ttl":60,"rData":{"ipAddress":"10.0.0.4"}},
		{"name":"both.example.net","type":"A","ttl":60,"rData":{"ipAddress":"10.0.0.7"}}
	]}`)
	p.dock.AnswerWhen("zones/records/get", "domain", "copied.example", `{"zone":{"name":"copied.example"},"records":[{"name":"x.copied.example","type":"A","ttl":60,"rData":{"ipAddress":"10.0.0.4"}}]}`)
	p.dock.AnswerWhen("zones/records/get", "domain", "0.0.10.in-addr.arpa", `{"zone":{"name":"0.0.10.in-addr.arpa"},"records":[]}`)
	at(p.dock, "4.0.0.10.in-addr.arpa", embyPTR, strings.ReplaceAll(embyPTR, "emby.example.com", "jf.example.net"))
	at(p.dock, "7.0.0.10.in-addr.arpa")

	return p
}

// A move of address is every record holding the old one given the new, each
// keeping what it had, and the PTRs with them: listed whole by a dry run, and
// then made.
func TestRecordRepoint(t *testing.T) {
	t.Parallel()

	p := repointPair(t)
	suite := p.session(t, everything)

	want := []string{
		"moved A emby.example.com from 10.0.0.4 to 10.0.0.7",
		"moved A jf.example.net from 10.0.0.4 to 10.0.0.7",
		// the name that holds both loses the old one
		"removed A 10.0.0.4 at both.example.net, which already holds 10.0.0.7",
		"added PTR emby.example.com at 7.0.0.10.in-addr.arpa",
		"removed PTR emby.example.com at 4.0.0.10.in-addr.arpa",
		"added PTR jf.example.net at 7.0.0.10.in-addr.arpa",
		"removed PTR jf.example.net at 4.0.0.10.in-addr.arpa",
	}
	dry := suite.Call(t, "record_repoint", map[string]any{"server": "dock", "from": "10.0.0.4", "to": "10.0.0.7", "dry_run": true})
	wouldHave := make([]string, 0, len(want))
	for _, w := range want {
		wouldHave = append(wouldHave, "would have "+w)
	}
	if got := acctest.Strs(t, dry["changes"], "changes"); !slices.Equal(got, wouldHave) {
		t.Errorf("a dry run =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(wouldHave, "\n  "))
	}
	if sent := writes(p.dock); len(sent) != 0 || !strings.Contains(acctest.Str(dry["note"]), "a dry run: nothing was changed") {
		t.Errorf("a dry run sent %v and said %q", sent, dry["note"])
	}

	out := suite.Call(t, "record_repoint", map[string]any{"server": "dock", "from": "10.0.0.4", "to": "10.0.0.7"})
	if got := acctest.Strs(t, out["changes"], "changes"); !slices.Equal(got, want) {
		t.Errorf("changes =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	moved := acctest.Rows(t, out["repointed"], "repointed")
	if len(moved) != 2 || moved[0]["name"] != "emby.example.com" || moved[0]["comment"] != "the emby vm" || acctest.Num(t, moved[0]["ttl"], "ttl") != 300 || moved[1]["zone"] != "example.net" {
		t.Errorf("repointed = %v", moved)
	}
	// each record kept what it had: its TTL, its comment, that it was disabled
	updates := p.dock.Requests("zones/records/update")
	if len(updates) != 2 || updates[0].Params.Get("newIpAddress") != "10.0.0.7" || updates[0].Params.Get("comments") != "the emby vm" || updates[0].Params.Get("ttl") != "300" || updates[1].Params.Get("disable") != "true" || updates[1].Params.Get("ttl") != "60" {
		t.Errorf("the records were moved with %v", updates)
	}
	// the copy's record is said, not touched; what reached the address by a CNAME, or holds another, is neither
	skipped := acctest.Rows(t, out["skipped"], "skipped")
	if len(skipped) != 1 || skipped[0]["name"] != "x.copied.example" || !strings.Contains(acctest.Str(skipped[0]["why"]), "dock holds copied.example as a copy") {
		t.Errorf("skipped = %v", skipped)
	}
	if out["already_at"] != nil || out["note"] != nil {
		t.Errorf("already_at = %v, note = %v: the one name at the new address is one that was moved", out["already_at"], out["note"])
	}
}

// A move onto an address another host has is refused unless that is meant;
// what cannot be a move is refused before anything is read.
func TestRecordRepointRefusals(t *testing.T) {
	t.Parallel()

	p := repointPair(t)
	suite := p.session(t, everything)

	if msg := suite.CallErr(t, "record_repoint", map[string]any{"server": "dock", "from": "10.0.0.4", "to": "10.0.0.9"}); !strings.Contains(msg, "10.0.0.9 is already held by mac.example.com: moving 3 records onto it") || !strings.Contains(msg, "share") {
		t.Errorf("onto another host's address = %q", msg)
	}
	if sent := writes(p.dock); len(sent) != 0 {
		t.Errorf("the refusal sent %v", sent)
	}
	shared := suite.Call(t, "record_repoint", map[string]any{"server": "dock", "from": "10.0.0.4", "to": "10.0.0.9", "share": true, "no_ptr": true, "dry_run": true})
	if got := acctest.Strs(t, shared["already_at"], "already_at"); !slices.Equal(got, []string{"mac.example.com"}) || len(acctest.Strs(t, shared["changes"], "changes")) != 3 {
		t.Errorf("shared on purpose, PTRs left = %v", shared)
	}

	// only the zones asked for
	if narrowed := suite.Call(t, "record_repoint", map[string]any{"server": "dock", "from": "10.0.0.4", "to": "10.0.0.7", "zone": "example.com", "no_ptr": true, "dry_run": true}); len(acctest.Strs(t, narrowed["changes"], "changes")) != 1 || narrowed["skipped"] != nil {
		t.Errorf("one zone alone = %v", narrowed)
	}
	// nothing at the address
	if none := suite.Call(t, "record_repoint", map[string]any{"server": "dock", "from": "10.0.0.55", "to": "10.0.0.56"}); !strings.Contains(acctest.Str(none["note"]), "no record on dock holds 10.0.0.55") || len(acctest.Strs(t, none["changes"], "changes")) != 0 {
		t.Errorf("nothing to move = %v", none)
	}

	for name, tc := range map[string]struct {
		args map[string]any
		want string
	}{
		"not addresses":        {map[string]any{"server": "dock", "from": "emby.example.com", "to": "10.0.0.7"}, "from and to are each an IPv4 or IPv6 address"},
		"the same address":     {map[string]any{"server": "dock", "from": "10.0.0.4", "to": "10.0.0.4"}, "there is nothing to move"},
		"two kinds":            {map[string]any{"server": "dock", "from": "10.0.0.4", "to": "fd00::7"}, "are not the same kind of address"},
		"no server":            {map[string]any{"from": "10.0.0.4", "to": "10.0.0.7"}, "which server"},
		"a server that is not": {map[string]any{"server": "pi", "from": "10.0.0.4", "to": "10.0.0.7"}, "dock, rpi"},
	} {
		if msg := suite.CallErr(t, "record_repoint", tc.args); !strings.Contains(msg, tc.want) {
			t.Errorf("%s = %q, want it to say %q", name, msg, tc.want)
		}
	}
	if sent := writes(p.dock); len(sent) != 0 {
		t.Errorf("the refusals and dry runs sent %v", sent)
	}
}
