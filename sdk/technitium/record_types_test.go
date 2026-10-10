package technitium_test

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// recordParams are a request's parameters without the ones every record call
// carries, as name=value in the order of their names.
func recordParams(asked technitiumtest.Request) string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(asked.Params)) {
		if !slices.Contains([]string{"domain", "type", "zone", "ttl", "disable", "comments", "expiryTtl"}, name) {
			out = append(out, name+"="+asked.Params.Get(name))
		}
	}

	return strings.Join(out, " ")
}

// Every type the server has a layout for is read from one line, added,
// changed and deleted with the parameters the API document gives the type,
// from the data as the server gives it back - which the canned server holds
// each request against.
func TestEveryRecordTypeIsWritten(t *testing.T) {
	t.Parallel()

	const hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	for recordType, tc := range map[string]struct {
		// value is the record on one line, read is its data as a server gives it back, and the rest are the parameters each call must carry
		value                   string
		read                    string
		added, changed, deleted string
	}{
		"A":     {"10.0.0.4", `{"ipAddress":"10.0.0.4"}`, "ipAddress=10.0.0.4", "ipAddress=10.0.0.4 newIpAddress=10.0.0.4", "ipAddress=10.0.0.4"},
		"NS":    {"ns1.example.com", `{"nameServer":"ns1.example.com"}`, "nameServer=ns1.example.com", "glue=10.0.0.2,10.0.0.3 nameServer=ns1.example.com newNameServer=ns1.example.com", "nameServer=ns1.example.com"},
		"CNAME": {"a.example.com", `{"cname":"a.example.com"}`, "cname=a.example.com", "cname=a.example.com", ""},
		"PTR":   {"x.example.com", `{"ptrName":"x.example.com"}`, "ptrName=x.example.com", "newPtrName=x.example.com ptrName=x.example.com", "ptrName=x.example.com"},
		"DNAME": {"other.example", `{"dname":"other.example"}`, "dname=other.example", "dname=other.example", ""},
		"MX":    {"10 mail.example.com", `{"preference":10,"exchange":"mail.example.com"}`, "exchange=mail.example.com preference=10", "exchange=mail.example.com newExchange=mail.example.com newPreference=10 preference=10", "exchange=mail.example.com preference=10"},
		"TXT":   {"v=spf1 -all", `{"text":"v=spf1 -all","splitText":false,"characterStrings":["v=spf1 -all"],"characterStringsBase64":["dj1zcGYxIC1hbGw="]}`, "text=v=spf1 -all", "characterStringsBase64=dj1zcGYxIC1hbGw= newCharacterStringsBase64=dj1zcGYxIC1hbGw=", "characterStringsBase64=dj1zcGYxIC1hbGw="},
		"RP":    {"admin@example.com info.example.com", `{"mailbox":"admin@example.com","txtDomain":"info.example.com"}`, "mailbox=admin@example.com txtDomain=info.example.com", "mailbox=admin@example.com newMailbox=admin@example.com newTxtDomain=info.example.com txtDomain=info.example.com", "mailbox=admin@example.com txtDomain=info.example.com"},
		"SRV":   {"1 2 5060 a.example.com", `{"priority":1,"weight":2,"port":5060,"target":"a.example.com"}`, "port=5060 priority=1 target=a.example.com weight=2", "newPort=5060 newPriority=1 newTarget=a.example.com newWeight=2 port=5060 priority=1 target=a.example.com weight=2", "port=5060 priority=1 target=a.example.com weight=2"},
		"NAPTR": {`100 10 "S" "SIP+D2U" "" _sip._udp.example.com`, `{"order":100,"preference":10,"flags":"S","services":"SIP+D2U","regexp":"","replacement":"_sip._udp.example.com"}`, "naptrFlags=S naptrOrder=100 naptrPreference=10 naptrRegexp= naptrReplacement=_sip._udp.example.com naptrServices=SIP+D2U", "naptrFlags=S naptrNewFlags=S naptrNewOrder=100 naptrNewPreference=10 naptrNewRegexp= naptrNewReplacement=_sip._udp.example.com naptrNewServices=SIP+D2U naptrOrder=100 naptrPreference=10 naptrRegexp= naptrReplacement=_sip._udp.example.com naptrServices=SIP+D2U", "naptrFlags=S naptrOrder=100 naptrPreference=10 naptrRegexp= naptrReplacement=_sip._udp.example.com naptrServices=SIP+D2U"},
		"DS":    {"12345 ECDSAP256SHA256 SHA256 " + hash, `{"keyTag":12345,"algorithm":"ECDSAP256SHA256","algorithmNumber":13,"digestType":"SHA256","digestTypeNumber":2,"digest":"` + hash + `"}`, "algorithm=ECDSAP256SHA256 digest=" + hash + " digestType=SHA256 keyTag=12345", "algorithm=ECDSAP256SHA256 digest=" + hash + " digestType=SHA256 keyTag=12345 newAlgorithm=ECDSAP256SHA256 newDigest=" + hash + " newDigestType=SHA256 newKeyTag=12345", "algorithm=ECDSAP256SHA256 digest=" + hash + " digestType=SHA256 keyTag=12345"},
		"SSHFP": {"Ed25519 SHA256 " + hash, `{"algorithm":"Ed25519","fingerprintType":"SHA256","fingerprint":"` + hash + `"}`, "sshfpAlgorithm=Ed25519 sshfpFingerprint=" + hash + " sshfpFingerprintType=SHA256", "newSshfpAlgorithm=Ed25519 newSshfpFingerprint=" + hash + " newSshfpFingerprintType=SHA256 sshfpAlgorithm=Ed25519 sshfpFingerprint=" + hash + " sshfpFingerprintType=SHA256", "sshfpAlgorithm=Ed25519 sshfpFingerprint=" + hash + " sshfpFingerprintType=SHA256"},
		"TLSA":  {"DANE-EE SPKI SHA2-256 " + hash, `{"certificateUsage":"DANE-EE","selector":"SPKI","matchingType":"SHA2-256","certificateAssociationData":"` + hash + `"}`, "tlsaCertificateAssociationData=" + hash + " tlsaCertificateUsage=DANE-EE tlsaMatchingType=SHA2-256 tlsaSelector=SPKI", "newTlsaCertificateAssociationData=" + hash + " newTlsaCertificateUsage=DANE-EE newTlsaMatchingType=SHA2-256 newTlsaSelector=SPKI tlsaCertificateAssociationData=" + hash + " tlsaCertificateUsage=DANE-EE tlsaMatchingType=SHA2-256 tlsaSelector=SPKI", "tlsaCertificateAssociationData=" + hash + " tlsaCertificateUsage=DANE-EE tlsaMatchingType=SHA2-256 tlsaSelector=SPKI"},
		"SVCB":  {"1 h.example.com alpn=h2,h3 port=53443", `{"svcPriority":1,"svcTargetName":"h.example.com","svcParams":{"alpn":"h2,h3","port":"53443"},"autoIpv4Hint":false,"autoIpv6Hint":false}`, "svcParams=alpn|h2,h3|port|53443 svcPriority=1 svcTargetName=h.example.com", "autoIpv4Hint=false autoIpv6Hint=false newSvcParams=alpn|h2,h3|port|53443 newSvcPriority=1 newSvcTargetName=h.example.com svcParams=alpn|h2,h3|port|53443 svcPriority=1 svcTargetName=h.example.com", "svcParams=alpn|h2,h3|port|53443 svcPriority=1 svcTargetName=h.example.com"},
		// the root as a target is read back as nothing and sent as a dot, and no parameters are sent as false
		"HTTPS": {"1 .", `{"svcPriority":1,"svcTargetName":"","svcParams":{},"autoIpv4Hint":true,"autoIpv6Hint":false}`, "svcParams=false svcPriority=1 svcTargetName=.", "autoIpv4Hint=true autoIpv6Hint=false newSvcParams=false newSvcPriority=1 newSvcTargetName=. svcParams=false svcPriority=1 svcTargetName=.", "svcParams=false svcPriority=1 svcTargetName=."},
		"URI":   {"10 1 https://example.com/", `{"priority":10,"weight":1,"uri":"https://example.com/"}`, "uri=https://example.com/ uriPriority=10 uriWeight=1", "newUri=https://example.com/ newUriPriority=10 newUriWeight=1 uri=https://example.com/ uriPriority=10 uriWeight=1", "uri=https://example.com/ uriPriority=10 uriWeight=1"},
		"CAA":   {"0 issue letsencrypt.org", `{"flags":0,"tag":"issue","value":"letsencrypt.org"}`, "flags=0 tag=issue value=letsencrypt.org", "flags=0 newFlags=0 newTag=issue newValue=letsencrypt.org tag=issue value=letsencrypt.org", "flags=0 tag=issue value=letsencrypt.org"},
		"ANAME": {"a.example.com", `{"aname":"a.example.com"}`, "aname=a.example.com", "aname=a.example.com newAName=a.example.com", "aname=a.example.com"},
		// what a forwarder is reached through is sent with every change: the server resets what an update leaves out
		"FWD": {"Tls 9.9.9.9", `{"protocol":"Tls","forwarder":"9.9.9.9","priority":5,"dnssecValidation":true,"proxyType":"NoProxy"}`, "forwarder=9.9.9.9 protocol=Tls", "dnssecValidation=true forwarder=9.9.9.9 forwarderPriority=5 newForwarder=9.9.9.9 newProtocol=Tls protocol=Tls proxyType=NoProxy", "forwarder=9.9.9.9 protocol=Tls"},
		// an app's name may hold spaces; which app and which part cannot be changed, only what it is told
		"APP": {"Split Horizon SplitHorizon.SimpleAddress", `{"appName":"Split Horizon","classPath":"SplitHorizon.SimpleAddress","data":"{\"public\":[\"203.0.113.4\"]}"}`, "appName=Split Horizon classPath=SplitHorizon.SimpleAddress", `appName=Split Horizon classPath=SplitHorizon.SimpleAddress recordData={"public":["203.0.113.4"]}`, ""},
		// a type the server has no layout for is its bytes in hex
		"LOC": {"01:02:03", `{"value":"01:02:03"}`, "rdata=01:02:03", "newRData=01:02:03 rdata=01:02:03", "rdata=01:02:03"},
	} {
		t.Run(recordType, func(t *testing.T) {
			t.Parallel()

			fake := technitiumtest.New(t)
			read := `{"name":"x.example.com","type":"` + recordType + `","ttl":300,"rData":` + tc.read + `,"glueRecords":["10.0.0.2","10.0.0.3"]}`
			fake.Answer("zones/records/add", `{"addedRecord":`+read+`}`)
			fake.Answer("zones/records/update", `{"updatedRecord":`+read+`}`)
			fake.Answer("zones/records/delete", `{}`)
			c := client(t, fake)

			data, err := technitium.ParseValue(recordType, tc.value)
			if err != nil {
				t.Fatal(err)
			}
			held, err := c.AddRecord(t.Context(), technitium.NewRecord{Zone: "example.com", Name: "x.example.com", Type: recordType, TTL: 300, Data: data})
			if err != nil {
				t.Fatal(err)
			}
			if got := recordParams(fake.Last("zones/records/add")); got != tc.added {
				t.Errorf("added with\n  %s\nwant\n  %s", got, tc.added)
			}
			// the value on one line is the same read from the server as parsed, which is how a tool knows a record it was asked for
			if got, want := held.Value(), (&technitium.Record{Type: recordType, Data: data}).Value(); got != want || got != tc.value {
				t.Errorf("Value() = %q from the server and %q as parsed, want %q", got, want, tc.value)
			}

			// changed with nothing changed but its TTL: every field is sent as it was, its options with it
			want := technitium.UpdateOf(held)
			want.TTL = 600
			if _, err := c.UpdateRecord(t.Context(), "example.com", held, want); err != nil {
				t.Fatal(err)
			}
			if got := recordParams(fake.Last("zones/records/update")); got != tc.changed {
				t.Errorf("changed with\n  %s\nwant\n  %s", got, tc.changed)
			}
			if err := c.DeleteRecord(t.Context(), "example.com", held); err != nil {
				t.Fatal(err)
			}
			if got := recordParams(fake.Last("zones/records/delete")); got != tc.deleted {
				t.Errorf("deleted with\n  %s\nwant\n  %s", got, tc.deleted)
			}
		})
	}
}

// What is an option of a record and no part of its value is sent when it is
// given, under the name the server reads it back as or the one it takes.
func TestRecordOptions(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("zones/records/add", `{"addedRecord":{"name":"x.example.com","type":"A","ttl":300,"rData":{"ipAddress":"10.0.0.4"}}}`)
	fake.Answer("zones/records/update", `{"updatedRecord":{"name":"x.example.com","type":"A","ttl":300,"rData":{"ipAddress":"10.0.0.4"}}}`)
	c := client(t, fake)

	for name, tc := range map[string]struct {
		rec  technitium.NewRecord
		want string
	}{
		"an address with its PTR, the zone for it and the hints":  {technitium.NewRecord{Name: "x.example.com", Type: "A", Data: technitium.RData{"ipAddress": "10.0.0.4"}, PTR: true, CreatePTRZone: true, UpdateSVCBHints: true, Overwrite: true}, "createPtrZone=true ipAddress=10.0.0.4 overwrite=true ptr=true updateSvcbHints=true"},
		"a name server with glue":                                 {technitium.NewRecord{Name: "sub.example.com", Type: "NS", Data: technitium.RData{"nameServer": "ns.sub.example.com", "glue": "10.0.0.9"}}, "glue=10.0.0.9 nameServer=ns.sub.example.com"},
		"text split at its line ends":                             {technitium.NewRecord{Name: "x.example.com", Type: "TXT", Data: technitium.RData{"text": "one\ntwo", "splitText": true}}, "splitText=true text=one\ntwo"},
		"text as its strings exactly":                             {technitium.NewRecord{Name: "x.example.com", Type: "TXT", Data: technitium.RData{"characterStringsBase64": []string{"b25l", "dHdv"}}}, "characterStringsBase64=b25l,dHdv"},
		"a forwarder through a proxy, by the names it is sent as": {technitium.NewRecord{Name: "x.example.com", Type: "FWD", Data: technitium.RData{"protocol": "Https", "forwarder": "https://dns.example/dns-query", "forwarderPriority": 2, "dnssecValidation": true, "proxyType": "Socks5", "proxyAddress": "10.0.0.9", "proxyPort": 1080, "proxyUsername": "u", "proxyPassword": "pr0xy-5ecre7"}}, "dnssecValidation=true forwarder=https://dns.example/dns-query forwarderPriority=2 protocol=Https proxyAddress=10.0.0.9 proxyPassword=pr0xy-5ecre7 proxyPort=1080 proxyType=Socks5 proxyUsername=u"},
		"an app with what it is told":                             {technitium.NewRecord{Name: "x.example.com", Type: "APP", Data: technitium.RData{"appName": "Split Horizon", "classPath": "SplitHorizon.SimpleAddress", "recordData": `{"private":["10.0.0.4"]}`}}, `appName=Split Horizon classPath=SplitHorizon.SimpleAddress recordData={"private":["10.0.0.4"]}`},
		"a service that keeps its own hints":                      {technitium.NewRecord{Name: "x.example.com", Type: "HTTPS", Data: technitium.RData{"svcPriority": 1, "svcTargetName": ".", "svcParams": "alpn=h2", "autoIpv4Hint": true, "autoIpv6Hint": true}}, "autoIpv4Hint=true autoIpv6Hint=true svcParams=alpn|h2 svcPriority=1 svcTargetName=."},
	} {
		if _, err := c.AddRecord(t.Context(), tc.rec); err != nil {
			t.Errorf("%s: %v", name, err)
		} else if got := recordParams(fake.Last("zones/records/add")); got != tc.want {
			t.Errorf("%s: added with\n  %s\nwant\n  %s", name, got, tc.want)
		}
	}
	if asked := fake.Last("zones/records/add"); asked.Method != http.MethodPost {
		t.Errorf("a record is added with %s", asked.Method)
	}

	// a forwarder that goes through a proxy is changed with the proxy sent again, password and all: the server gives none back, and resets what is left out
	forwarder := &technitium.Record{Name: "x.example.com", Type: "FWD", Data: technitium.RData{"protocol": "Udp", "forwarder": "192.0.2.53", "priority": 0, "dnssecValidation": false, "proxyType": "Socks5", "proxyAddress": "192.0.2.9", "proxyPort": 1080, "proxyUsername": "u"}}
	through := technitium.UpdateOf(forwarder)
	through.Data["proxyPassword"] = "pr0xy-5ecre7"
	if _, err := c.UpdateRecord(t.Context(), "", forwarder, through); err != nil {
		t.Fatal(err)
	}
	if got := recordParams(fake.Last("zones/records/update")); got != "dnssecValidation=false forwarder=192.0.2.53 forwarderPriority=0 newForwarder=192.0.2.53 newProtocol=Udp protocol=Udp proxyAddress=192.0.2.9 proxyPassword=pr0xy-5ecre7 proxyPort=1080 proxyType=Socks5 proxyUsername=u" {
		t.Errorf("a forwarder through a proxy was changed with %s", got)
	}
	// a TXT record known by its text alone is named by it, with how it was split
	plain := &technitium.Record{Name: "x.example.com", Type: "TXT", Data: technitium.RData{"text": "one\ntwo", "splitText": true}}
	if _, err := c.UpdateRecord(t.Context(), "", plain, technitium.UpdateOf(plain)); err != nil {
		t.Fatal(err)
	}
	if got := recordParams(fake.Last("zones/records/update")); got != "newSplitText=true newText=one\ntwo splitText=true text=one\ntwo" {
		t.Errorf("a TXT record known by its text was changed with %q", got)
	}

	// a TXT record's text changed: the record is named by its strings as they are, and given its new text
	held := &technitium.Record{Name: "x.example.com", Type: "TXT", TTL: 300, Data: technitium.RData{"text": "onetwo", "splitText": true, "characterStringsBase64": []any{"b25l", "dHdv"}}}
	want := technitium.UpdateOf(held)
	want.Data["text"] = "three"
	want.PTR, want.CreatePTRZone, want.UpdateSVCBHints = true, true, true
	if _, err := c.UpdateRecord(t.Context(), "", held, want); err != nil {
		t.Fatal(err)
	}
	if got := recordParams(fake.Last("zones/records/update")); got != "characterStringsBase64=b25l,dHdv createPtrZone=true newSplitText=true newText=three ptr=true updateSvcbHints=true" {
		t.Errorf("a TXT record's text was changed with %s", got)
	}
}

// A record's options are read by the names the API takes them under, and set
// under them, whatever the server calls each when it gives it back.
func TestRecordOptionsByName(t *testing.T) {
	t.Parallel()

	held := &technitium.Record{Type: "FWD", Data: technitium.RData{"protocol": "Udp", "forwarder": "192.0.2.53", "priority": 5, "dnssecValidation": true, "proxyType": "NoProxy"}}
	if got := held.Options(); len(got) != 3 || got["forwarderPriority"] != "5" || got["dnssecValidation"] != "true" || got["proxyType"] != "NoProxy" {
		t.Errorf("a forwarder's options = %v", got)
	}
	ns := &technitium.Record{Type: "NS", Data: technitium.RData{"nameServer": "ns.example.com"}, GlueRecords: []string{"192.0.2.2", "192.0.2.3"}}
	if got := ns.Options(); got["glue"] != "192.0.2.2,192.0.2.3" {
		t.Errorf("a name server's options = %v", got)
	}
	if got := (&technitium.Record{Type: "A", Data: technitium.RData{"ipAddress": "192.0.2.4"}}).Options(); len(got) != 0 || len(technitium.OptionNames("A")) != 0 {
		t.Errorf("an address has options: %v", got)
	}
	if got := technitium.OptionNames("APP"); !slices.Equal(got, []string{"recordData"}) {
		t.Errorf("an APP record's options = %v", got)
	}

	data := technitium.UpdateOf(held).Data
	if err := technitium.SetOption(data, "FWD", "forwarderPriority", "7"); err != nil || data["priority"] != "7" || data["forwarderPriority"] != nil {
		t.Errorf("SetOption = %v, leaving %v", err, data)
	}
	for want, call := range map[string]error{
		"a FWD record has no option named glue: it has forwarderPriority": technitium.SetOption(data, "FWD", "glue", "x"),
		"a MX record has no options beside its value":                     technitium.SetOption(data, "MX", "glue", "x"),
	} {
		if call == nil || !strings.Contains(call.Error(), want) {
			t.Errorf("SetOption = %v, want %q in it", call, want)
		}
	}
}
