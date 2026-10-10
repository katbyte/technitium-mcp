package technitium_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/katbyte/go-kt/chttp"
	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// client is a client for a canned server.
func client(t *testing.T, fake *technitiumtest.Server) *technitium.Client {
	t.Helper()

	c, err := technitium.New(fake.URL, technitiumtest.Token)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

// raw is a client for a server that is no Technitium at all: something in
// front of one, or in its place.
func raw(t *testing.T, h http.HandlerFunc) *technitium.Client {
	t.Helper()

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := technitium.New(srv.URL, technitiumtest.Token)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

// A client is made for an address a web console answers on and a token, and
// says what is wrong with anything else before a request is ever sent.
func TestNewRefusesWhatCannotWork(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct{ url, token, want string }{
		"no url":              {"", "t", "a server url is required"},
		"no token":            {"http://nas:5380", "", "an API token is required"},
		"no scheme":           {"nas:5380", "t", "must be the address the web console answers on"},
		"not http":            {"ftp://nas", "t", "must be the address the web console answers on"},
		"credentials":         {"http://admin:hunter2@nas:5380", "t", "must not contain credentials"},
		"a query":             {"http://nas:5380/?token=abc", "t", "must not carry a query"},
		"a password in a bad": {"://admin:hunter2@nas", "t", "must be the address"},
	} {
		_, err := technitium.New(tc.url, tc.token)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: New(%q) = %v, want an error saying %q", name, tc.url, err, tc.want)
		}
		if err != nil && (strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "abc")) {
			t.Errorf("%s: the error repeats a credential: %v", name, err)
		}
	}

	c, err := technitium.New("http://nas:5380/", "t")
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != "http://nas:5380" {
		t.Errorf("BaseURL = %q, want the trailing slash gone", c.BaseURL())
	}
}

// The API answers HTTP 200 whatever happened and says how the call went in
// the body, so a refusal is an error made from the body: the server's own
// words, the call, and for a refused token what that usually means.
func TestARefusalIsAnError(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	c := client(t, fake)

	fake.Fail("zones/list", "error", "No such zone was found: nope.example")
	_, err := c.Zones(t.Context(), technitium.ZoneFilter{})
	apiErr, ok := errors.AsType[*technitium.APIError](err)
	if !ok {
		t.Fatalf("Zones = %v, want an *APIError", err)
	}
	if apiErr.Path != "zones/list" || apiErr.Status != "error" || apiErr.Node != "canned" || err.Error() != "zones/list: No such zone was found: nope.example" {
		t.Errorf("the error = %+v (%q)", apiErr, err)
	}
	if technitium.IsInvalidToken(err) {
		t.Error("an ordinary refusal reads as a refused token")
	}

	fake.Fail("zones/list", "invalid-token", "Invalid token or session expired.")
	_, err = c.Zones(t.Context(), technitium.ZoneFilter{})
	if !technitium.IsInvalidToken(err) || !strings.Contains(err.Error(), "the API token was refused") || !strings.Contains(err.Error(), technitium.MinVersion) {
		t.Errorf("a refused token = %v, want it said, with the oldest server that reads the header", err)
	}
	if strings.Contains(err.Error(), technitiumtest.Token) {
		t.Errorf("the error repeats the token: %v", err)
	}

	fake.Fail("zones/list", "2fa-required", "")
	if _, err = c.Zones(t.Context(), technitium.ZoneFilter{}); err == nil || !strings.Contains(err.Error(), "the server answered 2fa-required") {
		t.Errorf("a refusal with no message = %v, want the status said", err)
	}
}

// An answer that is not the API's is said to be one, rather than decoded
// into a blank record: a web page from something in front of the server, a
// status the API never gives, an ok with nothing in it.
func TestAnswersThatAreNotTheAPI(t *testing.T) {
	t.Parallel()

	page := raw(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>Sign in</body></html>"))
	})
	if _, err := page.Zones(t.Context(), technitium.ZoneFilter{}); err == nil || !strings.Contains(err.Error(), "answered with a web page") {
		t.Errorf("a web page = %v", err)
	}

	missing := raw(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	_, err := missing.Zones(t.Context(), technitium.ZoneFilter{})
	if !chttp.IsNotFound(err) || !strings.Contains(err.Error(), "GET /api/zones/list: HTTP 404") || !strings.Contains(err.Error(), "no such API call") {
		t.Errorf("a 404 = %v, want the status and what it means", err)
	}

	junk := raw(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("pong")) })
	if _, err := junk.Zones(t.Context(), technitium.ZoneFilter{}); err == nil || !strings.Contains(err.Error(), "not the API's JSON") || !strings.Contains(err.Error(), "pong") {
		t.Errorf("an answer that is no JSON = %v", err)
	}

	fake := technitiumtest.New(t)
	fake.AnswerWhole("zones/list", `{"status":"ok"}`)
	if _, err := client(t, fake).Zones(t.Context(), technitium.ZoneFilter{}); err == nil || !strings.Contains(err.Error(), "sent nothing where an answer belongs") {
		t.Errorf("an ok with no answer = %v", err)
	}
}

// A zone read while a record is being written to it is refused by the server
// with an error of its own that passes: the read is made again, and a server
// that goes on refusing is an error in its words.
func TestAReadCaughtMidChangeIsMadeAgain(t *testing.T) {
	t.Parallel()

	const midChange = "Operation is not valid due to the current state of the object."
	fake := technitiumtest.New(t)
	fake.Fail("zones/records/get", "error", midChange)
	fake.Then("zones/records/get", func(technitiumtest.Request) {
		if len(fake.Requests("zones/records/get")) == 2 {
			fake.Answer("zones/records/get", `{"zone":{"name":"example.com"},"records":[{"name":"a.example.com","type":"A","ttl":60,"rData":{"ipAddress":"10.0.0.4"}}]}`)
		}
	})
	c := client(t, fake)

	got, err := c.ZoneRecords(t.Context(), "example.com")
	if err != nil || len(got.Records) != 1 {
		t.Fatalf("a zone read mid-change = %+v, %v, want it read again and given whole", got, err)
	}
	if n := len(fake.Requests("zones/records/get")); n != 3 {
		t.Errorf("the zone was asked for %d times, want until it was given", n)
	}

	// a refusal of any other kind is not asked again
	fake.Fail("zones/list", "error", "Access was denied.")
	if _, err := c.Zones(t.Context(), technitium.ZoneFilter{}); err == nil || len(fake.Requests("zones/list")) != 1 {
		t.Errorf("another refusal = %v, asked %d times", err, len(fake.Requests("zones/list")))
	}

	// a server that never stops refusing is an error, in its words
	stuck := technitiumtest.New(t)
	stuck.Fail("zones/records/get", "error", midChange)
	if _, err := client(t, stuck).ZoneRecords(t.Context(), "example.com"); err == nil || !strings.Contains(err.Error(), midChange) || len(stuck.Requests("zones/records/get")) != 5 {
		t.Errorf("a server that goes on refusing = %v, asked %d times", err, len(stuck.Requests("zones/records/get")))
	}
}

// A redirect is refused, not followed: Go turns a POST into a GET on the way,
// so a write would arrive as a read with no parameters and report success.
func TestARedirectIsRefused(t *testing.T) {
	t.Parallel()

	var followed atomic.Bool
	c := raw(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed.Store(true)

			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})

	err := c.DeleteZone(t.Context(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "was redirected to") || !strings.Contains(err.Error(), "the address the Technitium web console itself answers on") {
		t.Errorf("a redirected write = %v", err)
	}
	if followed.Load() {
		t.Error("the redirect was followed")
	}
}

// A write the server fails to answer is not sent again: it may have been
// made.
func TestAWriteIsSentOnce(t *testing.T) {
	t.Parallel()

	var sent atomic.Int32
	c := raw(t, func(w http.ResponseWriter, _ *http.Request) {
		sent.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	err := c.DeleteZone(t.Context(), "example.com")
	if chttp.StatusCode(err) != http.StatusInternalServerError {
		t.Errorf("DeleteZone = %v, want the 500", err)
	}
	if n := sent.Load(); n != 1 {
		t.Errorf("the write was sent %d times", n)
	}
}

// A server that is not there is an error naming the call, never the token.
func TestAServerThatIsNotThere(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	c, err := technitium.New(srv.URL, technitiumtest.Token)
	if err != nil {
		t.Fatal(err)
	}

	// a write, so the failure is not waited out and tried again
	err = c.DeleteZone(t.Context(), "example.com")
	if err == nil || !strings.HasPrefix(err.Error(), "zones/delete: ") {
		t.Errorf("DeleteZone = %v, want an error naming the call", err)
	}
	if err != nil && strings.Contains(err.Error(), technitiumtest.Token) {
		t.Errorf("the error repeats the token: %v", err)
	}
}

// traced keeps what a client says it sent and was sent.
type traced struct {
	mu   sync.Mutex
	said strings.Builder
}

func (l *traced) Debugf(format string, args ...any) { l.Tracef(format, args...) }

func (l *traced) Tracef(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.said, format+"\n", args...)
}

// A client given a logger says what it sent and was sent, with nothing
// secret in it: not its token, not a password it posts, and not a key or a
// password the server's settings hold. Given none, it says nothing.
func TestTheClientsTrafficIsLoggedWithoutItsSecrets(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("settings/get", `{"version":"15.6","dnsServerDomain":"ns1.example","webServiceTlsCertificatePassword":"5ecre7-cert","dnsTlsCertificatePassword":"5ecre7-dns","proxy":{"type":"Socks5","address":"192.0.2.9","port":1080,"username":"u","password":"5ecre7-proxy"},"tsigKeys":[{"keyName":"home","sharedSecret":"5ecre7-tsig=","algorithmName":"hmac-sha256"}]}`)
	fake.Answer("admin/cluster/initJoin", `{"clusterInitialized":true,"clusterDomain":"cluster.example","clusterNodes":[]}`)
	log := &traced{}
	c, err := technitium.New(fake.URL, technitiumtest.Token, technitium.WithLog(log))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Settings(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.JoinCluster(t.Context(), technitium.ClusterJoin{Addresses: []string{"192.0.2.3"}, PrimaryURL: "https://ns1.cluster.example:53443", PrimaryAddress: "192.0.2.2", Username: "admin", Password: "5ecre7-join"}); err != nil {
		t.Fatal(err)
	}

	said := log.said.String()
	for _, secret := range []string{technitiumtest.Token, "5ecre7"} {
		if strings.Contains(said, secret) {
			t.Errorf("%q is in what the client logged:\n%s", secret, said)
		}
	}
	// what is no secret is there: the calls, a key by its name, the user that joins
	for _, shown := range []string{"/api/settings/get", "/api/admin/cluster/initJoin", "hmac-sha256", "ns1.example", "primaryNodeUsername=admin"} {
		if !strings.Contains(said, shown) {
			t.Errorf("%q is not in what the client logged, and is no secret:\n%s", shown, said)
		}
	}
}
