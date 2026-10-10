// Package technitiumtest is a canned Technitium server for tests: it answers
// the API calls a test tells it to and records what it was asked. Every
// request it gets is also held against the vendored API document (sdk/apidoc)
// - the call must be one the document has, at its current path, and every
// parameter sent must be one the document gives that call - so a test that
// only meant to check an answer also proves the request was one the real
// server takes.
//
// The live suites are what prove the canned answers match a real server.
package technitiumtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/apidoc"
)

// Token is the API token the canned server expects.
const Token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Request is one call the canned server was sent.
type Request struct {
	Method string
	// Path is the call's path under /api/: zones/list
	Path   string
	Params url.Values
}

// Server is a canned Technitium server.
type Server struct {
	// URL is the address to give a client
	URL string

	tb  testing.TB
	doc *apidoc.Doc

	mu      sync.Mutex
	answers map[string]string
	then    map[string]func(Request)
	seen    []Request
}

// vendored reads the API document once for every canned server in a test
// binary.
var vendored = sync.OnceValues(apidoc.Vendored)

// New starts a canned server that is closed when the test ends. It answers
// nothing until told to (Answer, Fail): a call with no answer fails the test.
func New(tb testing.TB) *Server {
	tb.Helper()

	doc, err := vendored()
	if err != nil {
		tb.Fatalf("reading the vendored API document: %v", err)
	}
	s := &Server{tb: tb, doc: doc, answers: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	tb.Cleanup(srv.Close)
	s.URL = srv.URL

	return s
}

// Answer makes a call answer ok with the JSON given under "response".
func (s *Server) Answer(path, response string) {
	s.AnswerWhole(path, `{"response":`+response+`,"server":"canned","status":"ok"}`)
}

// AnswerWhole makes a call answer with exactly the body given, for the calls
// that put their answer beside "status" and for answers that are not the
// API's at all.
func (s *Server) AnswerWhole(path, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.answers[path] = body
}

// AnswerText makes a call answer with a text file, as the calls that export
// a list do: one entry a line.
func (s *Server) AnswerText(path, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.answers[path] = textAnswer + text
}

// textAnswer marks an answer that is a text file rather than the API's JSON.
const textAnswer = "\x00text\x00"

// AnswerWhen makes a call answer ok with the JSON given under "response"
// when it is sent a parameter with a value: one zone's records for that
// zone, where Answer is the same records whatever is asked for. A call that
// matches no such answer falls back to the path's own.
func (s *Server) AnswerWhen(path, param, value, response string) {
	s.AnswerWhole(path+"\x00"+param+"="+value, `{"response":`+response+`,"server":"canned","status":"ok"}`)
}

// FailWhen is Fail for a call sent a parameter with a value.
func (s *Server) FailWhen(path, param, value, status, message string) {
	s.Fail(path+"\x00"+param+"="+value, status, message)
}

// Fail makes a call answer as the server does when it refuses one: HTTP 200,
// with the status and the message in the body.
func (s *Server) Fail(path, status, message string) {
	body, err := json.Marshal(map[string]string{"server": "canned", "status": status, "errorMessage": message})
	if err != nil {
		s.tb.Fatal(err)
	}
	s.AnswerWhole(path, string(body))
}

// Then has the canned server do something when a call is made, before it
// answers: change what another call answers from then on, which is how a
// write comes to be read back. A nil do is nothing more to be done.
func (s *Server) Then(path string, do func(Request)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.then == nil {
		s.then = map[string]func(Request){}
	}
	s.then[path] = do
}

// Requests are the calls made to a path, in order.
func (s *Server) Requests(path string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Request
	for _, r := range s.seen {
		if r.Path == path {
			out = append(out, r)
		}
	}

	return out
}

// Last is the most recent call made to a path; it fails the test when there
// was none.
func (s *Server) Last(path string) Request {
	s.tb.Helper()

	made := s.Requests(path)
	if len(made) == 0 {
		s.tb.Fatalf("%s was never called", path)
	}

	return made[len(made)-1]
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	path, underAPI := strings.CutPrefix(r.URL.Path, "/api/")
	if !underAPI {
		s.tb.Errorf("the client asked for %s, which is not under /api/", r.URL.Path)
		http.NotFound(w, r)

		return
	}

	params, problem := s.read(r)
	if problem != "" {
		s.tb.Errorf("%s %s: %s", r.Method, path, problem)
	}
	s.check(r, path, params)

	s.mu.Lock()
	do := s.then[path]
	s.mu.Unlock()
	if do != nil {
		do(Request{Method: r.Method, Path: path, Params: params})
	}

	s.mu.Lock()
	s.seen = append(s.seen, Request{Method: r.Method, Path: path, Params: params})
	body, answered := s.answers[path]
	// an answer for what this call was sent comes before the path's own;
	// when two parameters each have one, the first by name does, so a test
	// gets the same answer every run
	names := make([]string, 0, len(params))
	for param := range params {
		names = append(names, param)
	}
	slices.Sort(names)
	for _, param := range slices.Backward(names) {
		for _, value := range params[param] {
			if specific, ok := s.answers[path+"\x00"+param+"="+value]; ok {
				body, answered = specific, true
			}
		}
	}
	s.mu.Unlock()

	if !answered {
		s.tb.Errorf("the client called %s, which this test gave the canned server no answer for", path)
		http.NotFound(w, r)

		return
	}
	if text, isText := strings.CutPrefix(body, textAnswer); isText {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", "attachment")
		_, _ = w.Write([]byte(text))

		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(body))
}

// read takes a request's parameters from where its method carries them: a
// GET's from the address, a POST's from a form in the body.
func (*Server) read(r *http.Request) (params url.Values, problem string) {
	switch r.Method {
	case http.MethodGet:
		return r.URL.Query(), ""
	case http.MethodPost:
		if r.URL.RawQuery != "" {
			problem = "a POST carries its parameters in the body, and this one has some in the address"
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			problem = fmt.Sprintf("a POST's parameters are a form, and its Content-Type is %q", ct)
		}
		if err := r.ParseForm(); err != nil {
			return nil, "its form cannot be read: " + err.Error()
		}

		return r.PostForm, problem
	default:
		return nil, "the API is asked with GET or POST"
	}
}

// check holds a request against the API document and the rules a client
// keeps.
func (s *Server) check(r *http.Request, path string, params url.Values) {
	if got := r.Header.Get("Authorization"); got != "Bearer "+Token {
		s.tb.Errorf("%s: the token is sent as a bearer header, and Authorization was %q", path, got)
	}
	if params.Has("token") {
		s.tb.Errorf("%s: the token was sent as a parameter, which puts it in addresses and logs", path)
	}

	call := s.doc.Call(path)
	if call == nil {
		if now := s.doc.ReplacedBy(path); now != nil {
			s.tb.Errorf("%s is an obsolete path: the call is %s now", path, now.Path)

			return
		}
		s.tb.Errorf("the client called %s, which the API document (%s) does not have", path, s.doc.File)

		return
	}
	for name := range params {
		if !call.Takes(name) {
			s.tb.Errorf("%s was sent the parameter %q, which the API document does not give it (it takes %s)", path, name, strings.Join(call.Params, ", "))
		}
	}
}
