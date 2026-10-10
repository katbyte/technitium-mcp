// Package technitium is a client for the Technitium DNS Server HTTP API, the
// one its own web console uses. It is written by hand from the server's
// APIDOCS.md, which is the only description of the API there is (see
// api-defs/README.md), and knows nothing of MCP: everything above this
// package works with the typed values here and never sees a raw answer.
//
// One Client talks to one server. Every call names its API path as a string
// literal handed to read, readWhole, readFile, write, writeWhole or upload,
// which is what lets the tests hold the package against the vendored document
// path by path.
package technitium

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/katbyte/go-kt/chttp"
)

// APIVersion is the server version the vendored API document describes, and
// so the one this client was written against. A server ahead of it may
// answer with fields the client does not read; one behind it may lack a call.
const APIVersion = "15.6.0"

// MinVersion is the oldest server this client can talk to: it sends its
// token in the Authorization header, which the API reads from 15.0.
const MinVersion = "15.0"

const (
	// maxResponseBytes is the most of an answer the client reads: a whole
	// zone of a few hundred thousand records fits, and a server sending more
	// is not answering the question asked
	maxResponseBytes = 64 << 20
	requestTimeout   = 120 * time.Second
	userAgent        = "technitium-mcp"
)

// The statuses the API answers with, in the body of an HTTP 200.
const (
	statusOK           = "ok"
	statusError        = "error"
	statusInvalidToken = "invalid-token"
	statusNeeds2FA     = "2fa-required"
)

// Client talks to one Technitium DNS server.
type Client struct {
	baseURL string
	token   string
	// node is another node of the server's cluster the calls are passed on
	// to, "" for the server itself (see OnNode)
	node string
	http *chttp.Client
}

// secretNames are the parameters and fields a trace must not show beside the
// ones it hides by their ending (password, secret, token): the passwords the
// API takes under shorter names, a one-time code, the picture a second
// factor's secret is shown as, a private key, and the transfer keys as the
// settings are sent them, each with its shared secret.
var secretNames = []string{"pass", "newPass", "totp", "primaryNodeTotp", "qrCodePngImage", "pemKskPrivateKey", "pemZskPrivateKey", "pemPrivateKey", "tsigKeys"}

// Option is something a client is made with beside its address and token.
type Option func(o *chttp.Options)

// WithLog has the client say what it sends and is sent to a logger, each
// exchange at trace and each request tried again at debug, with what is
// secret in them hidden. A client given none logs nothing.
func WithLog(log chttp.Logger) Option {
	return func(o *chttp.Options) { o.Log = log }
}

// New returns a client for the server whose web console answers at baseURL,
// http://nas:5380 say, authenticating with an API token (web console,
// Administration, Sessions, Create Token). The token is sent as a bearer
// header and never in an address.
func New(baseURL, token string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("a server url is required")
	}
	if token == "" {
		return nil, errors.New("an API token is required")
	}

	// a url that cannot be read is not repeated: what is in it is unknown,
	// a password included
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.New("the server url cannot be read as one: it must be the address the web console answers on, e.g. http://nas:5380")
	}
	if u.User != nil {
		return nil, errors.New("the server url must not contain credentials: the API takes a token, not a user and password")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("server url %q must be the address the web console answers on, e.g. http://nas:5380", chttp.RedactURL(baseURL))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("server url %q must not carry a query or a fragment", chttp.RedactURL(baseURL))
	}

	// the token goes in a header a trace hides by itself; a password the API
	// takes goes in a parameter named pass, which is said here. A write is
	// sent once, and a read again only for a connection that dropped or an
	// answer of a gateway's: a server that is not there is said at once
	// the server sends nothing of an answer until the call is done, and some calls take as long as there is work behind them - a server joining a cluster, a backup restored, a secondary told of a change while it is fetching one - so the wait for an answer to begin is the wait for the whole of it
	options := chttp.Options{Name: "Technitium", SecretNames: secretNames, HeaderWait: requestTimeout}
	for _, opt := range opts {
		opt(&options)
	}
	client := chttp.New(options)
	client.Timeout = requestTimeout
	// the API answers where it is asked, so a redirect means the server url
	// points at something in front of it: the console's own http-to-https
	// redirect, a proxy, a login page. Following one is worse than failing:
	// Go turns a POST into a GET on a 301, 302 or 303, dropping the form with
	// it, so a write would arrive as a read with no parameters
	client.CheckRedirect = chttp.RefuseRedirects("set the server url to the address the Technitium web console itself answers on")

	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, http: client}, nil
}

// BaseURL is the address the client was made with, without a trailing slash.
func (c *Client) BaseURL() string { return c.baseURL }

// OnNode is this client with its calls passed on to another node of the
// cluster the server is in, named by the node's domain: the server asked
// answers for that node. Only the calls the API passes on take it (see
// nodeCalls); any other fails without being sent, since it would be answered
// by the wrong server. "" is the server itself again.
func (c *Client) OnNode(domain string) *Client {
	on := *c
	on.node = domain

	return &on
}

// Node is the node the client's calls are passed on to, "" for the server
// itself.
func (c *Client) Node() string { return c.node }

// anonymous is this client with no token, for the two calls that take a
// name and a password in place of one.
func (c *Client) anonymous() *Client {
	anon := *c
	anon.token, anon.node = "", ""

	return &anon
}

// nodeCalls are the calls the API passes on to another node of a cluster
// when asked to, as the API document gives them; the tests hold the list
// against the document.
var nodeCalls = []string{
	"admin/cluster/primary/delete",
	"admin/cluster/primary/setOptions",
	"admin/cluster/secondary/leave",
	"admin/cluster/secondary/promote",
	"admin/cluster/secondary/resync",
	"admin/cluster/secondary/updatePrimary",
	"admin/cluster/state",
	"admin/cluster/updateIpAddress",
	"admin/groups/get",
	"admin/groups/list",
	"admin/permissions/list",
	"admin/permissions/set",
	"admin/sessions/delete",
	"admin/sessions/list",
	"admin/users/get",
	"admin/users/list",
	"allowed/export",
	"allowed/list",
	"apps/config/get",
	"apps/list",
	"apps/listStoreApps",
	"blocked/export",
	"blocked/list",
	"dashboard/stats/deleteAll",
	"dashboard/stats/get",
	"dashboard/stats/getTop",
	"dnsClient/healthCheck",
	"dnsClient/resolve",
	"logs/delete",
	"logs/deleteAll",
	"logs/download",
	"logs/export",
	"logs/list",
	"logs/query",
	"settings/backup",
	"settings/restore",
	"zones/catalogs/list",
	"zones/clone",
	"zones/convert",
	"zones/create",
	"zones/delete",
	"zones/disable",
	"zones/dnssec/properties/addPrivateKey",
	"zones/dnssec/properties/convertToNSEC",
	"zones/dnssec/properties/convertToNSEC3",
	"zones/dnssec/properties/deletePrivateKey",
	"zones/dnssec/properties/get",
	"zones/dnssec/properties/publishAllPrivateKeys",
	"zones/dnssec/properties/retireDnsKey",
	"zones/dnssec/properties/rolloverDnsKey",
	"zones/dnssec/properties/updateDnsKeyTtl",
	"zones/dnssec/properties/updateNSEC3Params",
	"zones/dnssec/properties/updatePrivateKey",
	"zones/dnssec/sign",
	"zones/dnssec/unsign",
	"zones/dnssec/viewDS",
	"zones/enable",
	"zones/export",
	"zones/import",
	"zones/list",
	"zones/options/get",
	"zones/options/set",
	"zones/permissions/get",
	"zones/permissions/set",
	"zones/records/add",
	"zones/records/delete",
	"zones/records/get",
	"zones/records/update",
	"zones/resync",
}

// file is a file sent with a call, as a browser posts one from a form.
type file struct {
	// name is the file's name, which the server reads nothing from
	name string
	data []byte
}

// APIError is the server refusing a call: the API answers every request it
// understands with HTTP 200 and says how it went in the body.
type APIError struct {
	// Path is the API call, zones/records/get say
	Path string
	// Status is what the server called the outcome: error, invalid-token or
	// 2fa-required
	Status string
	// Message is the server's own words
	Message string
	// Inner is the error under it, when the server gives one
	Inner string
	// Node is the server's name for itself, when it says
	Node string
}

func (e *APIError) Error() string {
	msg := e.Path + ": " + e.Message
	if e.Message == "" {
		msg = e.Path + ": the server answered " + e.Status
	}
	if e.Inner != "" && e.Inner != e.Message {
		msg += " (" + e.Inner + ")"
	}
	switch e.Status {
	case statusInvalidToken:
		msg += " (the API token was refused: it is wrong, its session was deleted, or the server is older than " + MinVersion + " and does not read the Authorization header)"
	case statusNeeds2FA:
		msg += " (the account asks for a one-time code, which an API token never needs: use a token made under Administration, Sessions)"
	default:
	}

	return msg
}

// IsInvalidToken reports whether err is the server refusing the token.
func IsInvalidToken(err error) bool {
	e, ok := errors.AsType[*APIError](err)

	return ok && e.Status == statusInvalidToken
}

// envelope is what every answer is wrapped in: how the call went, and the
// answer itself under "response" - or, for the handful of calls about the
// session, beside it.
type envelope struct {
	Status            string          `json:"status"`
	Server            string          `json:"server"`
	ErrorMessage      string          `json:"errorMessage"`
	InnerErrorMessage string          `json:"innerErrorMessage"`
	Response          json.RawMessage `json:"response"`
}

// read asks a call that changes nothing, as a GET, and decodes what is under
// "response" into out. A GET is sent again when the server does not answer,
// and when it answers that it was caught mid-change (see busy).
func (c *Client) read(ctx context.Context, path string, params url.Values, out any) error {
	var (
		response json.RawMessage
		err      error
	)
	for _, wait := range busyWaits {
		if wait > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%s: %w", path, ctx.Err())
			case <-time.After(wait):
			}
		}
		if _, response, err = c.call(ctx, http.MethodGet, path, params, nil); !busy(err) {
			break
		}
	}
	if err != nil {
		return err
	}

	return decode(path, response, out)
}

// busyWaits is how long a read waits before each try: the first at once, the
// rest a moment after the server said it was mid-change.
var busyWaits = []time.Duration{0, 50 * time.Millisecond, 150 * time.Millisecond, 400 * time.Millisecond, time.Second}

// busy reports whether a read failed because the server was changing what it
// was asked to list: a zone read while a record is being written to it is
// refused with the server's own "Operation is not valid due to the current
// state of the object", and read again a moment later is given whole.
func busy(err error) bool {
	apiErr, ok := errors.AsType[*APIError](err)

	return ok && strings.Contains(apiErr.Message, "Operation is not valid due to the current state of the object")
}

// readWhole is read for the calls that put their answer beside "status"
// rather than under "response".
func (c *Client) readWhole(ctx context.Context, path string, params url.Values, out any) error {
	whole, _, err := c.call(ctx, http.MethodGet, path, params, nil)
	if err != nil {
		return err
	}

	return decode(path, whole, out)
}

// write asks a call that changes the server, as a POST with its parameters
// in the body, and decodes what is under "response" into out. It is sent
// once: a write the server did not answer may still have been made.
func (c *Client) write(ctx context.Context, path string, params url.Values, out any) error {
	_, response, err := c.call(ctx, http.MethodPost, path, params, nil)
	if err != nil {
		return err
	}

	return decode(path, response, out)
}

// writeWhole is write for the calls that put their answer beside "status"
// rather than under "response".
func (c *Client) writeWhole(ctx context.Context, path string, params url.Values, out any) error {
	whole, _, err := c.call(ctx, http.MethodPost, path, params, nil)
	if err != nil {
		return err
	}

	return decode(path, whole, out)
}

// upload asks a call that takes a file: a POST with the file as a form's and
// the call's parameters in the address, which is where the API reads them
// from when the body is a file. It is sent once, as a write is.
func (c *Client) upload(ctx context.Context, path string, params url.Values, sent file, out any) error {
	if len(sent.data) == 0 {
		return fmt.Errorf("%s: the file to send is empty", path)
	}
	_, response, err := c.call(ctx, http.MethodPost, path, params, &sent)
	if err != nil {
		return err
	}

	return decode(path, response, out)
}

// decode reads an answer into out; a nil out wants none.
func decode(path string, raw json.RawMessage, out any) error {
	if out == nil {
		return nil
	}
	// a call that answers with a record answers with something: decoding
	// nothing would hand back a blank one that reads as real
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s: the server said ok and sent nothing where an answer belongs", path)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s: reading the answer: %w", path, err)
	}

	return nil
}

// readText asks a call that answers with a text file rather than the API's
// JSON - a list, one entry a line - and returns the text. A call the server
// refuses answers in JSON all the same, and is that error.
func (c *Client) readText(ctx context.Context, path string, params url.Values) (string, error) {
	raw, err := c.download(ctx, path, params)

	return string(raw), err
}

// readFile is readText for a file that is not text: a backup.
func (c *Client) readFile(ctx context.Context, path string, params url.Values) ([]byte, error) {
	return c.download(ctx, path, params)
}

// download asks a call that answers with a file and returns what is in it.
func (c *Client) download(ctx context.Context, path string, params url.Values) ([]byte, error) {
	raw, err := c.fetch(ctx, http.MethodGet, path, params, nil)
	if err != nil {
		return nil, err
	}
	var env envelope
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) && json.Unmarshal(raw, &env) == nil && env.Status != "" {
		if env.Status != statusOK {
			return nil, &APIError{Path: path, Status: env.Status, Message: env.ErrorMessage, Inner: env.InnerErrorMessage, Node: env.Server}
		}

		return nil, fmt.Errorf("%s: the server said ok and sent no file", path)
	}

	return raw, nil
}

// call makes one API call and returns the whole answer and the part under
// "response", once the server has said the call went ok.
func (c *Client) call(ctx context.Context, method, path string, params url.Values, sent *file) (whole, response json.RawMessage, err error) {
	raw, err := c.fetch(ctx, method, path, params, sent)
	if err != nil {
		return nil, nil, err
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, fmt.Errorf("%s: the answer is not the API's JSON (%w): %s", path, err, chttp.Preview(raw))
	}
	if env.Status != statusOK {
		return nil, nil, &APIError{Path: path, Status: env.Status, Message: env.ErrorMessage, Inner: env.InnerErrorMessage, Node: env.Server}
	}

	return raw, env.Response, nil
}

// fetch sends one API call and returns what the server answered, once it is
// known to be the API that answered: not another status, and not a web page.
func (c *Client) fetch(ctx context.Context, method, path string, params url.Values, sent *file) ([]byte, error) {
	if c.node != "" {
		if !slices.Contains(nodeCalls, path) {
			return nil, fmt.Errorf("%s: the API does not pass this call on to another node, so it cannot be asked of %s through this server: ask that node itself", path, c.node)
		}
		params = cloneValues(params)
		params.Set("node", c.node)
	}

	// a GET carries its parameters in the address and a POST in its body,
	// but for one sending a file, which has the body
	target := c.baseURL + "/api/" + path
	var body io.Reader = http.NoBody
	contentType := "application/x-www-form-urlencoded"
	switch {
	case sent != nil:
		form, formType, err := formFile(*sent)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		body, contentType = form, formType
		if len(params) > 0 {
			target += "?" + params.Encode()
		}
	case len(params) == 0:
	case method == http.MethodGet:
		target += "?" + params.Encode()
	default:
		body = strings.NewReader(params.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", contentType)
	}

	// the whole answer, asked for again if it stops part way; with no
	// response there was no answer at all, and the error says why
	resp, raw, err := c.http.Fetch(req, maxResponseBytes) //nolint:bodyclose // Fetch hands the response back with its body read and closed
	if resp == nil {
		return nil, fmt.Errorf("%s: %w", path, chttp.RedactError(err, secretNames...))
	}

	// the API answers 200 for every call it knows, so any other status is
	// not the API speaking: a path this server's version does not have, or
	// something in front of the server. It keeps its status whether or not
	// its body could be read
	if resp.StatusCode != http.StatusOK {
		statusErr := &chttp.StatusError{Method: method, Path: "/api/" + path, StatusCode: resp.StatusCode, Expected: []int{http.StatusOK}, Body: chttp.Preview(raw)}
		if resp.StatusCode == http.StatusNotFound {
			statusErr.Note = "this server has no such API call: it may be older than " + APIVersion + ", which this client was written against, or the server url may not be a Technitium web console"
		}

		return nil, statusErr
	}

	switch {
	case errors.Is(err, chttp.ErrTooLarge):
		return nil, fmt.Errorf("%s: the answer is over %d MiB, more than this client reads: ask for less at a time", path, maxResponseBytes>>20)
	case err != nil:
		return nil, fmt.Errorf("%s: %w", path, chttp.RedactError(err, secretNames...))
	case chttp.IsWebPage(resp.Header.Get("Content-Type"), raw):
		return nil, fmt.Errorf("%s: answered with a web page, not the Technitium API: check the server url", path)
	default:
		return raw, nil
	}
}

// yes is "true" as the API takes a boolean: a parameter left out is the
// API's own default, so only what is switched on is ever sent.
const yes = "true"

// cloneValues is a copy of a call's parameters that can be added to, which a
// call with none also has.
func cloneValues(params url.Values) url.Values {
	out := make(url.Values, len(params)+1)
	for name, values := range params {
		out[name] = slices.Clone(values)
	}

	return out
}

// isZip reports whether a file begins as a zip file does. The server keeps
// what it is sent as an app before it finds it cannot read it, and the
// wreck it leaves stops other servers from joining its cluster: what is no
// zip file is not sent.
func isZip(data []byte) bool {
	return bytes.HasPrefix(data, []byte("PK\x03\x04"))
}

// formFile is a file as the body of a form a browser would post it in, and
// the content type that says where its parts end.
func formFile(sent file) (body io.Reader, contentType string, err error) {
	var form bytes.Buffer
	w := multipart.NewWriter(&form)
	part, err := w.CreateFormFile("file", sent.name)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(sent.data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}

	return &form, w.FormDataContentType(), nil
}

// set puts the parameters that were given into a call's: a "" is one left to
// the server.
func set(params url.Values, given map[string]string) {
	for name, value := range given {
		if value != "" {
			params.Set(name, value)
		}
	}
}

// flag is a boolean as the API takes one, "" when it was not given and so is
// left as the server has it.
func flag(value *bool) string {
	if value == nil {
		return ""
	}
	if *value {
		return yes
	}

	return "false"
}
