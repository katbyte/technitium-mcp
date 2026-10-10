package tools

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/katbyte/technitium-mcp/lib/servers"
)

// serverArg is the argument every read takes to say which server it is
// about.
type serverArg struct {
	Server string `json:"server,omitempty" jsonschema:"which configured server to ask: a name server_info lists, or all (the default) to ask every one and set the answers side by side"`
}

// answer is what one server said to a question asked of several.
type answer[T any] struct {
	Server *servers.Server
	Value  T
	Err    error
}

// ask puts one question to each of the servers at once and returns every
// answer, in the servers' own order. One server failing is its own answer's
// error and takes nothing from the others: two servers are asked so that one
// can be seen when the other is down or wrong.
func ask[T any](ctx context.Context, picked []*servers.Server, question func(ctx context.Context, srv *servers.Server) (T, error)) []answer[T] {
	out := make([]answer[T], len(picked))

	var wg sync.WaitGroup
	for i, srv := range picked {
		wg.Go(func() {
			value, err := question(ctx, srv)
			out[i] = answer[T]{Server: srv, Value: value, Err: err}
		})
	}
	wg.Wait()

	return out
}

// serverFailure is a server that could not answer, as a tool says so beside
// the answers of the ones that could.
type serverFailure struct {
	Server string `json:"server"`
	Error  string `json:"error"`
}

// failures are the answers that failed, and an error when every one did: a
// call that learned nothing from any server has failed, where one that heard
// from some answers with what it has and says who is missing.
func failures[T any](answers []answer[T]) ([]serverFailure, error) {
	var failed []serverFailure
	var errs []error
	for _, a := range answers {
		if a.Err == nil {
			continue
		}
		failed = append(failed, serverFailure{Server: a.Server.Name, Error: a.Err.Error()})
		errs = append(errs, fmt.Errorf("%s: %w", a.Server.Name, a.Err))
	}
	if len(failed) == len(answers) {
		return nil, errors.Join(errs...)
	}

	return failed, nil
}

// pattern is a filter on a name or a value as the tools take one: with a *
// (any run of characters) or a ? (any one) it must match the whole text,
// and without either it matches anywhere in it. Case is ignored, as DNS
// ignores it.
type pattern struct {
	text string
	re   *regexp.Regexp
}

// newPattern reads a filter; "" matches everything.
func newPattern(text string) pattern {
	text = strings.ToLower(strings.TrimSpace(text))
	if !strings.ContainsAny(text, "*?") {
		return pattern{text: text}
	}
	quoted := regexp.QuoteMeta(text)
	quoted = strings.ReplaceAll(quoted, `\*`, ".*")
	quoted = strings.ReplaceAll(quoted, `\?`, ".")

	return pattern{text: text, re: regexp.MustCompile("^" + quoted + "$")}
}

func (p pattern) matches(s string) bool {
	s = strings.ToLower(s)
	if p.re != nil {
		return p.re.MatchString(s)
	}

	return strings.Contains(s, p.text)
}

// listDefault is how many rows a listing gives when no limit is asked for:
// enough for most answers whole, and few enough to read.
const listDefault = 200

// limitOr is a limit as asked for, or listDefault when none was.
func limitOr(asked int) int {
	if asked <= 0 {
		return listDefault
	}

	return asked
}
