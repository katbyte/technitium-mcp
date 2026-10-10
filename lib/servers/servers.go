// Package servers is the set of Technitium servers one technitium-mcp process
// works on, each under a short name of the operator's choosing. The tools
// take that name to say which server a call is about, and "all" to ask every
// one and set the answers side by side - which is the point of holding
// several: two servers meant to agree are only seen to disagree when both are
// asked.
package servers

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
)

const (
	// All is the name that asks for every server.
	All = "all"
	// Default is the name of a single server given without one.
	Default = "default"
)

// Server is one configured server.
type Server struct {
	// Name is what the operator called it: ns1, ns2
	Name   string
	Client *technitium.Client
}

// Set is the configured servers, in the order given.
type Set struct {
	list []*Server
}

// validName is a name a tool argument and a setting can both carry.
var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// New builds the set from the server and token settings as given: each a
// list whose entries may themselves hold several joined by commas, as a flag
// given twice and an environment variable both arrive.
//
// A server is name=url; a single server may be a url alone, and is then
// called default. A token is name=token for the server of that name, or a
// token alone for every server given none of its own.
//
// Every server's client is made with the options given: a logger for its
// traffic, say.
func New(serverSettings, tokenSettings []string, opts ...technitium.Option) (*Set, error) {
	type named struct{ name, value string }

	given := entries(serverSettings)
	urls := make([]named, 0, len(given))
	for _, entry := range given {
		name, value, hasName := splitServer(entry)
		if !hasName {
			name = Default
		}
		urls = append(urls, named{name, value})
	}
	if len(urls) == 0 {
		return nil, errors.New("no server is configured: give --server (TECHNITIUM_SERVER) the address a Technitium web console answers on, e.g. http://nas:5380, or several as name=url")
	}

	set := &Set{}
	seenURL := map[string]string{}
	for _, u := range urls {
		if u.name == Default && len(urls) > 1 {
			return nil, fmt.Errorf("server %s has no name: with more than one server each needs one, as in --server ns1=http://192.168.1.2:5380,ns2=http://192.168.1.3:5380", u.value)
		}
		if u.name == All || !validName.MatchString(u.name) {
			return nil, fmt.Errorf("server name %q will not do: use lowercase letters, digits and dashes, and not %q, which asks for every server", u.name, All)
		}
		if set.find(u.name) != nil {
			return nil, fmt.Errorf("two servers are named %q", u.name)
		}
		address := strings.TrimRight(strings.ToLower(u.value), "/")
		if other, dup := seenURL[address]; dup {
			return nil, fmt.Errorf("servers %s and %s are the same address, %s: a server compared with itself always agrees", other, u.name, u.value)
		}
		seenURL[address] = u.name
		set.list = append(set.list, &Server{Name: u.name})
	}

	tokens, shared, err := splitTokens(tokenSettings, set)
	if err != nil {
		return nil, err
	}
	for i, srv := range set.list {
		token := tokens[srv.Name]
		if token == "" {
			token = shared
		}
		if token == "" {
			return nil, fmt.Errorf("server %s has no API token: give --token (TECHNITIUM_TOKEN) one for it as %s=<token>, or one token alone for every server", srv.Name, srv.Name)
		}
		client, err := technitium.New(urls[i].value, token, opts...)
		if err != nil {
			return nil, fmt.Errorf("server %s: %w", srv.Name, err)
		}
		srv.Client = client
	}

	return set, nil
}

// splitServer takes a server entry apart: name=url, or a url alone. A url
// has its own "=" only after its scheme, in a query the client refuses, so
// an "=" before any "://" is the name's.
func splitServer(entry string) (name, value string, hasName bool) {
	before, after, found := strings.Cut(entry, "=")
	if !found || strings.Contains(before, "://") {
		return "", entry, false
	}

	return strings.TrimSpace(before), strings.TrimSpace(after), true
}

// splitTokens sorts the token settings into the ones named for a server and
// the one given alone. A token is never part of an error: a name is said,
// and how many there were.
func splitTokens(settings []string, set *Set) (byName map[string]string, shared string, err error) {
	byName = map[string]string{}
	for _, entry := range entries(settings) {
		name, token, hasName := strings.Cut(entry, "=")
		if !hasName {
			if shared != "" {
				return nil, "", errors.New("two API tokens were given without a server's name: name each as <server>=<token>")
			}
			shared = entry

			continue
		}
		name = strings.TrimSpace(name)
		if set.find(name) == nil {
			return nil, "", fmt.Errorf("an API token is named for server %q, which is not configured (servers: %s)", name, strings.Join(set.Names(), ", "))
		}
		if byName[name] != "" {
			return nil, "", fmt.Errorf("server %s was given two API tokens", name)
		}
		byName[name] = strings.TrimSpace(token)
	}

	return byName, shared, nil
}

// entries splits a list whose entries may each hold several joined by
// commas.
func entries(raw []string) []string {
	var out []string
	for _, entry := range raw {
		for part := range strings.SplitSeq(entry, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}

	return out
}

func (s *Set) find(name string) *Server {
	for _, srv := range s.list {
		if srv.Name == name {
			return srv
		}
	}

	return nil
}

// Len is how many servers are configured.
func (s *Set) Len() int { return len(s.list) }

// Names are the configured servers' names, in the order given.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.list))
	for _, srv := range s.list {
		out = append(out, srv.Name)
	}

	return out
}

// Every is every configured server, in the order given.
func (s *Set) Every() []*Server {
	return append([]*Server(nil), s.list...)
}

// Pick is the servers a read is about: the one named, or every one for All
// and for no name at all. A name that is no server's is an error saying
// which there are.
func (s *Set) Pick(name string) ([]*Server, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == All {
		return s.Every(), nil
	}
	if srv := s.find(name); srv != nil {
		return []*Server{srv}, nil
	}

	return nil, fmt.Errorf("no server is named %q: the configured servers are %s, and %s asks every one", name, strings.Join(s.Names(), ", "), All)
}

// One is the server a change is made on. A change is never made on "every
// server" by leaving the name out: with more than one configured it must be
// named, since two servers may hold a zone in different roles.
func (s *Set) One(name string) (*Server, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" && len(s.list) == 1 {
		return s.list[0], nil
	}
	if name == "" || name == All {
		return nil, fmt.Errorf("which server: a change is made on one server at a time, so name it (%s)", strings.Join(s.Names(), ", "))
	}
	if srv := s.find(name); srv != nil {
		return srv, nil
	}

	return nil, fmt.Errorf("no server is named %q: the configured servers are %s", name, strings.Join(s.Names(), ", "))
}
