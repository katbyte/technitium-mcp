package servers

import (
	"slices"
	"strings"
	"testing"
)

const (
	dockURL = "http://10.0.0.2:5380"
	rpiURL  = "http://10.0.0.3:5380"
	// tokenA and tokenB stand in for API tokens: no error may repeat either
	tokenA = "aaaa1111aaaa1111"
	tokenB = "bbbb2222bbbb2222"
)

// One server is its address and a token, as the other katbyte MCP servers
// are configured, and goes by "default".
func TestOneServer(t *testing.T) {
	t.Parallel()

	set, err := New([]string{dockURL}, []string{tokenA})
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 || !slices.Equal(set.Names(), []string{Default}) || set.Every()[0].Client.BaseURL() != dockURL {
		t.Errorf("the set = %v", set.Names())
	}

	// a change needs no name when there is one server to make it on
	for _, name := range []string{"", Default, " Default "} {
		if srv, err := set.One(name); err != nil || srv.Name != Default {
			t.Errorf("One(%q) = %v, %v", name, srv, err)
		}
	}
	if _, err := set.One(All); err == nil {
		t.Error("a change was allowed on every server by name")
	}
}

// Several servers are each named, in a list a flag given twice and an
// environment variable both arrive as; a token is one server's by name, or
// every other server's when given alone.
func TestSeveralServers(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct{ servers, tokens []string }{
		"one entry each":       {[]string{"dock=" + dockURL, "rpi=" + rpiURL}, []string{"dock=" + tokenA, "rpi=" + tokenB}},
		"joined by commas":     {[]string{"dock=" + dockURL + ", rpi=" + rpiURL}, []string{"dock=" + tokenA + ",rpi=" + tokenB}},
		"one token for both":   {[]string{"dock=" + dockURL, "rpi=" + rpiURL}, []string{tokenA}},
		"one named, one alone": {[]string{"dock=" + dockURL, "rpi=" + rpiURL}, []string{"rpi=" + tokenB, tokenA}},
	} {
		set, err := New(tc.servers, tc.tokens)
		if err != nil {
			t.Errorf("%s: %v", name, err)

			continue
		}
		if !slices.Equal(set.Names(), []string{"dock", "rpi"}) || set.Every()[1].Client.BaseURL() != rpiURL {
			t.Errorf("%s: the set = %v", name, set.Names())
		}
	}

	set, err := New([]string{"dock=" + dockURL, "rpi=" + rpiURL}, []string{tokenA})
	if err != nil {
		t.Fatal(err)
	}

	// a read asks every server unless one is named
	for _, name := range []string{"", All, "ALL"} {
		if picked, err := set.Pick(name); err != nil || len(picked) != 2 {
			t.Errorf("Pick(%q) = %d servers, %v", name, len(picked), err)
		}
	}
	if picked, err := set.Pick("RPI"); err != nil || len(picked) != 1 || picked[0].Name != "rpi" {
		t.Errorf("Pick(RPI) = %v, %v", picked, err)
	}
	if _, err := set.Pick("pi"); err == nil || !strings.Contains(err.Error(), "dock, rpi") {
		t.Errorf("Pick of a server that is not one = %v, want the ones there are", err)
	}

	// a change is made on one named server: never on all by leaving it out
	if srv, err := set.One("dock"); err != nil || srv.Name != "dock" {
		t.Errorf("One(dock) = %v, %v", srv, err)
	}
	for _, name := range []string{"", All} {
		if _, err := set.One(name); err == nil || !strings.Contains(err.Error(), "one server at a time") || !strings.Contains(err.Error(), "dock, rpi") {
			t.Errorf("One(%q) = %v, want a refusal naming the servers", name, err)
		}
	}
	if _, err := set.One("pi"); err == nil {
		t.Error("One of a server that is not one was allowed")
	}

	// what Every hands out is the caller's to reorder
	slices.Reverse(set.Every())
	if !slices.Equal(set.Names(), []string{"dock", "rpi"}) {
		t.Error("reordering what Every returned reordered the set")
	}
}

// A configuration that cannot work says what is wrong with it, and never
// repeats a token doing so.
func TestWhatCannotWork(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		servers, tokens []string
		want            string
	}{
		"no server":                  {nil, []string{tokenA}, "no server is configured"},
		"only blanks":                {[]string{" , "}, []string{tokenA}, "no server is configured"},
		"no token":                   {[]string{dockURL}, nil, "server default has no API token"},
		"two servers, one unnamed":   {[]string{"dock=" + dockURL, rpiURL}, []string{tokenA}, "has no name"},
		"two unnamed":                {[]string{dockURL, rpiURL}, []string{tokenA}, "has no name"},
		"named all":                  {[]string{"all=" + dockURL}, []string{tokenA}, `server name "all" will not do`},
		"a name with a capital":      {[]string{"Dock=" + dockURL}, []string{tokenA}, `server name "Dock" will not do`},
		"a name with a dot":          {[]string{"dock.van=" + dockURL}, []string{tokenA}, "will not do"},
		"the same name twice":        {[]string{"dock=" + dockURL, "dock=" + rpiURL}, []string{tokenA}, `two servers are named "dock"`},
		"the same address twice":     {[]string{"dock=" + dockURL, "rpi=" + dockURL + "/"}, []string{tokenA}, "are the same address"},
		"a token for nobody":         {[]string{"dock=" + dockURL}, []string{"rpi=" + tokenB}, `named for server "rpi", which is not configured`},
		"two tokens for one":         {[]string{"dock=" + dockURL}, []string{"dock=" + tokenA, "dock=" + tokenB}, "was given two API tokens"},
		"two tokens alone":           {[]string{"dock=" + dockURL}, []string{tokenA, tokenB}, "two API tokens were given without a server's name"},
		"one server left without":    {[]string{"dock=" + dockURL, "rpi=" + rpiURL}, []string{"dock=" + tokenA}, "server rpi has no API token"},
		"an address that is not one": {[]string{"dock=10.0.0.2"}, []string{tokenA}, "server dock: "},
	} {
		_, err := New(tc.servers, tc.tokens)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: New = %v, want an error saying %q", name, err, tc.want)

			continue
		}
		if strings.Contains(err.Error(), tokenA) || strings.Contains(err.Error(), tokenB) {
			t.Errorf("%s: the error repeats a token: %v", name, err)
		}
	}
}
