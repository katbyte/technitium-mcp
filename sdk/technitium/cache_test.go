package technitium_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium"
	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// What a 15.6 server's cache held after it resolved two names through a
// forwarder: an address, and a name that was not there.
const cacheAnswer = `{"domain":"a.cached.test","zones":["deep.a.cached.test"],"records":[
	{"name":"a.cached.test","type":"A","ttl":"600 (10m)","rData":{"ipAddress":"10.5.5.5"},"dnssecStatus":"Disabled","responseMetadata":{"nameServer":"172.18.0.3","protocol":"Udp","roundTripTime":"19.26 ms"},"lastUsedOn":"2026-10-10T01:19:26.6210257Z"},
	{"name":"a.cached.test","type":"AAAA","ttl":"900 (15m)","rData":{"dataType":"DnsSpecialCacheRecordData","data":"NegativeCache: NoData; cached.test. 900 IN SOA ns2. hostadmin.cached.test. 3 900 300 604800 900"},"dnssecStatus":"Unknown","responseMetadata":{"nameServer":"172.18.0.3"},"lastUsedOn":"0001-01-01T00:00:00"}
]}`

func TestCache(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("cache/list", cacheAnswer)
	fake.Answer("cache/delete", `{}`)
	fake.Answer("cache/flush", `{}`)
	c := client(t, fake)

	got, err := c.Cache(t.Context(), "a.cached.test")
	if err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("cache/list"); asked.Method != http.MethodGet || asked.Params.Get("domain") != "a.cached.test" {
		t.Errorf("the cache was read with %s %v", asked.Method, asked.Params)
	}
	if got.Domain != "a.cached.test" || !slices.Equal(got.Zones, []string{"deep.a.cached.test"}) || len(got.Records) != 2 {
		t.Fatalf("Cache = %+v", got)
	}
	held, negative := &got.Records[0], &got.Records[1]
	if held.Value() != "10.5.5.5" || held.TTL() != 600 || held.Source.NameServer != "172.18.0.3" {
		t.Errorf("the address kept = %+v", held)
	}
	if _, isNegative := held.Negative(); isNegative {
		t.Error("an answer reads as a negative one")
	}
	if used, ok := held.Used(); !ok || used.Year() != 2026 {
		t.Errorf("the address was last used %v, %v", used, ok)
	}
	if said, isNegative := negative.Negative(); !isNegative || said != "NoData" || negative.Value() != "NoData" || negative.TTL() != 900 {
		t.Errorf("the negative answer = %q, %v (value %q)", said, isNegative, negative.Value())
	}
	if _, ok := negative.Used(); ok {
		t.Error("an answer never given reads as used")
	}

	// the top of the cache is asked for with no name
	if _, err := c.Cache(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("cache/list"); asked.Params.Has("domain") {
		t.Errorf("the top of the cache was read with %v", asked.Params)
	}

	if err := c.DeleteCached(t.Context(), "a.cached.test"); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("cache/delete"); asked.Method != http.MethodPost || asked.Params.Get("domain") != "a.cached.test" {
		t.Errorf("the name was dropped with %s %v", asked.Method, asked.Params)
	}
	// dropping no name is not dropping everything
	if err := c.DeleteCached(t.Context(), ""); err == nil || len(fake.Requests("cache/delete")) != 1 {
		t.Errorf("a drop of no name = %v, with %d sent", err, len(fake.Requests("cache/delete")))
	}
	if err := c.FlushCache(t.Context()); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("cache/flush"); asked.Method != http.MethodPost || len(asked.Params) != 0 {
		t.Errorf("the cache was flushed with %s %v", asked.Method, asked.Params)
	}

	// a zone that forwards is made with where to
	fake.Answer("zones/create", `{"domain":"fwd.test"}`)
	if _, err := c.CreateZone(t.Context(), technitium.NewZone{Name: "fwd.test", Type: technitium.ZoneForwarder, Forwarder: "172.18.0.3"}); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("zones/create"); asked.Params.Get("forwarder") != "172.18.0.3" || asked.Params.Get("type") != "Forwarder" {
		t.Errorf("the forwarder zone was made with %v", asked.Params)
	}
}
