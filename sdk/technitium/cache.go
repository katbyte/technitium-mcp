package technitium

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

// Cached is what a server's cache holds at a name: the answers it keeps for
// the name itself, and the names under it that it holds something for.
type Cached struct {
	// Domain is the name the answer is for. Asked for a name it holds
	// nothing at, the server answers for the nearest name below it that it
	// does, so this is not always the name asked for
	Domain string `json:"domain"`
	// Zones are the names directly under Domain that hold something
	Zones   []string       `json:"zones"`
	Records []CachedRecord `json:"records"`
}

// CachedRecord is one answer a server is keeping.
type CachedRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// TTLText is how long the answer is kept for yet, with its length in
	// words: 283 (4 mins 43 sec)
	TTLText string `json:"ttl"`
	// Data is the record's data, laid out as a zone's record's is; a
	// negative answer has its own two fields (see Negative)
	Data RData `json:"rData"`
	// Source is the name server the answer came from
	Source struct {
		NameServer string `json:"nameServer"`
	} `json:"responseMetadata"`
	LastUsedOn string `json:"lastUsedOn"`
}

// TTL is how many seconds the answer is kept for yet.
func (r *CachedRecord) TTL() int { return leadingInt(r.TTLText) }

// Negative is what a negative answer says - that the name does not exist, or
// has no record of the type - and false for a record that is an answer.
func (r *CachedRecord) Negative() (string, bool) {
	if r.Data.field("dataType") != "DnsSpecialCacheRecordData" {
		return "", false
	}
	// "NegativeCache: NxDomain; <the SOA it came with>"
	said, _, _ := strings.Cut(strings.TrimPrefix(r.Data.field("data"), "NegativeCache: "), ";")

	return strings.TrimSpace(said), true
}

// Value is the record's data on one line, as a zone's record's is written;
// for a negative answer, what it says.
func (r *CachedRecord) Value() string {
	if said, negative := r.Negative(); negative {
		return said
	}

	return (&Record{Type: r.Type, Data: r.Data}).Value()
}

// Used is when the answer was last given to a client.
func (r *CachedRecord) Used() (time.Time, bool) { return ParseTime(r.LastUsedOn) }

// Cache reads what the server's cache holds at a name: "" is the top.
func (c *Client) Cache(ctx context.Context, name string) (*Cached, error) {
	params := url.Values{}
	if name != "" {
		params.Set("domain", name)
	}

	var out Cached
	if err := c.read(ctx, "cache/list", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// DeleteCached drops what the server's cache holds at a name and at every
// name under it, so the next query for one is resolved afresh.
func (c *Client) DeleteCached(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("cache/delete: which name: the whole cache is FlushCache's to drop")
	}

	return c.write(ctx, "cache/delete", url.Values{"domain": {name}}, nil)
}

// FlushCache drops everything the server's cache holds.
func (c *Client) FlushCache(ctx context.Context) error {
	return c.write(ctx, "cache/flush", nil, nil)
}
