package technitium

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// A server blocks names three ways: by its own list of blocked names, which
// these calls keep; by block lists it fetches, whose addresses are in its
// settings; and by apps. Its own list of allowed names is the exception to
// all of them: a name on it, or under one on it, is never blocked. A name on
// either list stands for every name under it.

// BlockedNames lists every name on the server's own list of blocked names:
// the ones added by hand, not those of the block lists it fetches.
func (c *Client) BlockedNames(ctx context.Context) ([]string, error) {
	text, err := c.readText(ctx, "blocked/export", nil)

	return lines(text), err
}

// AllowedNames lists every name on the server's list of allowed names.
func (c *Client) AllowedNames(ctx context.Context) ([]string, error) {
	text, err := c.readText(ctx, "allowed/export", nil)

	return lines(text), err
}

// lines are the lines of a text that hold something.
func lines(text string) []string {
	var out []string
	for line := range strings.SplitSeq(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}

	return out
}

// BlockName adds a name to the server's own list of blocked names. A name
// already on it is no error.
func (c *Client) BlockName(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("blocked/add: which name")
	}

	return c.write(ctx, "blocked/add", url.Values{"domain": {name}}, nil)
}

// UnblockName takes a name off the server's own list of blocked names. A
// name that is not on it is no error.
func (c *Client) UnblockName(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("blocked/delete: which name")
	}

	return c.write(ctx, "blocked/delete", url.Values{"domain": {name}}, nil)
}

// AllowName adds a name to the server's list of allowed names. A name
// already on it is no error.
func (c *Client) AllowName(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("allowed/add: which name")
	}

	return c.write(ctx, "allowed/add", url.Values{"domain": {name}}, nil)
}

// UnallowName takes a name off the server's list of allowed names. A name
// that is not on it is no error.
func (c *Client) UnallowName(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("allowed/delete: which name")
	}

	return c.write(ctx, "allowed/delete", url.Values{"domain": {name}}, nil)
}

// SetBlocking switches the server's blocking on or off, and returns its
// settings as they then stand. Switched on, a pause is over.
func (c *Client) SetBlocking(ctx context.Context, on bool) (*Settings, error) {
	var out Settings
	if err := c.write(ctx, "settings/set", url.Values{"enableBlocking": {strconv.FormatBool(on)}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// SetBlockLists sets the lists the server fetches to the ones at these
// addresses, and to none when there are none; an address with a ! before it
// is a list of names to allow. Nothing else of the settings is changed.
func (c *Client) SetBlockLists(ctx context.Context, addresses []string) (*Settings, error) {
	// the API's word for none
	lists := "false"
	if len(addresses) > 0 {
		lists = strings.Join(addresses, ",")
	}

	var out Settings
	if err := c.write(ctx, "settings/set", url.Values{"blockListUrls": {lists}}, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// PauseBlocking switches the server's blocking off for some minutes, after
// which it comes back on by itself, and returns when that is.
func (c *Client) PauseBlocking(ctx context.Context, minutes int) (string, error) {
	if minutes <= 0 {
		return "", errors.New("settings/temporaryDisableBlocking: for how many minutes")
	}

	var out struct {
		Till string `json:"temporaryDisableBlockingTill"`
	}
	if err := c.write(ctx, "settings/temporaryDisableBlocking", url.Values{"minutes": {strconv.Itoa(minutes)}}, &out); err != nil {
		return "", err
	}

	return out.Till, nil
}

// UpdateBlockLists has the server fetch its block lists now rather than when
// they are next due. It answers at once: the lists are fetched after.
func (c *Client) UpdateBlockLists(ctx context.Context) error {
	return c.write(ctx, "settings/forceUpdateBlockLists", nil, nil)
}
