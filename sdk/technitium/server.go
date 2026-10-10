package technitium

import (
	"context"
	"time"
)

// Status is what a server says of itself to anyone who asks, token or none.
type Status struct {
	// Server is the server's own domain name
	Server string `json:"server"`
	// HasDefaultCredentials is the admin account still on the password the
	// server ships with
	HasDefaultCredentials bool `json:"hasDefaultCredentials"`
	SSOEnabled            bool `json:"ssoEnabled"`
}

// Status asks whether the API is there, which needs no token to answer.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var out Status
	if err := c.readWhole(ctx, "status", nil, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Session is what a token's session says of the account it belongs to and of
// the server. The token itself, which the server sends back with it, is not
// kept.
type Session struct {
	Username    string     `json:"username"`
	DisplayName string     `json:"displayName"`
	TokenName   string     `json:"tokenName"`
	Info        ServerInfo `json:"info"`
}

// ServerInfo is what a session is told of the server it is on.
type ServerInfo struct {
	Version string `json:"version"`
	// UpSince is when the server started, in UTC
	UpSince string `json:"uptimestamp"`
	// Domain is the server's own domain name, the primary name server its
	// zones name
	Domain             string `json:"dnsServerDomain"`
	DefaultRecordTTL   int    `json:"defaultRecordTtl"`
	DefaultNSRecordTTL int    `json:"defaultNsRecordTtl"`
	DefaultSOATTL      int    `json:"defaultSoaRecordTtl"`
	DNSSECValidation   bool   `json:"dnssecValidation"`
	ClusterInitialized bool   `json:"clusterInitialized"`
	ClusterDomain      string `json:"clusterDomain"`
	// Permissions are what the token's account may do, by section of the
	// console: Zones, Cache, Settings and the rest
	Permissions map[string]Permission `json:"permissions"`
}

// Permission is what an account may do in one section.
type Permission struct {
	CanView   bool `json:"canView"`
	CanModify bool `json:"canModify"`
	CanDelete bool `json:"canDelete"`
}

// Started is when the server started, and false when it does not say in a
// way that can be read.
func (i *ServerInfo) Started() (time.Time, bool) {
	return ParseTime(i.UpSince)
}

// Session reads the session the client's token belongs to: who it acts as,
// what that account may do, and the server's version and name.
func (c *Client) Session(ctx context.Context) (*Session, error) {
	var out Session
	if err := c.readWhole(ctx, "user/session/get", nil, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Update is what the server knows of a newer version of itself.
type Update struct {
	// CheckEnabled is the server set to look for updates at all
	CheckEnabled   bool   `json:"dnsServerEnableCheckForUpdate"`
	Available      bool   `json:"updateAvailable"`
	CurrentVersion string `json:"currentVersion"`
	UpdateVersion  string `json:"updateVersion"`
	Title          string `json:"updateTitle"`
	Message        string `json:"updateMessage"`
	ChangeLogLink  string `json:"changeLogLink"`
}

// CheckForUpdate asks the server whether a newer version of itself is out,
// which it answers by asking its maker's site.
func (c *Client) CheckForUpdate(ctx context.Context) (*Update, error) {
	var out Update
	if err := c.read(ctx, "user/checkForUpdate", nil, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ParseTime reads a time as the server writes one, and reports false for one
// that is no time: it writes UTC with a Z, and for "never" the zero time with
// no zone at all.
func ParseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, t.Year() > 1
		}
	}

	return time.Time{}, false
}
