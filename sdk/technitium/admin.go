package technitium

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// CreateTokenAs makes an API token for any account, which only an
// administrator may: the token acts as that account and does not expire. It
// is given to whatever will use it and kept nowhere else, since the server
// never shows it again.
func (c *Client) CreateTokenAs(ctx context.Context, user, name string) (string, error) {
	if user == "" || name == "" {
		return "", errors.New("admin/sessions/createToken: a token is made for an account, under a name that says what it is for")
	}

	var out struct {
		Token string `json:"token"`
	}
	if err := c.write(ctx, "admin/sessions/createToken", url.Values{"user": {user}, "tokenName": {name}}, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("admin/sessions/createToken: the server said ok and gave no token")
	}

	return out.Token, nil
}

// DeleteSession ends anyone's session, or deletes an API token, by the part
// of its token Sessions gives it under.
func (c *Client) DeleteSession(ctx context.Context, partialToken string) error {
	if partialToken == "" {
		return errors.New("admin/sessions/delete: which session, by the partial token the list of sessions gives it")
	}

	return c.write(ctx, "admin/sessions/delete", url.Values{"partialToken": {partialToken}}, nil)
}

// User is an account as an administrator sees it. A list of users gives
// each without its groups and sessions.
type User struct {
	Profile

	// Groups are every group there is, for choosing among, when they were
	// asked for
	Groups []string `json:"groups"`
}

// Users lists the accounts on the server.
func (c *Client) Users(ctx context.Context) ([]User, error) {
	var out struct {
		Users []User `json:"users"`
	}
	if err := c.read(ctx, "admin/users/list", nil, &out); err != nil {
		return nil, err
	}

	return out.Users, nil
}

// User reads one account: its groups, its sessions and its tokens. With
// withGroups it also lists every group there is.
func (c *Client) User(ctx context.Context, name string, withGroups bool) (*User, error) {
	if name == "" {
		return nil, errors.New("admin/users/get: which account")
	}
	params := url.Values{"user": {name}}
	if withGroups {
		params.Set("includeGroups", yes)
	}

	var out User
	if err := c.read(ctx, "admin/users/get", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// NewUser is an account to make.
type NewUser struct {
	Username string
	Password string
	// DisplayName is the account's name as people read it, the username
	// when left out
	DisplayName string
}

// CreateUser makes an account, which is in no group but Everyone until
// SetUser puts it in one.
func (c *Client) CreateUser(ctx context.Context, user NewUser) (*User, error) {
	if user.Username == "" || user.Password == "" {
		return nil, errors.New("admin/users/create: an account is made with a name and a password")
	}
	params := url.Values{"user": {user.Username}, "pass": {user.Password}}
	set(params, map[string]string{"displayName": user.DisplayName})

	var out User
	if err := c.write(ctx, "admin/users/create", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// UserChange is what to set of an account: whatever is left as it is here
// stays as it is on the server.
type UserChange struct {
	DisplayName string
	// NewUsername renames the account
	NewUsername string
	// DisableTwoFactor takes the account's second factor off. One cannot be
	// put on for somebody else
	DisableTwoFactor bool
	// Disabled switches the account off, which ends its sessions, or back on
	Disabled *bool
	// SessionTimeoutSeconds is how long a session lasts with nothing using
	// it, 0 to leave it
	SessionTimeoutSeconds int
	// NewPassword resets the password, hashed with Iterations rounds or the
	// server's own 100000 for 0
	NewPassword string
	Iterations  int
	// MemberOfGroups are the groups the account is in from now on: nil
	// leaves them as they are
	MemberOfGroups []string
}

// SetUser changes an account, and returns it as it now stands.
func (c *Client) SetUser(ctx context.Context, name string, change UserChange) (*User, error) {
	if name == "" {
		return nil, errors.New("admin/users/set: which account")
	}
	if change.Iterations != 0 && (change.NewPassword == "" || change.Iterations < MinPasswordIterations || change.Iterations > MaxPasswordIterations) {
		return nil, errors.New("admin/users/set: the rounds are those a new password is hashed with, between 100000 and 1000000")
	}
	params := url.Values{"user": {name}}
	set(params, map[string]string{"displayName": change.DisplayName, "newUser": change.NewUsername, "disabled": flag(change.Disabled), "newPass": change.NewPassword})
	if change.DisableTwoFactor {
		params.Set("totpEnabled", "false")
	}
	if change.SessionTimeoutSeconds != 0 {
		params.Set("sessionTimeoutSeconds", strconv.Itoa(change.SessionTimeoutSeconds))
	}
	if change.Iterations != 0 {
		params.Set("iterations", strconv.Itoa(change.Iterations))
	}
	if change.MemberOfGroups != nil {
		params.Set("memberOfGroups", strings.Join(change.MemberOfGroups, ","))
	}
	if len(params) == 1 {
		return nil, errors.New("admin/users/set: which of the account: nothing was given to set")
	}

	var out User
	if err := c.write(ctx, "admin/users/set", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// DeleteUser deletes an account, and with it its sessions and its tokens.
func (c *Client) DeleteUser(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("admin/users/delete: which account")
	}

	return c.write(ctx, "admin/users/delete", url.Values{"user": {name}}, nil)
}

// Group is a group of accounts, which permissions are given to.
type Group struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Members are the accounts in the group, which a list of groups leaves
	// out, and Users every account there is, for choosing among, when they
	// were asked for
	Members []string `json:"members"`
	Users   []string `json:"users"`
}

// Groups lists the groups on the server, each without its members.
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	var out struct {
		Groups []Group `json:"groups"`
	}
	if err := c.read(ctx, "admin/groups/list", nil, &out); err != nil {
		return nil, err
	}

	return out.Groups, nil
}

// Group reads one group and its members. With withUsers it also lists every
// account there is.
func (c *Client) Group(ctx context.Context, name string, withUsers bool) (*Group, error) {
	if name == "" {
		return nil, errors.New("admin/groups/get: which group")
	}
	params := url.Values{"group": {name}}
	if withUsers {
		params.Set("includeUsers", yes)
	}

	var out Group
	if err := c.read(ctx, "admin/groups/get", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// CreateGroup makes a group with nobody in it.
func (c *Client) CreateGroup(ctx context.Context, name, description string) (*Group, error) {
	if name == "" {
		return nil, errors.New("admin/groups/create: a group is made with a name")
	}
	params := url.Values{"group": {name}}
	set(params, map[string]string{"description": description})

	var out Group
	if err := c.write(ctx, "admin/groups/create", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// GroupChange is what to set of a group: whatever is left as it is here
// stays as it is on the server.
type GroupChange struct {
	// NewName renames the group
	NewName string
	// Description is what the group is for; nil leaves it, and "" clears it
	Description *string
	// Members are the accounts in the group from now on: nil leaves them as
	// they are
	Members []string
}

// SetGroup changes a group, and returns it as it now stands.
func (c *Client) SetGroup(ctx context.Context, name string, change GroupChange) (*Group, error) {
	if name == "" {
		return nil, errors.New("admin/groups/set: which group")
	}
	params := url.Values{"group": {name}}
	set(params, map[string]string{"newGroup": change.NewName})
	if change.Description != nil {
		params.Set("description", *change.Description)
	}
	if change.Members != nil {
		params.Set("members", strings.Join(change.Members, ","))
	}
	if len(params) == 1 {
		return nil, errors.New("admin/groups/set: which of the group: nothing was given to set")
	}

	var out Group
	if err := c.write(ctx, "admin/groups/set", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// DeleteGroup deletes a group, and with it what its members were allowed as
// members of it.
func (c *Client) DeleteGroup(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("admin/groups/delete: which group")
	}

	return c.write(ctx, "admin/groups/delete", url.Values{"group": {name}}, nil)
}

// UserAccess is what one account may do with something, and GroupAccess what
// the members of one group may.
type UserAccess struct {
	Username string `json:"username"`

	Permission
}

// GroupAccess is what the members of one group may do with something.
type GroupAccess struct {
	Name string `json:"name"`

	Permission
}

// Access is who may do what in one section of the server - Zones, Settings,
// Logs and the rest - or, with SubItem, with one zone.
type Access struct {
	Section string `json:"section"`
	// SubItem is the zone the permissions are for, "" for a whole section's
	SubItem string        `json:"subItem"`
	Users   []UserAccess  `json:"userPermissions"`
	Groups  []GroupAccess `json:"groupPermissions"`
	// AllUsers and AllGroups are every account and every group there is, for
	// choosing among, when they were asked for
	AllUsers  []string `json:"users"`
	AllGroups []string `json:"groups"`
}

// Permissions lists who may do what in every section of the server.
func (c *Client) Permissions(ctx context.Context) ([]Access, error) {
	var out struct {
		Permissions []Access `json:"permissions"`
	}
	if err := c.read(ctx, "admin/permissions/list", nil, &out); err != nil {
		return nil, err
	}

	return out.Permissions, nil
}

// SectionPermissions reads who may do what in one section. With withNames
// it also lists every account and group there is.
func (c *Client) SectionPermissions(ctx context.Context, section string, withNames bool) (*Access, error) {
	if section == "" {
		return nil, errors.New("admin/permissions/get: which section")
	}
	params := url.Values{"section": {section}}
	if withNames {
		params.Set("includeUsersAndGroups", yes)
	}

	var out Access
	if err := c.read(ctx, "admin/permissions/get", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// AccessChange is who may do what from now on. Each list given replaces the
// one there is, whole: nil leaves one as it is.
type AccessChange struct {
	Users  []UserAccess
	Groups []GroupAccess
}

// params are the lists as the API takes them: a table written out in one
// line, a name and then whether it may view, modify and delete.
func (a AccessChange) params(path string, params url.Values) error {
	if a.Users == nil && a.Groups == nil {
		return errors.New(path + ": whose permissions: neither accounts nor groups were given")
	}
	row := func(name string, may Permission) ([]string, error) {
		if name == "" || strings.Contains(name, "|") {
			return nil, errors.New(path + ": a permission is given to an account or a group by its name, which has no | in it")
		}

		return []string{name, strconv.FormatBool(may.CanView), strconv.FormatBool(may.CanModify), strconv.FormatBool(may.CanDelete)}, nil
	}
	if a.Users != nil {
		cells := []string{}
		for _, u := range a.Users {
			cellsOf, err := row(u.Username, u.Permission)
			if err != nil {
				return err
			}
			cells = append(cells, cellsOf...)
		}
		params.Set("userPermissions", strings.Join(cells, "|"))
	}
	if a.Groups != nil {
		cells := []string{}
		for _, g := range a.Groups {
			cellsOf, err := row(g.Name, g.Permission)
			if err != nil {
				return err
			}
			cells = append(cells, cellsOf...)
		}
		params.Set("groupPermissions", strings.Join(cells, "|"))
	}

	return nil
}

// SetSectionPermissions sets who may do what in one section, and returns the
// permissions as they now stand.
func (c *Client) SetSectionPermissions(ctx context.Context, section string, change AccessChange) (*Access, error) {
	if section == "" {
		return nil, errors.New("admin/permissions/set: which section")
	}
	params := url.Values{"section": {section}}
	if err := change.params("admin/permissions/set", params); err != nil {
		return nil, err
	}

	var out Access
	if err := c.write(ctx, "admin/permissions/set", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ZonePermissions reads who may do what with one zone, which is beside what
// the Zones section allows everybody in it. With withNames it also lists
// every account and group there is.
func (c *Client) ZonePermissions(ctx context.Context, zone string, withNames bool) (*Access, error) {
	if zone == "" {
		return nil, errors.New("zones/permissions/get: which zone")
	}
	params := url.Values{"zone": {zone}}
	if withNames {
		params.Set("includeUsersAndGroups", yes)
	}

	var out Access
	if err := c.read(ctx, "zones/permissions/get", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// SetZonePermissions sets who may do what with one zone, and returns the
// permissions as they now stand.
func (c *Client) SetZonePermissions(ctx context.Context, zone string, change AccessChange) (*Access, error) {
	if zone == "" {
		return nil, errors.New("zones/permissions/set: which zone")
	}
	params := url.Values{"zone": {zone}}
	if err := change.params("zones/permissions/set", params); err != nil {
		return nil, err
	}

	var out Access
	if err := c.write(ctx, "zones/permissions/set", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// GroupMapping is a group at the single sign-on provider and the group here
// its members are put in.
type GroupMapping struct {
	RemoteGroup string `json:"remoteGroup"`
	LocalGroup  string `json:"localGroup"`
}

// SSO is how the server is set up for single sign-on with OpenID Connect.
// The client's secret at the provider is never read.
type SSO struct {
	Enabled   bool   `json:"ssoEnabled"`
	Authority string `json:"ssoAuthority"`
	ClientID  string `json:"ssoClientId"`
	// MetadataAddress is where the provider describes itself, when that is
	// not where the authority's address says
	MetadataAddress string `json:"ssoMetadataAddress"`
	// AllowSignup is an account being made for whoever signs in through the
	// provider for the first time, and AllowSignupOnlyForMappedUsers only
	// for those in a group the map names
	AllowSignup                   bool           `json:"ssoAllowSignup"`
	AllowSignupOnlyForMappedUsers bool           `json:"ssoAllowSignupOnlyForMappedUsers"`
	GroupMap                      []GroupMapping `json:"ssoGroupMap"`
	// LocalGroups are every group there is here, for mapping to, when they
	// were asked for
	LocalGroups []string `json:"localGroups"`
}

// SSO reads how the server is set up for single sign-on. With withGroups it
// also lists the groups here.
func (c *Client) SSO(ctx context.Context, withGroups bool) (*SSO, error) {
	params := url.Values{}
	if withGroups {
		params.Set("includeGroups", yes)
	}

	var out SSO
	if err := c.read(ctx, "admin/sso/get", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// SSOChange is what to set of single sign-on: whatever is left as it is
// here stays as it is on the server.
type SSOChange struct {
	Enabled *bool
	// Authority, ClientID and MetadataAddress are set by a value and cleared
	// by ""; nil leaves one as it is
	Authority, ClientID, MetadataAddress *string
	// ClientSecret is the client's secret at the provider, "" to leave it
	ClientSecret                  string
	AllowSignup                   *bool
	AllowSignupOnlyForMappedUsers *bool
	// GroupMap replaces the map there is, whole: nil leaves it
	GroupMap []GroupMapping
}

// SetSSO changes how the server is set up for single sign-on, and returns
// it as it now stands. The server restarts its web console when the change
// needs it, and for that moment answers nothing.
func (c *Client) SetSSO(ctx context.Context, change SSOChange) (*SSO, error) {
	params := url.Values{}
	set(params, map[string]string{"ssoEnabled": flag(change.Enabled), "ssoClientSecret": change.ClientSecret, "ssoAllowSignup": flag(change.AllowSignup), "ssoAllowSignupOnlyForMappedUsers": flag(change.AllowSignupOnlyForMappedUsers)})
	for name, value := range map[string]*string{"ssoAuthority": change.Authority, "ssoClientId": change.ClientID, "ssoMetadataAddress": change.MetadataAddress} {
		if value != nil {
			params.Set(name, *value)
		}
	}
	if change.GroupMap != nil {
		cells := []string{}
		for _, m := range change.GroupMap {
			if m.RemoteGroup == "" || m.LocalGroup == "" || strings.Contains(m.RemoteGroup+m.LocalGroup, "|") {
				return nil, errors.New("admin/sso/set: a group is mapped by its name at the provider and a group's name here, neither with a | in it")
			}
			cells = append(cells, m.RemoteGroup, m.LocalGroup)
		}
		params.Set("ssoGroupMap", strings.Join(cells, "|"))
	}
	if len(params) == 0 {
		return nil, errors.New("admin/sso/set: which of single sign-on: nothing was given to set")
	}

	var out SSO
	if err := c.write(ctx, "admin/sso/set", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// NewSSOUser is an account for someone who signs in through the provider.
type NewSSOUser struct {
	Username    string
	DisplayName string
	// Identifier is what the provider knows the person by
	Identifier     string
	MemberOfGroups []string
}

// CreateSSOUser makes an account for someone who signs in through the
// provider. It is the call one node of a cluster makes of another, and the
// server takes it only under the cluster's own token: an administrator's is
// refused.
func (c *Client) CreateSSOUser(ctx context.Context, user NewSSOUser) (*User, error) {
	if user.Username == "" || user.Identifier == "" {
		return nil, errors.New("admin/sso/users/create: an account for single sign-on is made with a name and what the provider knows the person by")
	}
	params := url.Values{"user": {user.Username}, "ssoIdentifier": {user.Identifier}}
	set(params, map[string]string{"displayName": user.DisplayName, "memberOfGroups": strings.Join(user.MemberOfGroups, ",")})

	var out User
	if err := c.write(ctx, "admin/sso/users/create", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// SSOUserChange is what to set of a single sign-on account: whatever is
// left as it is here stays as it is on the server.
type SSOUserChange struct {
	NewUsername string
	DisplayName string
	// MemberOfGroups are the groups the account is in from now on: nil
	// leaves them as they are
	MemberOfGroups []string
}

// SetSSOUser changes a single sign-on account. Like CreateSSOUser it is a
// call between the nodes of a cluster, taken only under the cluster's own
// token.
func (c *Client) SetSSOUser(ctx context.Context, name string, change SSOUserChange) (*User, error) {
	if name == "" {
		return nil, errors.New("admin/sso/users/set: which account")
	}
	params := url.Values{"user": {name}}
	set(params, map[string]string{"newUser": change.NewUsername, "displayName": change.DisplayName})
	if change.MemberOfGroups != nil {
		params.Set("memberOfGroups", strings.Join(change.MemberOfGroups, ","))
	}
	if len(params) == 1 {
		return nil, errors.New("admin/sso/users/set: which of the account: nothing was given to set")
	}

	var out User
	if err := c.write(ctx, "admin/sso/users/set", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}
