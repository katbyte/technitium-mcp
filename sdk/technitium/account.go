package technitium

import (
	"context"
	"errors"
	"net/url"
	"strconv"
)

// SignedIn is who signing in found the name and password to be.
type SignedIn struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	// IsSSOUser is an account that signs in through the single sign-on the
	// server is set up with, and has no password of its own here
	IsSSOUser bool `json:"isSsoUser"`
	// TOTPEnabled is the account asking for a one-time code beside its
	// password
	TOTPEnabled bool       `json:"totpEnabled"`
	Info        ServerInfo `json:"info"`
}

// Login signs in to the server with an account's name and password, and its
// one-time code when it has a second factor, and returns a client that works
// under the session that opened. The session ends when nothing has used it
// for the account's timeout, half an hour unless it was changed, or at
// Logout.
//
// A session is what a handful of calls about the account itself ask for,
// where an API token is refused: ChangePassword, SetProfile, the calls about
// a second factor, and CreateToken.
func (c *Client) Login(ctx context.Context, user, pass, totp string) (*Client, *SignedIn, error) {
	if user == "" || pass == "" {
		return nil, nil, errors.New("user/login: signing in takes an account's name and its password")
	}
	params := url.Values{"user": {user}, "pass": {pass}, "includeInfo": {yes}}
	set(params, map[string]string{"totp": totp})

	var out struct {
		SignedIn

		Token string `json:"token"`
	}
	if err := c.anonymous().writeWhole(ctx, "user/login", params, &out); err != nil {
		return nil, nil, err
	}
	if out.Token == "" {
		return nil, nil, errors.New("user/login: the server said ok and gave no session")
	}
	session := c.anonymous()
	session.token = out.Token

	return session, &out.SignedIn, nil
}

// CreateToken makes an API token for the account the client is signed in as
// (see Login), under a name that says what it is for. A token does not
// expire and may do whatever its account may, so it is given to whatever
// will use it and kept nowhere else: the server never shows it again.
func (c *Client) CreateToken(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", errors.New("user/createToken: a token is made under a name that says what it is for")
	}

	return c.newToken(ctx, c, url.Values{"tokenName": {name}})
}

// CreateTokenFor is CreateToken with an account's name and password in place
// of a session, and its one-time code when it has a second factor.
func (c *Client) CreateTokenFor(ctx context.Context, user, pass, totp, name string) (string, error) {
	if user == "" || pass == "" || name == "" {
		return "", errors.New("user/createToken: a token is made for an account, by its name and password, under a name that says what it is for")
	}
	params := url.Values{"user": {user}, "pass": {pass}, "tokenName": {name}}
	set(params, map[string]string{"totp": totp})

	return c.newToken(ctx, c.anonymous(), params)
}

func (*Client) newToken(ctx context.Context, as *Client, params url.Values) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	if err := as.writeWhole(ctx, "user/createToken", params, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("user/createToken: the server said ok and gave no token")
	}

	return out.Token, nil
}

// SingleUseToken makes a token for the account the client is signed in as
// (see Login) that works for one call and then is gone.
func (c *Client) SingleUseToken(ctx context.Context) (string, error) {
	// the API document shows the token beside "status", and a 15.6 server
	// puts it under "response": it is read from wherever it is
	var out struct {
		Token    string `json:"token"`
		Response struct {
			Token string `json:"token"`
		} `json:"response"`
	}
	if err := c.writeWhole(ctx, "user/createSingleUseToken", nil, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		out.Token = out.Response.Token
	}
	if out.Token == "" {
		return "", errors.New("user/createSingleUseToken: the server said ok and gave no token")
	}

	return out.Token, nil
}

// Logout ends the session the client works under, after which its token is
// refused. For a client made with an API token that is the token itself,
// deleted for good.
func (c *Client) Logout(ctx context.Context) error {
	return c.write(ctx, "user/logout", nil, nil)
}

// EndSession ends another session of the client's own account, or one of
// its API tokens, by the part of its token the profile gives it under.
func (c *Client) EndSession(ctx context.Context, partialToken string) error {
	if partialToken == "" {
		return errors.New("user/session/delete: which session, by the partial token the profile gives it")
	}

	return c.write(ctx, "user/session/delete", url.Values{"partialToken": {partialToken}}, nil)
}

// The fewest and the most rounds a password may be hashed with.
const (
	MinPasswordIterations = 100000
	MaxPasswordIterations = 1000000
)

// ChangePassword changes the password of the account the client is signed in
// as (see Login), given the one it has, and its one-time code when it has a
// second factor. Iterations is how many rounds the new one is hashed with
// where it is kept, 0 for the server's own 100000.
func (c *Client) ChangePassword(ctx context.Context, current, replacement, totp string, iterations int) error {
	if current == "" || replacement == "" {
		return errors.New("user/changePassword: a password is changed with the one the account has and the one it is to have")
	}
	if iterations != 0 && (iterations < MinPasswordIterations || iterations > MaxPasswordIterations) {
		return errors.New("user/changePassword: a password is hashed with between 100000 and 1000000 rounds")
	}
	params := url.Values{"pass": {current}, "newPass": {replacement}}
	set(params, map[string]string{"totp": totp})
	if iterations != 0 {
		params.Set("iterations", strconv.Itoa(iterations))
	}

	return c.write(ctx, "user/changePassword", params, nil)
}

// TwoFactorSetup is a second factor waiting to be switched on: the secret an
// authenticator app is given, as text and as the picture one scans.
type TwoFactorSetup struct {
	// Enabled is the account having a second factor already
	Enabled bool `json:"totpEnabled"`
	// Secret is what the app is given by hand, and QRCodePNG the same as a
	// picture, a PNG in base64. Either one is the second factor itself:
	// whoever has it can make the codes
	Secret    string `json:"secret"`
	QRCodePNG string `json:"qrCodePngImage"`
}

// InitTwoFactor begins giving the account the client is signed in as (see
// Login) a second factor: the server makes a secret, and EnableTwoFactor
// switches it on once an app is making codes from it.
func (c *Client) InitTwoFactor(ctx context.Context) (*TwoFactorSetup, error) {
	var out TwoFactorSetup
	if err := c.write(ctx, "user/2fa/init", nil, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// EnableTwoFactor switches the second factor on with a code made from the
// secret InitTwoFactor gave: from then on signing in takes a code too.
func (c *Client) EnableTwoFactor(ctx context.Context, code string) error {
	if code == "" {
		return errors.New("user/2fa/enable: a second factor is switched on with a code the authenticator app made from its secret")
	}

	return c.write(ctx, "user/2fa/enable", url.Values{"totp": {code}}, nil)
}

// DisableTwoFactor takes the second factor off the account the client is
// signed in as (see Login).
func (c *Client) DisableTwoFactor(ctx context.Context) error {
	return c.write(ctx, "user/2fa/disable", nil, nil)
}

// Profile is an account as its own owner sees it.
type Profile struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	IsSSOUser   bool   `json:"isSsoUser"`
	TOTPEnabled bool   `json:"totpEnabled"`
	Disabled    bool   `json:"disabled"`
	// PreviousSessionLoggedOn and RecentSessionLoggedOn are when the account
	// signed in the time before last and last, in UTC, and the addresses
	// beside them where from
	PreviousSessionLoggedOn      string `json:"previousSessionLoggedOn"`
	PreviousSessionRemoteAddress string `json:"previousSessionRemoteAddress"`
	RecentSessionLoggedOn        string `json:"recentSessionLoggedOn"`
	RecentSessionRemoteAddress   string `json:"recentSessionRemoteAddress"`
	// SessionTimeoutSeconds is how long a session of the account's lasts
	// with nothing using it
	SessionTimeoutSeconds int      `json:"sessionTimeoutSeconds"`
	MemberOfGroups        []string `json:"memberOfGroups"`
	// Sessions are the account's own: who is signed in as it, and its API
	// tokens
	Sessions []OpenSession `json:"sessions"`
}

// Profile reads the account the client's token belongs to.
func (c *Client) Profile(ctx context.Context) (*Profile, error) {
	var out Profile
	if err := c.read(ctx, "user/profile/get", nil, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ProfileChange is what to set of an account's own profile: whatever is left
// as it is here stays as it is on the server.
type ProfileChange struct {
	// DisplayName is the account's name as people read it, which single
	// sign-on sets for an account of its own
	DisplayName string
	// SessionTimeoutSeconds is how long a session lasts with nothing using
	// it, 0 to leave it
	SessionTimeoutSeconds int
}

// SetProfile changes the profile of the account the client is signed in as
// (see Login), and returns it as it now stands.
func (c *Client) SetProfile(ctx context.Context, change ProfileChange) (*Profile, error) {
	params := url.Values{}
	set(params, map[string]string{"displayName": change.DisplayName})
	if change.SessionTimeoutSeconds != 0 {
		params.Set("sessionTimeoutSeconds", strconv.Itoa(change.SessionTimeoutSeconds))
	}
	if len(params) == 0 {
		return nil, errors.New("user/profile/set: which of the profile: nothing was given to set")
	}

	var out Profile
	if err := c.write(ctx, "user/profile/set", params, &out); err != nil {
		return nil, err
	}

	return &out, nil
}
