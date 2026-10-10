package technitium

import (
	"context"
	"errors"
	"net/url"
	"strings"
)

// StoreApp is a DNS app the server's maker offers for installing.
type StoreApp struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	// URL is where the app's zip file is fetched from
	URL string `json:"url"`
	// Size is how big the zip file is, as the server writes a size: 2.01 MB
	Size      string `json:"size"`
	Installed bool   `json:"installed"`
	// InstalledVersion and UpdateAvailable are an installed app's
	InstalledVersion string `json:"installedVersion"`
	UpdateAvailable  bool   `json:"updateAvailable"`
}

// StoreApps lists the apps the server's maker offers, which the server
// answers by asking its maker's site.
func (c *Client) StoreApps(ctx context.Context) ([]StoreApp, error) {
	var out struct {
		Apps []StoreApp `json:"storeApps"`
	}
	if err := c.read(ctx, "apps/listStoreApps", nil, &out); err != nil {
		return nil, err
	}

	return out.Apps, nil
}

// fetchParams are the parameters of the two calls that have the server
// fetch an app's zip file itself, from an address that must be over HTTPS.
func fetchParams(path, name, from string) (url.Values, error) {
	if name == "" || !strings.HasPrefix(from, "https://") {
		return nil, errors.New(path + ": which app, and the https:// address its zip file is fetched from")
	}

	return url.Values{"name": {name}, "url": {from}}, nil
}

// InstallAppFrom has the server fetch an app's zip file from an address,
// as StoreApps gives one, and install it under a name.
func (c *Client) InstallAppFrom(ctx context.Context, name, from string) (*App, error) {
	params, err := fetchParams("apps/downloadAndInstall", name, from)
	if err != nil {
		return nil, err
	}

	var out struct {
		App App `json:"installedApp"`
	}
	if err := c.write(ctx, "apps/downloadAndInstall", params, &out); err != nil {
		return nil, err
	}

	return &out.App, nil
}

// UpdateAppFrom has the server fetch an app's zip file from an address and
// put it in place of the app installed under a name, keeping its
// configuration.
func (c *Client) UpdateAppFrom(ctx context.Context, name, from string) (*App, error) {
	params, err := fetchParams("apps/downloadAndUpdate", name, from)
	if err != nil {
		return nil, err
	}

	var out struct {
		App App `json:"updatedApp"`
	}
	if err := c.write(ctx, "apps/downloadAndUpdate", params, &out); err != nil {
		return nil, err
	}

	return &out.App, nil
}

// InstallApp installs an app from its zip file under a name.
func (c *Client) InstallApp(ctx context.Context, name string, zip []byte) (*App, error) {
	if name == "" {
		return nil, errors.New("apps/install: an app is installed under a name")
	}
	if !isZip(zip) {
		return nil, errors.New("apps/install: an app is installed from its zip file, and what was given is not one")
	}

	var out struct {
		App App `json:"installedApp"`
	}
	if err := c.upload(ctx, "apps/install", url.Values{"name": {name}}, file{name: name + ".zip", data: zip}, &out); err != nil {
		return nil, err
	}

	return &out.App, nil
}

// UpdateApp puts an app's zip file in place of the app installed under a
// name, keeping its configuration.
func (c *Client) UpdateApp(ctx context.Context, name string, zip []byte) (*App, error) {
	if name == "" {
		return nil, errors.New("apps/update: which app")
	}
	if !isZip(zip) {
		return nil, errors.New("apps/update: an app is updated from its zip file, and what was given is not one")
	}

	var out struct {
		App App `json:"updatedApp"`
	}
	if err := c.upload(ctx, "apps/update", url.Values{"name": {name}}, file{name: name + ".zip", data: zip}, &out); err != nil {
		return nil, err
	}

	return &out.App, nil
}

// UninstallApp takes an app off the server. Records that were answered by
// the app stay in their zones and answer nothing.
func (c *Client) UninstallApp(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("apps/uninstall: which app")
	}

	return c.write(ctx, "apps/uninstall", url.Values{"name": {name}}, nil)
}

// SetAppConfig writes an installed app's configuration, which is text of
// the app's own kind - JSON, for most - and takes effect at once.
func (c *Client) SetAppConfig(ctx context.Context, name, config string) error {
	if name == "" {
		return errors.New("apps/config/set: which app")
	}

	return c.write(ctx, "apps/config/set", url.Values{"name": {name}, "config": {config}}, nil)
}
