package technitium_test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/technitium/technitiumtest"
)

// app is an app as the server answers with one it has just installed.
const app = `{"name":"Wild IP","version":"1.0","dnsApps":[{"classPath":"WildIp.App","description":"Returns the IP address that was embedded in the subdomain name.","isAppRecordRequestHandler":true,"recordDataTemplate":null,"isRequestController":false,"isAuthoritativeRequestHandler":false,"isRequestBlockingHandler":false,"isQueryLogger":false,"isPostProcessor":false}]}`

// An app is installed from an address the server fetches itself, or from a
// zip file sent to it; either way the answer is the app as installed.
func TestAppsInstalledAndRemoved(t *testing.T) {
	t.Parallel()

	fake := technitiumtest.New(t)
	fake.Answer("apps/listStoreApps", `{"storeApps":[{"name":"Geo Continent","version":"1.1","description":"Returns A or AAAA records by continent.","url":"https://download.technitium.com/dns/apps/GeoContinentApp.zip","size":"2.01 MB","installed":false},{"name":"Split Horizon","version":"1.2","description":"Returns different records for public and private networks.","url":"https://download.technitium.com/dns/apps/SplitHorizonApp.zip","size":"11.1 KB","installed":true,"installedVersion":"1.1","updateAvailable":true}]}`)
	fake.Answer("apps/downloadAndInstall", `{"installedApp":`+app+`}`)
	fake.Answer("apps/downloadAndUpdate", `{"updatedApp":`+app+`}`)
	fake.Answer("apps/install", `{"installedApp":`+app+`}`)
	fake.Answer("apps/update", `{"updatedApp":`+app+`}`)
	fake.Answer("apps/uninstall", `{}`)
	fake.Answer("apps/config/set", `{}`)
	fake.AnswerWhole("dnsClient/healthCheck", `{"server":"ns1.example","status":"ok"}`)
	c := client(t, fake)

	store, err := c.StoreApps(t.Context())
	if err != nil || len(store) != 2 {
		t.Fatalf("StoreApps = %+v, %v", store, err)
	}
	if a := store[0]; a.Name != "Geo Continent" || a.Version != "1.1" || a.Size != "2.01 MB" || a.Installed || a.URL == "" || a.Description == "" {
		t.Errorf("an app not installed = %+v", a)
	}
	if a := store[1]; !a.Installed || a.InstalledVersion != "1.1" || !a.UpdateAvailable {
		t.Errorf("an app with an update = %+v", a)
	}

	const from = "https://download.technitium.com/dns/apps/WildIpApp.zip"
	got, err := c.InstallAppFrom(t.Context(), "Wild IP", from)
	if asked := fake.Last("apps/downloadAndInstall"); err != nil || got.Name != "Wild IP" || got.Version != "1.0" || len(got.Parts) != 1 || got.Parts[0].ClassPath != "WildIp.App" || asked.Method != http.MethodPost || len(asked.Params) != 2 || asked.Params.Get("name") != "Wild IP" || asked.Params.Get("url") != from {
		t.Errorf("InstallAppFrom = %+v, %v, sent %v", got, err, asked.Params)
	}
	got, err = c.UpdateAppFrom(t.Context(), "Wild IP", from)
	if asked := fake.Last("apps/downloadAndUpdate"); err != nil || got.Name != "Wild IP" || asked.Method != http.MethodPost || asked.Params.Get("name") != "Wild IP" || asked.Params.Get("url") != from {
		t.Errorf("UpdateAppFrom = %+v, %v, sent %v", got, err, asked.Params)
	}

	// a zip file is sent as a file, and the app's name beside it in the address
	zip := []byte("PK\x03\x04 an app")
	got, err = c.InstallApp(t.Context(), "Wild IP", zip)
	if asked := fake.Last("apps/install"); err != nil || got.Name != "Wild IP" || asked.Method != http.MethodPost || !bytes.Equal(asked.File, zip) || asked.FileName != "Wild IP.zip" || len(asked.Params) != 1 || asked.Params.Get("name") != "Wild IP" {
		t.Errorf("InstallApp = %+v, %v, sent %q with %v", got, err, asked.File, asked.Params)
	}
	got, err = c.UpdateApp(t.Context(), "Wild IP", zip)
	if asked := fake.Last("apps/update"); err != nil || got.Name != "Wild IP" || !bytes.Equal(asked.File, zip) || asked.Params.Get("name") != "Wild IP" {
		t.Errorf("UpdateApp = %+v, %v, sent %q with %v", got, err, asked.File, asked.Params)
	}

	if err := c.SetAppConfig(t.Context(), "Wild IP", `{"enable":true}`); err != nil {
		t.Fatal(err)
	}
	if asked := fake.Last("apps/config/set"); asked.Method != http.MethodPost || len(asked.Params) != 2 || asked.Params.Get("name") != "Wild IP" || asked.Params.Get("config") != `{"enable":true}` {
		t.Errorf("the app's configuration was set with %v", asked.Params)
	}
	// an empty configuration is one all the same: it is how an app's is cleared
	if err := c.SetAppConfig(t.Context(), "Wild IP", ""); err != nil || !fake.Last("apps/config/set").Params.Has("config") {
		t.Errorf("the app's configuration was cleared with %v, %v", fake.Last("apps/config/set").Params, err)
	}
	if err := c.UninstallApp(t.Context(), "Wild IP"); err != nil || fake.Last("apps/uninstall").Method != http.MethodPost || fake.Last("apps/uninstall").Params.Get("name") != "Wild IP" {
		t.Errorf("UninstallApp = %v, sent %v", err, fake.Last("apps/uninstall").Params)
	}

	if err := c.HealthCheck(t.Context(), "", ""); err != nil || len(fake.Last("dnsClient/healthCheck").Params) != 0 {
		t.Errorf("HealthCheck = %v, asked with %v", err, fake.Last("dnsClient/healthCheck").Params)
	}
	if err := c.HealthCheck(t.Context(), "example.com", "AAAA"); err != nil || fake.Last("dnsClient/healthCheck").Params.Get("domain") != "example.com" || fake.Last("dnsClient/healthCheck").Params.Get("type") != "AAAA" {
		t.Errorf("HealthCheck = %v, asked with %v", err, fake.Last("dnsClient/healthCheck").Params)
	}
	fake.Fail("dnsClient/healthCheck", "error", "DNS Server failed to resolve the request")
	if err := c.HealthCheck(t.Context(), "", ""); err == nil {
		t.Error("a server that cannot resolve passed its health check")
	}

	refused := map[string]error{"no app's configuration": c.SetAppConfig(t.Context(), "", "{}"), "no app uninstalled": c.UninstallApp(t.Context(), "")}
	_, refused["an app from an address not over https"] = c.InstallAppFrom(t.Context(), "Wild IP", "http://example.com/app.zip")
	_, refused["no app installed from an address"] = c.InstallAppFrom(t.Context(), "", from)
	_, refused["an app updated from no address"] = c.UpdateAppFrom(t.Context(), "Wild IP", "")
	_, refused["an app with no name"] = c.InstallApp(t.Context(), "", zip)
	_, refused["an app with no file"] = c.InstallApp(t.Context(), "Wild IP", nil)
	_, refused["an app from what is no zip file"] = c.InstallApp(t.Context(), "Wild IP", []byte("not a zip file"))
	_, refused["an app updated from what is no zip file"] = c.UpdateApp(t.Context(), "Wild IP", []byte("not a zip file"))
	_, refused["no app updated"] = c.UpdateApp(t.Context(), "", zip)
	for what, err := range refused {
		if err == nil {
			t.Errorf("%s: no error", what)
		}
	}
	if len(fake.Requests("apps/config/set")) != 2 || len(fake.Requests("apps/uninstall")) != 1 || len(fake.Requests("apps/downloadAndInstall")) != 1 || len(fake.Requests("apps/downloadAndUpdate")) != 1 || len(fake.Requests("apps/install")) != 1 || len(fake.Requests("apps/update")) != 1 {
		t.Error("a refused call reached the server")
	}
}
