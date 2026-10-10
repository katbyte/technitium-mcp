package technitium

import (
	"slices"
	"testing"

	"github.com/katbyte/technitium-mcp/sdk/apidoc"
)

// The calls the client passes on to another node are the ones the API
// document gives a node parameter, no more and none missing.
func TestNodeCallsAreTheDocuments(t *testing.T) {
	t.Parallel()

	doc, err := apidoc.Vendored()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSorted(nodeCalls) {
		t.Error("nodeCalls is not sorted")
	}
	for _, path := range nodeCalls {
		call := doc.Call(path)
		switch {
		case call == nil:
			t.Errorf("nodeCalls has %s, which the document does not have", path)
		case !call.Takes("node"):
			t.Errorf("nodeCalls has %s, which the document gives no node parameter", path)
		default:
		}
	}
	for _, path := range doc.Paths() {
		if doc.Call(path).Takes("node") && !slices.Contains(nodeCalls, path) {
			t.Errorf("the document gives %s a node parameter, and nodeCalls does not have it", path)
		}
	}
}

// What is secret is taken out of the settings wherever it sits, and what is
// beside it is kept.
func TestWithoutSecrets(t *testing.T) {
	t.Parallel()

	settings := map[string]any{"version": "15.6", "webServiceTlsCertificatePassword": "x", "proxy": map[string]any{"address": "192.0.2.9", "Password": "x"}, "tsigKeys": []any{map[string]any{"keyName": "home", "sharedSecret": "x"}, "text"}, "ssoClientSecret": "x"}
	withoutSecrets(settings)

	proxy, isObject := settings["proxy"].(map[string]any)
	keys, isList := settings["tsigKeys"].([]any)
	if !isObject || !isList || len(keys) != 2 {
		t.Fatalf("the settings without what is secret = %v", settings)
	}
	first, isObject := keys[0].(map[string]any)
	if !isObject || len(settings) != 3 || settings["version"] != "15.6" || len(proxy) != 1 || proxy["address"] != "192.0.2.9" || len(first) != 1 || first["keyName"] != "home" || keys[1] != "text" {
		t.Errorf("the settings without what is secret = %v", settings)
	}
}
