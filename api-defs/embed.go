// Package apidefs holds the Technitium API document vendored beside it, and
// the list of the calls it describes that sdk/technitium does not wrap yet,
// for the tests that hold the client against them (see README.md here, and
// sdk/apidoc, which reads the document). Nothing the binary is built from
// imports it.
package apidefs

import "embed"

// Docs are the vendored documents, each named technitium-apidocs-<version>.md
// for the server version it describes.
//
//go:embed technitium-apidocs-*.md
var Docs embed.FS

// Unwrapped is the path of every call in the document that sdk/technitium has
// no method for yet, one a line.
//
//go:embed unwrapped.txt
var Unwrapped string

// Unsent is every parameter in the document that no test of sdk/technitium
// sends, each as its call's path and its name on a line, with why.
//
//go:embed unsent.txt
var Unsent string
