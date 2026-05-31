// Package integration holds netctl's black-box integration tests, which are
// compiled and run with the `integration` build tag against the dev stack
// (deploy/compose/dev.yml). The tagged test files arrive in S6+.
//
// This file carries no build tag so the package is always present to the Go
// toolchain (otherwise a default `go test ./...` would fail with
// "build constraints exclude all Go files").
package integration
