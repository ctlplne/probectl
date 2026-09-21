// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package integration holds probectl's black-box integration tests, which are
// compiled and run with the `integration` build tag against the dev stack
// (deploy/compose/dev.yml). The tagged test files arrive in S6+.
//
// This file carries no build tag so the package is always present to the Go
// toolchain (otherwise a default `go test ./...` would fail with
// "build constraints exclude all Go files").
package integration
