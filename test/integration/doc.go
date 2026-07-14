// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package integration holds probectl's black-box integration tests, which are
// compiled and run with the `integration` build tag against the dev stack
// (deploy/compose/dev.yml). The tagged test files arrive in S6+.
//
// This file carries no build tag so the package is always present to the Go
// toolchain (otherwise a default `go test ./...` would fail with
// "build constraints exclude all Go files").
package integration
