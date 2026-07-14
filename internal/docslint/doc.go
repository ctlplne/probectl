// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package docslint holds doc-accuracy tests — assertions that the operations
// docs do not over-claim capabilities the code does not ship (e.g. RESIL-003:
// the multi-region doc must not imply ClickHouse replicates cross-region like
// Postgres). It carries no runtime code; the package exists so the test files
// have a home and so `go build ./...` (and the editions-gate core-only build)
// see a non-test Go file here.
package docslint
