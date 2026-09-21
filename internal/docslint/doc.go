// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package docslint holds doc-accuracy tests — assertions that the operations
// docs do not over-claim capabilities the code does not ship (e.g. RESIL-003:
// the multi-region doc must not imply ClickHouse replicates cross-region like
// Postgres). It carries no runtime code; the package exists so the test files
// have a home and so `go build ./...` (and the editions-gate core-only build)
// see a non-test Go file here.
package docslint
