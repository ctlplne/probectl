// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package docslint holds doc-accuracy tests — assertions that the operations
// docs do not over-claim capabilities the code does not ship (e.g. RESIL-003:
// the multi-region doc must not imply ClickHouse replicates cross-region like
// Postgres). It carries no runtime code; the package exists so the test files
// have a home and so `go build ./...` (and the editions-gate core-only build)
// see a non-test Go file here.
package docslint
