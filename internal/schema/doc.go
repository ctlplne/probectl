// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package schema holds offline schema-hygiene lints (e.g. the SCHEMA-006 proto
// reserved-tag gap check). It carries no production code — only test-time
// guards that read committed schema sources and fail the build on a policy
// violation. The package exists so those guards have a home that the toolchain
// builds; see the *_test.go files for the actual lints.
package schema
