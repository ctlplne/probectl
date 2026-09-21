// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package schema holds offline schema-hygiene lints (e.g. the SCHEMA-006 proto
// reserved-tag gap check). It carries no production code — only test-time
// guards that read committed schema sources and fail the build on a policy
// violation. The package exists so those guards have a home that the toolchain
// builds; see the *_test.go files for the actual lints.
package schema
