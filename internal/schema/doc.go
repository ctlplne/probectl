// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package schema holds offline schema-hygiene lints (e.g. the SCHEMA-006 proto
// reserved-tag gap check). It carries no production code — only test-time
// guards that read committed schema sources and fail the build on a policy
// violation. The package exists so those guards have a home that the toolchain
// builds; see the *_test.go files for the actual lints.
package schema
