// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build probectl_fips

package crypto

// fipsBuildTag is true in the FIPS distribution artifact (built with
// -tags probectl_fips). It is the DISTRIBUTION marker — the editions
// decision: the FIPS build is gated by the artifact, never a runtime license
// check. Activating the validated module itself is orthogonal (GOFIPS140 at
// build time, or GODEBUG=fips140=on at runtime); the power-on self-test
// asserts the module is actually live in this build and fails closed if not.
const fipsBuildTag = true
