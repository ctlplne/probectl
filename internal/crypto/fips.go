// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build probectl_fips

package crypto

// fipsBuildTag is true in the FIPS distribution artifact (built with
// -tags probectl_fips). It is the DISTRIBUTION marker — the editions
// decision: the FIPS build is gated by the artifact, never a runtime license
// check. Activating the validated module itself is orthogonal (GOFIPS140 at
// build time, or GODEBUG=fips140=on at runtime); the power-on self-test
// asserts the module is actually live in this build and fails closed if not.
const fipsBuildTag = true
