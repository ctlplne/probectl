// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build !probectl_fips

package crypto

// fipsBuildTag is false in the standard (non-FIPS) build. The power-on
// self-test still runs its known-answer tests here (good hygiene, and it
// proves the S3 interface produces identical, standardized outputs whether or
// not FIPS is compiled in — the transparent-swap property), but it does not
// require the validated module to be active.
const fipsBuildTag = false
