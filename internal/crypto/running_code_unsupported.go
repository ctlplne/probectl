// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build !windows && (!darwin || !cgo)

package crypto

// RunningCodeIdentity treats an unavailable native measurement as missing
// evidence for a managed endpoint rollout.
func RunningCodeIdentity() (string, error) {
	return "", ErrRunningCodeIdentityUnavailable
}
