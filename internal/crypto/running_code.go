// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import "errors"

// ErrRunningCodeIdentityUnavailable means the running image cannot provide
// executable evidence for a managed endpoint rollout.
var ErrRunningCodeIdentityUnavailable = errors.New("running code identity unavailable")
