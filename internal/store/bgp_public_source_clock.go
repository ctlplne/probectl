// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import "time"

// publicSnapshotDataLease is freshness admission, never source authority. A
// current collector credential/assignment must independently authorize access.
// maxAge is server/operator policy, never supplied by a source frame.
func publicSnapshotDataLease(sourceClock *int64, asOf, captureLease, authorityLease time.Time, maxAge time.Duration) (time.Time, error) {
	if maxAge <= 0 {
		return time.Time{}, ErrBGPRoutingBudget
	}
	if sourceClock == nil || *sourceClock < 0 || asOf.IsZero() {
		return time.Time{}, ErrBGPRoutingSourceUnavailable
	}
	origin := time.Unix(0, *sourceClock)
	if origin.After(asOf) {
		return time.Time{}, ErrBGPRoutingSourceUnavailable
	}
	until := origin.Add(maxAge)
	for _, limit := range []time.Time{captureLease, authorityLease} {
		if limit.Before(until) {
			until = limit
		}
	}
	if !until.After(asOf) {
		return time.Time{}, ErrBGPRoutingSourceUnavailable
	}
	return until, nil
}
