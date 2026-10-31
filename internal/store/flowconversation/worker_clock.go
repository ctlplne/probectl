// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import "time"

// sent precedes the SQL update and retains the process's monotonic clock.
// Anchoring the authoritative remaining duration there can expire early after
// network/lock latency; it never adds that latency or remote wall-clock skew to
// the last confirmed lease. It is an IO fence, not a storage/renewal capability.
func projectFlowLeaseDeadline(sent, databaseClock, until time.Time, requested time.Duration) (time.Time, error) {
	remaining := until.Sub(databaseClock)
	if sent.IsZero() || databaseClock.IsZero() || until.IsZero() || requested <= 0 || remaining <= 0 || remaining > requested {
		return time.Time{}, ErrJournalLease
	}
	return sent.Add(remaining), nil
}
