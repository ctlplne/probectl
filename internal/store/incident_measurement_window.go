// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import "time"

// Retained observation clocks are Postgres microsecond points. For the exact
// public half-open [from,to) predicate, both SQL bounds must be the first
// representable microsecond at or after the supplied instant. Letting the
// driver truncate to loses an included point; truncating from adds an older
// one. Only query parameters change, never observations or the public window.
func incidentMeasurementSQLWindow(from, to time.Time) (time.Time, time.Time) {
	ceil := func(at time.Time) time.Time {
		point := at.UTC().Truncate(time.Microsecond)
		if point.Before(at) {
			return point.Add(time.Microsecond)
		}
		return point
	}
	return ceil(from), ceil(to)
}
