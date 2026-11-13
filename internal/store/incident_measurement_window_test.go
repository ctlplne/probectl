// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"testing"
	"time"
)

func TestIncidentMeasurementSQLWindowPreservesEveryDiscretePoint(t *testing.T) {
	for _, base := range []time.Time{time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC), time.Date(1969, 12, 31, 23, 59, 59, 999999000, time.UTC)} {
		for left := -1500; left <= 1500; left += 250 {
			for right := left + 1; right <= 1500; right += 251 {
				from, to := base.Add(time.Duration(left)), base.Add(time.Duration(right))
				sqlFrom, sqlTo := incidentMeasurementSQLWindow(from, to)
				for step := -2; step <= 2; step++ {
					point := base.Add(time.Duration(step) * time.Microsecond)
					want := !point.Before(from) && point.Before(to)
					got := !point.Before(sqlFrom) && point.Before(sqlTo)
					if got != want {
						t.Fatalf("window[%s,%s) changed membership of%s", from, to, point)
					}
				}
			}
		}
	}
}
