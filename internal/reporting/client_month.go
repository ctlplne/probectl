// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"errors"
	"time"
)

var ErrClientReportMonth = errors.New("a completed UTC calendar month in YYYY-MM form is required")

// ClientReportMonth resolves a whole calendar month, never a fixed thirty-day
// approximation or the generation machine's local timezone. An empty selection
// means the most recently completed month. Current/future months cannot be
// presented as complete monthly client reports.
func ClientReportMonth(selection string, at time.Time) (time.Time, time.Time, error) {
	if at.IsZero() {
		return time.Time{}, time.Time{}, ErrClientReportMonth
	}
	at = at.UTC()
	current := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
	if selection == "" {
		return current.AddDate(0, -1, 0), current, nil
	}
	from, err := time.Parse("2006-01", selection)
	if err != nil || from.Year() < 1 || from.Format("2006-01") != selection {
		return time.Time{}, time.Time{}, ErrClientReportMonth
	}
	to := from.AddDate(0, 1, 0)
	if to.After(at) {
		return time.Time{}, time.Time{}, ErrClientReportMonth
	}
	return from, to, nil
}
