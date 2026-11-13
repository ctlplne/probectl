// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
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

// ClientReportPeriod preserves exact absolute bounds plus their civil meaning.
// Month-to-date is always partial; it never becomes a completed-month claim.
type ClientReportPeriod struct {
	From, To              time.Time
	Timezone, Kind, Month string
	Partial               bool
}

// ResolveClientReportPeriod uses the existing offline calendar implementation,
// including skipped/repeated civil instants, instead of approximating days.
func ResolveClientReportPeriod(ctx context.Context, definition ClientReportDefinition, at time.Time) (ClientReportPeriod, error) {
	none := ClientReportPeriod{}
	if at.IsZero() {
		return none, ErrClientReportMonth
	}
	zone := definition.Timezone
	if zone == "" {
		zone = "UTC"
	}
	if zone == "Local" {
		return none, ErrClientReportMonth
	}
	location, err := time.LoadLocation(zone)
	if err != nil {
		return none, ErrClientReportMonth
	}
	kind := definition.Period
	if kind == "" {
		kind = "completed_month"
	}
	if kind != "completed_month" && kind != "month_to_date" {
		return none, ErrClientReportMonth
	}
	if zone == "UTC" && kind == "completed_month" {
		from, to, err := ClientReportMonth(definition.Month, at)
		if err != nil {
			return none, err
		}
		return ClientReportPeriod{From: from, To: to, Timezone: zone, Kind: kind, Month: from.Format("2006-01")}, nil
	}
	local := at.In(location)
	year, month, _ := local.Date()
	selected := definition.Month
	if selected != "" {
		parsed, err := time.Parse("2006-01", selected)
		if err != nil || parsed.Year() < 1 || parsed.Format("2006-01") != selected {
			return none, ErrClientReportMonth
		}
		year, month = parsed.Year(), parsed.Month()
	} else if kind == "completed_month" {
		previous := time.Date(year, month-1, 1, 12, 0, 0, 0, time.UTC)
		year, month = previous.Year(), previous.Month()
	}
	if kind == "month_to_date" && (year != local.Year() || month != local.Month()) {
		return none, ErrClientReportMonth
	}
	from, err := flow.CalendarBoundary(ctx, zone, year, month, 1, 4096)
	if err != nil {
		return none, ErrClientReportMonth
	}
	var to time.Time
	if kind == "month_to_date" {
		to = at.UTC()
	} else {
		next := time.Date(year, month+1, 1, 12, 0, 0, 0, time.UTC)
		to, err = flow.CalendarBoundary(ctx, zone, next.Year(), next.Month(), 1, 4096)
	}
	if err != nil || !to.After(from) || to.After(at) {
		return none, ErrClientReportMonth
	}
	return ClientReportPeriod{From: from.UTC(), To: to.UTC(), Timezone: zone, Kind: kind, Month: time.Date(year, month, 1, 0, 0, 0, 0, time.UTC).Format("2006-01"), Partial: kind == "month_to_date"}, nil
}
