// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"strings"
	"time"
	_ "time/tzdata" // Offline IANA fallback in minimal/air-gapped images.

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Calendar facts are private calculation inputs, not an agreement read grant.
// The operator's monthly day is clamped independently in each short month.
type capacityBillingCalendar struct {
	tenant, timezone string
	day              int
}

type capacityBillingPeriod struct {
	tenant, timezone string
	requestedDay     int
	from, to         time.Time // Inclusive start, exclusive end, both exact UTC instants.
	boundaryPolicy   string
}

func capacityBillingPeriodAt(ctx context.Context, calendar capacityBillingCalendar, at time.Time, memoryBytes, workUnits int64) (capacityBillingPeriod, error) {
	none := capacityBillingPeriod{}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return none, tenancy.ErrNoTenant
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if calendar.tenant == "" || calendar.tenant != tenant.String() || calendar.day < 1 || calendar.day > 31 || at.IsZero() || calendar.timezone == "" || calendar.timezone == "Local" || strings.TrimSpace(calendar.timezone) != calendar.timezone || memoryBytes < 1<<20 || workUnits < 4096 || int64(len(calendar.timezone)) > (memoryBytes-(1<<20))/32 {
		return none, errCapacityCounterInput
	}
	location, err := time.LoadLocation(calendar.timezone)
	if err != nil {
		return none, errCapacityCounterInput
	}
	year, month, _ := at.In(location).Date()
	for {
		from, err := capacityCivilBillingBoundary(ctx, location, year, month, calendar.day, &workUnits)
		if err != nil {
			return none, err
		}
		next := time.Date(year, month+1, 1, 12, 0, 0, 0, time.UTC)
		to, err := capacityCivilBillingBoundary(ctx, location, next.Year(), next.Month(), calendar.day, &workUnits)
		if err != nil {
			return none, err
		}
		if !to.After(from) {
			return none, errCapacityCounterInput
		}
		if at.Before(from) {
			previous := time.Date(year, month-1, 1, 12, 0, 0, 0, time.UTC)
			year, month = previous.Year(), previous.Month()
			continue
		}
		if !at.Before(to) {
			year, month = next.Year(), next.Month()
			continue
		}
		if err := ctx.Err(); err != nil {
			return none, err
		}
		return capacityBillingPeriod{tenant: calendar.tenant, timezone: calendar.timezone, requestedDay: calendar.day, from: from.UTC(), to: to.UTC(), boundaryPolicy: "first_valid_local_instant"}, nil
	}
}

func capacityCivilBillingBoundary(ctx context.Context, location *time.Location, year int, month time.Month, day int, work *int64) (time.Time, error) {
	lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	wall := time.Date(year, month, min(day, lastDay), 0, 0, 0, 0, time.UTC)
	return calendarWallInstant(ctx, location, wall, work)
}

func calendarWallInstant(ctx context.Context, location *time.Location, wall time.Time, work *int64) (time.Time, error) {
	// TZif encodes UTC offsets as signed 32-bit seconds. Search its full
	// representable offset domain, not a guessed +/-24h window or a timezone
	// allowlist. ZoneBounds skips directly between actual transitions.
	// A repeated midnight selects its first occurrence; a missing midnight or
	// an entirely skipped civil date selects the first valid following instant.
	offsetDomain := time.Duration(1<<31) * time.Second
	cursor, limit := wall.Add(-offsetDomain), wall.Add(offsetDomain)
	for !cursor.After(limit) {
		if err := ctx.Err(); err != nil {
			return time.Time{}, err
		}
		if *work <= 0 {
			return time.Time{}, errCapacityCounterInput
		}
		*work--
		local := cursor.In(location)
		_, offset := local.Zone()
		_, end := local.ZoneBounds()
		candidate := wall.Add(-time.Duration(offset) * time.Second)
		if candidate.Before(cursor) {
			candidate = cursor
		}
		if (end.IsZero() || candidate.Before(end)) && !candidate.After(limit) {
			return candidate, nil
		}
		if end.IsZero() || !end.After(cursor) {
			return time.Time{}, errCapacityCounterInput
		}
		cursor = end
	}
	return time.Time{}, errCapacityCounterInput
}

// CalendarBoundary shares billing's deterministic civil-time rules with report
// periods. It performs no tenant/state read and conveys no source authority.
func CalendarBoundary(ctx context.Context, timezone string, year int, month time.Month, day int, workUnits int64) (time.Time, error) {
	location, err := calendarLocation(timezone, workUnits)
	if err != nil || year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 {
		return time.Time{}, errCapacityCounterInput
	}
	return capacityCivilBillingBoundary(ctx, location, year, month, day, &workUnits)
}

// CalendarMonthOffset keeps the local wall clock and clamps the original day
// independently in the destination month. DST gaps use the first following
// instant; repeated wall times use their first occurrence, as billing does.
func CalendarMonthOffset(ctx context.Context, at time.Time, months int, timezone string, workUnits int64) (time.Time, error) {
	location, err := calendarLocation(timezone, workUnits)
	if err != nil || at.IsZero() || months < 1 {
		return time.Time{}, errCapacityCounterInput
	}
	local := at.In(location)
	if months > (9999-local.Year())*12+12-int(local.Month()) {
		return time.Time{}, errCapacityCounterInput
	}
	month := time.Date(local.Year(), local.Month()+time.Month(months), 1, 12, 0, 0, 0, time.UTC)
	lastDay := time.Date(month.Year(), month.Month()+1, 0, 12, 0, 0, 0, time.UTC).Day()
	wall := time.Date(month.Year(), month.Month(), min(local.Day(), lastDay), local.Hour(), local.Minute(), local.Second(), local.Nanosecond(), time.UTC)
	return calendarWallInstant(ctx, location, wall, &workUnits)
}

func calendarLocation(timezone string, work int64) (*time.Location, error) {
	if timezone == "" || timezone == "Local" || strings.TrimSpace(timezone) != timezone || work <= 0 || int64(len(timezone)) > work {
		return nil, errCapacityCounterInput
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, errCapacityCounterInput
	}
	return location, nil
}
