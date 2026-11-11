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
