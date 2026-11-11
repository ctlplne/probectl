// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCapacityBillingCalendarUsesWholeLocalMonthsDSTLeapAndClampedDays(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		for _, test := range []struct {
			zone, at, from, to string
			day                int
		}{
			{"UTC", "2024-02-29T12:00:00Z", "2024-02-29T00:00:00Z", "2024-03-31T00:00:00Z", 31},
			{"UTC", "2025-02-27T12:00:00Z", "2025-01-31T00:00:00Z", "2025-02-28T00:00:00Z", 31},
			{"America/New_York", "2026-03-20T12:00:00Z", "2026-03-01T05:00:00Z", "2026-04-01T04:00:00Z", 1},
			{"America/New_York", "2026-11-20T12:00:00Z", "2026-11-01T04:00:00Z", "2026-12-01T05:00:00Z", 1},
			{"Asia/Kathmandu", "2026-01-15T12:00:00Z", "2026-01-14T18:15:00Z", "2026-02-14T18:15:00Z", 15},
			{"America/Sao_Paulo", "2018-11-10T12:00:00Z", "2018-11-04T03:00:00Z", "2018-12-04T02:00:00Z", 4},
			{"Pacific/Apia", "2011-12-31T12:00:00Z", "2011-12-30T10:00:00Z", "2012-01-29T10:00:00Z", 30},
			{"America/Havana", "2020-11-02T12:00:00Z", "2020-11-01T04:00:00Z", "2020-12-01T05:00:00Z", 1},
		} {
			at, err := time.Parse(time.RFC3339, test.at)
			if err != nil {
				t.Fatal(err)
			}
			got, err := capacityBillingPeriodAt(ctx, capacityBillingCalendar{tenant: tenant, timezone: test.zone, day: test.day}, at, 8<<20, 8<<20)
			if err != nil || got.from.Format(time.RFC3339) != test.from || got.to.Format(time.RFC3339) != test.to || got.tenant != tenant || got.timezone != test.zone || got.requestedDay != test.day || got.boundaryPolicy != "first_valid_local_instant" {
				t.Fatal("billing calendar lost civil boundaries, whole period or tenant", test, got, err)
			}
			// Exactly at the exclusive end belongs to the following period.
			next, err := capacityBillingPeriodAt(ctx, capacityBillingCalendar{tenant: tenant, timezone: test.zone, day: test.day}, got.to, 8<<20, 8<<20)
			if err != nil || !next.from.Equal(got.to) || !next.to.After(next.from) {
				t.Fatal("boundary instant was billed twice or omitted", test, next, err)
			}
		}
	}
}

func TestCapacityBillingCalendarRequiresTenantAndFiniteWholeOperation(t *testing.T) {
	calendar := capacityBillingCalendar{tenant: "red", timezone: "UTC", day: 1}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if got, err := capacityBillingPeriodAt(t.Context(), calendar, at, 8<<20, 8<<20); !errors.Is(err, tenancy.ErrNoTenant) || !reflect.DeepEqual(got, capacityBillingPeriod{}) {
		t.Fatal("calendar calculation preceded tenant scope", got, err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("blue"))
	if got, err := capacityBillingPeriodAt(ctx, calendar, at, 8<<20, 8<<20); err == nil || !reflect.DeepEqual(got, capacityBillingPeriod{}) {
		t.Fatal("calendar inherited a foreign tenant agreement", got, err)
	}
	ctx = tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	for _, alter := range []func(*capacityBillingCalendar){func(c *capacityBillingCalendar) { c.day = 0 }, func(c *capacityBillingCalendar) { c.day = 32 }, func(c *capacityBillingCalendar) { c.timezone = "unknown-zone" }, func(c *capacityBillingCalendar) { c.timezone = "Local" }} {
		bad := calendar
		alter(&bad)
		if got, err := capacityBillingPeriodAt(ctx, bad, at, 8<<20, 8<<20); err == nil || !reflect.DeepEqual(got, capacityBillingPeriod{}) {
			t.Fatal("incomplete calendar invented a billing period", bad, got, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := capacityBillingPeriodAt(canceled, calendar, at, 8<<20, 8<<20); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled calendar operation completed", err)
	}
}
