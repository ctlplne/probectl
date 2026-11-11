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
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func capacityAgreementFixture() CapacityAgreementDefinition {
	return CapacityAgreementDefinition{Name: "WAN contract", Reference: "operator-recorded terms", ValidFrom: "2026-11-01T05:45:00.123456789+05:45", Target: CapacityTarget{Kind: "interface", ContextID: "22222222-2222-4222-8222-222222222222", InterfaceID: "33333333-3333-4333-8333-333333333333"}, BillingDay: 31, Timezone: "Asia/Kathmandu", Direction: string(capacityBillingMaxPercentiles), Currency: "USD", CommitBPS: "1000000000", UnitBPS: "1000000", UnitPrice: "1.250000000000000001"}
}

func TestCapacityAgreementRejectsIncompleteTermsAndContradictoryTargets(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		for _, change := range []func(*CapacityAgreementDefinition){
			func(d *CapacityAgreementDefinition) { d.Name = "" },
			func(d *CapacityAgreementDefinition) { d.Reference = "hidden\x00suffix" },
			func(d *CapacityAgreementDefinition) { d.Currency = "\nUSD" },
			func(d *CapacityAgreementDefinition) { d.Timezone = "Local" },
			func(d *CapacityAgreementDefinition) { d.Timezone = "unknown/timezone" },
			func(d *CapacityAgreementDefinition) { d.ValidFrom = "not a date" },
			func(d *CapacityAgreementDefinition) { d.BillingDay = 0 },
			func(d *CapacityAgreementDefinition) { d.Direction = "implicit" },
			func(d *CapacityAgreementDefinition) { d.CommitBPS = "-1" },
			func(d *CapacityAgreementDefinition) { d.UnitBPS = "0" },
			func(d *CapacityAgreementDefinition) { d.UnitPrice = "NaN" },
			func(d *CapacityAgreementDefinition) { d.Target.ContextID = "not a UUID" },
			func(d *CapacityAgreementDefinition) { d.Target.TagID = "44444444-4444-4444-8444-444444444444" },
			func(d *CapacityAgreementDefinition) {
				d.Target = CapacityTarget{Kind: "circuit", TagID: "44444444-4444-4444-8444-444444444444"}
			},
			func(d *CapacityAgreementDefinition) { d.Target.Kind = "implicit all interfaces" },
		} {
			input := capacityAgreementFixture()
			change(&input)
			got, err := NormalizeCapacityAgreement(ctx, input, 8<<20, 8<<20)
			if !errors.Is(err, ErrCapacityAgreementInvalid) || !reflect.DeepEqual(got, CapacityAgreementDefinition{}) {
				t.Fatal("incomplete financial terms or target became recorded configuration", input, got, err)
			}
		}
	}
}

func TestCapacityAgreementStorageErrorsWithholdBackendDetails(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{{"23503", ErrCapacityAgreementNotFound}, {"23505", ErrCapacityAgreementConflict}, {"23514", ErrCapacityAgreementInvalid}, {"22P02", ErrCapacityAgreementInvalid}, {"22003", ErrCapacityAgreementInvalid}, {"42501", nil}, {"XX000", nil}} {
		backend := &pgconn.PgError{Code: tc.code, Message: "private financial reference", Detail: "private unit rate and tenant"}
		err := capacityAgreementStorageError(backend)
		if err == nil || tc.want != nil && !errors.Is(err, tc.want) || strings.Contains(err.Error(), "private") {
			t.Fatal("financial storage error exposed backend values or lost its domain meaning", tc.code, err)
		}
	}
	if err := capacityAgreementStorageError(pgx.ErrNoRows); !errors.Is(err, ErrCapacityAgreementNotFound) {
		t.Fatal("missing or unreadable agreement lost not-found semantics", err)
	}
	if err := capacityAgreementStorageError(context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("operation cancellation became a successful storage result", err)
	}
}

func TestCapacityAgreementEffectiveDatesKeepFullCalendarNanoseconds(t *testing.T) {
	for _, tc := range []struct{ date, nanos string }{
		{"1970-01-01T00:00:00.123456789Z", "123456789"},
		{"1969-12-31T23:59:59.999999999Z", "-1"},
		{"2500-01-01T00:00:00.123456789Z", "16725225600123456789"},
		{"9999-12-31T23:59:59.999999999Z", "253402300799999999999"},
	} {
		at, err := time.Parse(time.RFC3339Nano, tc.date)
		if err != nil || capacityAgreementNanos(at) != tc.nanos {
			t.Fatal("effective agreement time was narrowed to an epoch int64 or microseconds", tc, err)
		}
	}
}

func TestCapacityAgreementDefinitionKeepsFullTargetsTermsPrecisionAndTenantBoundary(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		input := capacityAgreementFixture()
		got, err := NormalizeCapacityAgreement(ctx, input, 8<<20, 8<<20)
		if err != nil || got.Target != input.Target || got.CommitBPS != input.CommitBPS || got.UnitPrice != input.UnitPrice || got.ValidFrom != "2026-11-01T00:00:00.123456789Z" || got.BillingDay != 31 || got.Direction != input.Direction {
			t.Fatal("operator terms or nanosecond effective date were narrowed", got, err)
		}
		input.Target = CapacityTarget{Kind: "circuit", TagID: "44444444-4444-4444-8444-444444444444", TagValue: strings.Repeat("線", 24000)}
		input.UnitPrice = "-0.000000000000000001"
		got, err = NormalizeCapacityAgreement(ctx, input, 32<<20, 32<<20)
		if err != nil || got.Target != input.Target || got.UnitPrice != input.UnitPrice {
			t.Fatal("complete circuit value or recorded credit rate was shortened", err)
		}
	}
	if _, err := NormalizeCapacityAgreement(t.Context(), capacityAgreementFixture(), 8<<20, 8<<20); err == nil {
		t.Fatal("agreement normalization preceded its tenant boundary")
	}
}
