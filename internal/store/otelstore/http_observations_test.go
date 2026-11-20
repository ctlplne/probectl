// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otelstore

import (
	"errors"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHTTPObservationReadKeepsCompleteScopedWindowBeyondTraceSearchLimit(t *testing.T) {
	store := NewMemory()
	owner := tenancy.WithTenant(t.Context(), "health-owner")
	other := tenancy.WithTenant(t.Context(), "other-owner")
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	q := SpanQuery{Service: "site", Since: start, Until: start.Add(5 * time.Second),
		HTTPServer: &HTTPServerTarget{Address: netip.MustParseAddr("192.0.2.1"), Port: 443}}
	base := Span{TenantID: "health-owner", Service: q.Service, Kind: "server", Start: start,
		TraceID: "observation", Duration: time.Millisecond, Attrs: map[string]string{
			"server.address": "192.0.2.1", "server.port": "443", "http.response.status_code": "200", "unneeded": "hidden",
		}}
	rows := make([]Span, 0, httpObservationLimit+2)
	for i := range httpObservationLimit - 1 {
		span := base
		span.SpanID = strconv.Itoa(i)
		rows = append(rows, span)
	}
	foreign, adjacent, port := base, base, base
	foreign.TenantID, foreign.SpanID = "other-owner", "foreign"
	adjacent.Start, adjacent.SpanID = q.Until, "next-window"
	port.SpanID = "other-port"
	port.Attrs = httpObservationAttributes("192.0.2.1", "8443", "200")
	rows = append(rows, foreign, adjacent, port)
	if err := store.WriteSpans(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	got, err := ReadHTTPObservations(owner, store, "health-owner", q)
	if err != nil || len(got) != httpObservationLimit-1 || len(got[0].Attrs) != 3 || got[0].Attrs["unneeded"] != "" {
		t.Fatalf("the scoped HTTP evidence lost its population or field boundary: %d rows, %v", len(got), err)
	}
	for _, row := range got {
		if row.TenantID != "health-owner" || !row.Start.Equal(start) || row.Attrs["server.port"] != "443" {
			t.Fatal("an observation escaped the exact tenant, port or clock scope")
		}
	}
	if got, err := ReadHTTPObservations(other, store, "health-owner", q); got != nil || !errors.Is(err, ErrNoTenant) {
		t.Fatal("a sibling context could read another tenant's window", err)
	}
	if got, err := ReadHTTPObservations(other, store, "other-owner", q); err != nil || len(got) != 1 || got[0].SpanID != "foreign" {
		t.Fatal("the sibling's overlap lost its own scope", err)
	}
	base.SpanID = "sentinel"
	if err := store.WriteSpans(t.Context(), []Span{base}); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadHTTPObservations(owner, store, "health-owner", q); got != nil || err != nil {
		t.Fatal("the observation ceiling returned a partial sample as complete", err)
	}
}

func TestHTTPObservationReadAbstainsAfterTenantRingEviction(t *testing.T) {
	store := NewMemory()
	const tenant = "health-owner"
	ctx := tenancy.WithTenant(t.Context(), tenant)
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	base := Span{TenantID: tenant, Service: "site", Kind: "server", Start: start,
		TraceID: "observation", Duration: time.Millisecond, Attrs: httpObservationAttributes("192.0.2.1", "443", "200")}
	rows := make([]Span, 0, memoryMaxPerTenant+1)
	for i := range memoryMaxPerTenant + 1 {
		span := base
		span.SpanID = strconv.Itoa(i)
		if i > 20 {
			span.Start = start.Add(10 * time.Second)
			span.Service = "different service"
		}
		rows = append(rows, span)
	}
	if err := store.WriteSpans(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	q := SpanQuery{Service: base.Service, Since: start, Until: start.Add(5 * time.Second),
		HTTPServer: &HTTPServerTarget{Address: netip.MustParseAddr("192.0.2.1"), Port: 443}}
	if got, err := ReadHTTPObservations(ctx, store, tenant, q); got != nil || err != nil {
		t.Fatal("a partially retained window qualified as complete", err)
	}
	if _, _, err := store.EraseTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	base.SpanID = "after-erase"
	if err := store.WriteSpans(ctx, []Span{base}); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadHTTPObservations(ctx, store, tenant, q); err != nil || len(got) != 1 || got[0].SpanID != base.SpanID {
		t.Fatal("tenant erasure left a stale retention boundary", err)
	}
}
