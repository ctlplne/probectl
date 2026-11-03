// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestTaggedSnapshotInputsKeepTenantVocabularyAndNativeRawDependencies(t *testing.T) {
	a, b := uuid.NewString(), uuid.NewString()
	definition := tags.Definition{TenantID: a, ID: uuid.NewString(), Key: "customer"}
	lookup, err := NewTagQueryData(a, 8, []tags.Definition{definition},
		[]tags.ExporterProjection{{Exporter: "192.0.2.1", Values: map[string]string{"customer": "private-predicate-value"}}}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	mapped := explorerFixtureRow(a)
	memory := NewMemory()
	if err := memory.Insert(t.Context(), []Row{mapped}); err != nil {
		t.Fatal(err)
	}
	from := mapped.TS.Truncate(time.Hour)
	plan := flow.QueryPlan{From: from, To: from.Add(time.Hour), BucketSeconds: 3600,
		GroupBy: []string{"tag.customer", "protocol"},
		Metrics: []flow.QueryMetric{{Measure: "unique_src_asn", Calculation: "total", Role: "primary"}},
		Filter:  &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryEqual, Values: []string{"private-predicate-value"}}}}}
	result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: a, Plan: plan, Tags: lookup})
	if err != nil || result.TotalGroups != 1 {
		t.Fatalf("tagged source execution failed: %v", err)
	}
	vocabulary, err := lookup.Vocabulary(a)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := flow.WithQueryVocabulary(t.Context(), a, vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	clock, err := SnapshotInputsForTenant(ctx, a, result)
	if err != nil || !clock.TagLookup || !clock.NeedsComplete || clock.Source != "raw" || !slices.Equal(clock.Fields, []string{"exporter", "protocol", "src_asn"}) {
		t.Fatalf("tagged snapshot lost native raw input dependencies: %+v %v", clock, err)
	}
	encoded, err := json.Marshal(clock)
	if err != nil || bytes.Contains(encoded, []byte("private-predicate-value")) || bytes.Contains(encoded, []byte("tag.customer")) {
		t.Fatal("source receipt retained dynamic grammar or predicate values")
	}
	if _, err := clock.ExpiresAt(1, nil); err != nil {
		t.Fatal(err)
	}
	if err := memory.VerifySnapshotInputs(t.Context(), a, clock); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SnapshotInputs){
		func(c *SnapshotInputs) { c.NeedsComplete = false },
		func(c *SnapshotInputs) { c.Source = "rollup" },
		func(c *SnapshotInputs) { c.Fields = []string{"protocol"} },
	} {
		bad := clock
		mutate(&bad)
		if _, err := bad.ExpiresAt(1, nil); !errors.Is(err, ErrSnapshotInputs) {
			t.Fatal("tag lookup lost raw/complete native coverage")
		}
	}
	if _, err := SnapshotInputsForTenant(t.Context(), a, result); !errors.Is(err, ErrSnapshotInputs) {
		t.Fatal("unbound dynamic fields became source input coverage")
	}
	if _, err := SnapshotInputsForTenant(ctx, b, result); !errors.Is(err, ErrTagQueryScope) {
		t.Fatal("another tenant reused a bound vocabulary")
	}
	if _, err := SnapshotInputsForTenant(ctx, "", result); !errors.Is(err, ErrNoTenant) {
		t.Fatal("source receipt omitted its tenant boundary")
	}
	bad := result
	bad.Query.GroupBy = []string{"tag.unknown"}
	if _, err := SnapshotInputsForTenant(ctx, a, bad); !errors.Is(err, ErrSnapshotInputs) {
		t.Fatal("unregistered dynamic field became source coverage")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := SnapshotInputsForTenant(canceled, a, result); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled input validation continued")
	}
}

func TestSnapshotInputsCaptureDependenciesWithoutFilterLiterals(t *testing.T) {
	row := explorerFixtureRow("red")
	memory := NewMemory()
	if err := memory.Insert(t.Context(), []Row{row}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: row.TS.AddDate(-2, 0, 0), To: row.TS.Add(time.Hour), GroupBy: []string{"protocol"}, BucketSeconds: 3600, Metrics: []flow.QueryMetric{{Measure: "unique_src_asn", Calculation: "total", Role: "primary"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "agent_id", Op: flow.QueryNotEqual, Values: []string{"private-expression-must-not-enter-receipt"}}}}}
	result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	clock, err := SnapshotInputsFor(result)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(clock.Fields, []string{"agent_id", "protocol", "src_asn"}) || !clock.NeedsComplete || !clock.OldestInput.Equal(row.TS) {
		t.Fatalf("missing input dependency or wrong clock: %+v", clock)
	}
	encoded, err := json.Marshal(clock)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("private-expression")) || len(encoded) > 8192 {
		t.Fatal("filter literal or unbounded grammar copied into source receipt")
	}
	if _, ok := SnapshotInputVerifierOf(&writeFencedStore{next: memory}); !ok {
		t.Fatal("writer wrapper hid source-verification capability")
	}
	if err := memory.VerifySnapshotInputs(t.Context(), "", clock); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("missing scope: %v", err)
	}
}

func TestSnapshotInputsExpiryUsesActualSourceClocks(t *testing.T) {
	oldest := time.Date(2026, 10, 28, 12, 34, 56, 789000000, time.UTC)
	base := SnapshotInputs{Version: 1, From: oldest.AddDate(-10, 0, 0), To: oldest.Add(time.Hour), OldestInput: oldest, Source: "raw", DataSeries: "auto", BucketSeconds: 60, Fields: []string{"src_port"}, NeedsComplete: true}
	one, thirty, zero := 1, 30, 0
	for _, test := range []struct {
		name, source string
		deployment   int
		tenant       *int
		expected     time.Time
	}{
		{"raw deployment seconds", "raw", 1, nil, oldest.Truncate(time.Second).AddDate(0, 0, 1)},
		{"raw tighter tenant exact timestamp", "raw", 30, &one, oldest.AddDate(0, 0, 1)},
		{"retained deployment hour", "rollup", 1, nil, oldest.Truncate(time.Hour).AddDate(0, 0, 1)},
		{"retained tighter tenant exact timestamp", "rollup", 30, &one, oldest.AddDate(0, 0, 1)},
		{"explicit deployment optout", "rollup", 0, nil, time.Time{}},
		{"tenant clock under deployment optout", "rollup", 0, &thirty, oldest.AddDate(0, 0, 30)},
		{"legacy tenant zero inherits", "raw", 1, &zero, oldest.Truncate(time.Second).AddDate(0, 0, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := base
			clock.Source = test.source
			got, err := clock.ExpiresAt(test.deployment, test.tenant)
			if err != nil || !got.Equal(test.expected) {
				t.Fatalf("expiry %s, want %s: %v", got, test.expected, err)
			}
		})
	}
	legacy := base
	legacy.Source = "rollup"
	legacy.From = oldest.Truncate(time.Hour).AddDate(-10, 0, 0)
	legacy.To = oldest.Truncate(time.Hour).Add(time.Hour)
	legacy.BucketSeconds = 3600
	legacy.Fields = []string{"protocol"}
	legacy.NeedsComplete = false
	if expiry, err := legacy.ExpiresAt(1, &one); err != nil || !expiry.IsZero() {
		t.Fatalf("legitimate old hourly information acquired an exact-input clock: %s %v", expiry, err)
	}
	empty := base
	empty.OldestInput = time.Time{}
	empty.Empty = true
	if expiry, err := empty.ExpiresAt(1, &one); err != nil || !expiry.IsZero() {
		t.Fatalf("empty prefix invented an input clock: %s %v", expiry, err)
	}
}

func TestSnapshotInputsRejectMalformedOrWeakenedProof(t *testing.T) {
	now := time.Now().UTC()
	base := SnapshotInputs{Version: 1, From: now.Add(-time.Hour), To: now.Add(time.Hour), OldestInput: now, Source: "raw", DataSeries: "auto", BucketSeconds: 60, Fields: []string{"src_port"}, NeedsComplete: true}
	for _, mutate := range []func(*SnapshotInputs){
		func(c *SnapshotInputs) { c.Version = 2 }, func(c *SnapshotInputs) { c.NeedsComplete = false }, func(c *SnapshotInputs) { c.Fields = []string{"tenant_id"} }, func(c *SnapshotInputs) { c.Fields = []string{"src_port", "agent_id"} }, func(c *SnapshotInputs) { c.Empty = true }, func(c *SnapshotInputs) { c.OldestInput = c.To }, func(c *SnapshotInputs) { c.DataSeries = "rollup" },
	} {
		clock := base
		mutate(&clock)
		if _, err := clock.ExpiresAt(7, nil); !errors.Is(err, ErrSnapshotInputs) {
			t.Fatalf("bad source proof accepted: %+v %v", clock, err)
		}
	}
}
