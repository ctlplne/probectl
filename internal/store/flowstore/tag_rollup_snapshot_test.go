// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

// This existing-API assertion also compiles on the original candidate. It is
// a source-receipt unit proof, not a substitute for real retained-store I/O.
func TestTagRollupSnapshotUsesActualCompleteInputs(t *testing.T) {
	tenant := uuid.NewString()
	lookup, err := NewTagQueryData(tenant, 7, []tags.Definition{{TenantID: tenant, ID: uuid.NewString(), Key: "customer"}}, nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	vocabulary, err := lookup.Vocabulary(tenant)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := flow.WithQueryVocabulary(t.Context(), tenant, vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 3, 12, 34, 56, 123000000, time.UTC)
	result := PlanResult{Source: "rollup", OldestInput: at, TotalGroups: 1,
		Coverage: &PlanSourceCoverage{Fields: []string{"exporter"}, ResolutionSeconds: 60, CompleteInputs: true},
		Query:    flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Hour), DataSeries: "rollup", GroupBy: []string{"tag.customer"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}},
	}
	clock, err := SnapshotInputsForTenant(ctx, tenant, result)
	if err != nil {
		t.Fatal("complete retained tag rollup was refused by frozen source receipt")
	}
	if clock.Source != "rollup" || !clock.TagLookup || !clock.NeedsComplete {
		t.Fatal("tag rollup was relabeled or lost complete-input requirement")
	}
	expiry, err := clock.ExpiresAt(1, nil)
	if err != nil || !expiry.Equal(at.Truncate(time.Hour).AddDate(0, 0, 1)) {
		t.Fatalf("retained tag input used wrong expiry: %s %v", expiry, err)
	}
	result.Coverage = &PlanSourceCoverage{Fields: []string{"exporter"}, ResolutionSeconds: 3600, CompleteInputs: false}
	if _, err := SnapshotInputsForTenant(ctx, tenant, result); !errors.Is(err, ErrSnapshotInputs) {
		t.Fatal("incomplete hourly tag source acquired frozen authority")
	}
	result.Coverage = nil
	if _, err := SnapshotInputsForTenant(ctx, tenant, result); !errors.Is(err, ErrSnapshotInputs) {
		t.Fatal("unknown rollup completeness acquired frozen authority")
	}
	// Ordinary aligned legacy aggregates remain available when they do not
	// need tag or exact input columns. The fix must preserve that reach too.
	result.Query.GroupBy = []string{"protocol"}
	result.Query.From = at.Truncate(time.Hour)
	result.Query.To = result.Query.From.Add(time.Hour)
	result.Query.BucketSeconds = 3600
	result.Coverage = &PlanSourceCoverage{Fields: []string{"protocol"}, ResolutionSeconds: 3600, CompleteInputs: false}
	if ordinary, err := SnapshotInputsForTenant(ctx, tenant, result); err != nil || ordinary.NeedsComplete || ordinary.TagLookup {
		t.Fatalf("valid legacy aggregate was narrowed: %+v %v", ordinary, err)
	}
}
