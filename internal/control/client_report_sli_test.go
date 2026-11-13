// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

func clientReportSLIFixture(t *testing.T, tenant string) (context.Context, store.IncidentConfiguredTest, time.Time, time.Time) {
	t.Helper()
	source := store.IncidentConfiguredTest{TenantID: tenant, SourceGeneration: 1, ContextID: uuid.NewString(), EntityID: uuid.NewString(), TestID: uuid.NewString(), AgentID: "original-sender", Name: "monthly availability", Type: "http", Target: "https://example.test/"}
	source.Definition = testspec.ExecutableDefinition{ID: source.TestID, Type: source.Type, Target: source.Target, IntervalSeconds: 30, TimeoutSeconds: 5}
	from := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	return tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), source, from, from.AddDate(0, 1, 0)
}

func clientReportSLIRead(source store.IncidentConfiguredTest, index uint64, at time.Time, success bool) store.IncidentTestMeasurement {
	var digest [32]byte
	binary.BigEndian.PutUint64(digest[24:], index+1)
	return store.IncidentTestMeasurement{TenantID: source.TenantID, SourceGeneration: source.SourceGeneration, ContextID: source.ContextID, EntityID: source.EntityID, TestID: source.TestID, AgentID: source.AgentID,
		EvidenceID: fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1), CaptureDigest: digest, ObservedAt: at, Available: true, Outcome: &entity.ProbeOutcome{Success: success}}
}

func TestClientReportSLIsKeepCompleteMonthAndConfiguredWindowsWithoutRetainingExecutions(t *testing.T) {
	tenant := uuid.NewString()
	ctx, source, from, to := clientReportSLIFixture(t, tenant)
	definitions := []slo.SLO{
		{TenantID: tenant, Name: "long-window", TestID: source.TestID, Window: 45 * 24 * time.Hour, Objective: .5},
		{TenantID: tenant, Name: "last-day", TestID: source.TestID, Window: 24 * time.Hour, Objective: .999},
		{TenantID: tenant, Name: "no-samples", TestID: uuid.NewString(), Window: 7 * 24 * time.Hour, Objective: .999},
	}
	a, err := newClientReportSLIAccumulator(ctx, tenant, []store.IncidentConfiguredTest{source}, definitions, from, to, 256<<10, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.observe(ctx, clientReportSLIRead(source, 0, from.Add(-24*time.Hour), true)); err != nil {
		t.Fatal(err)
	}
	for index := uint64(1); index <= 100_000; index++ {
		if err := a.observe(ctx, clientReportSLIRead(source, index, from.Add(time.Duration(index)*time.Second), index%2 == 0)); err != nil {
			t.Fatal("complete monthly population was refused", index, err)
		}
	}
	if err := a.observe(ctx, clientReportSLIRead(source, 100_001, to.Add(-time.Second), true)); err != nil {
		t.Fatal(err)
	}
	unavailable := clientReportSLIRead(source, 100_002, to.Add(-500*time.Millisecond), true)
	unavailable.Available = false
	if err := a.observe(ctx, unavailable); err != nil {
		t.Fatal(err)
	}
	canceled := clientReportSLIRead(source, 100_003, to.Add(-250*time.Millisecond), true)
	canceled.Outcome.Canceled = true
	if err := a.observe(ctx, canceled); err != nil {
		t.Fatal(err)
	}
	availability, results, err := a.finish(ctx)
	if err != nil || len(availability) != 1 || len(results) != 3 {
		t.Fatal("complete monthly calculation was unavailable", err)
	}
	counts := availability[0].Counts
	if counts.Successful != "50001" || counts.Failed != "50000" || counts.Unknown != "2" || counts.Canceled != "1" || counts.AvailabilityDenominator != "100001" || availability[0].OriginalCount != "100003" || counts.Coverage != "partial_observation_coverage" {
		t.Fatal("monthly sample boundaries or unknown outcomes changed", counts)
	}
	if results[0].OriginalCount != "100004" || results[0].Counts.Successful != "50002" || results[0].ObservedMeetsObjective == nil || !*results[0].ObservedMeetsObjective || !results[0].From.Equal(to.Add(-45*24*time.Hour)) {
		t.Fatal("configured long SLO window was replaced by the calendar month")
	}
	if results[1].OriginalCount != "3" || results[1].Counts.Successful != "1" || results[1].Counts.Unknown != "2" || results[1].Counts.AvailabilityDenominator != "1" || results[1].ObservedMeetsObjective == nil || !*results[1].ObservedMeetsObjective {
		t.Fatal("SLO inputs were replaced by a live status, or unknown samples became successes")
	}
	if results[2].OriginalCount != "0" || results[2].ObservedMeetsObjective != nil || results[2].Counts.AvailabilityDenominator != "0" || len(results[2].Sources) != 0 {
		t.Fatal("no matching SLO observations became a healthy result")
	}
	if len(availability[0].OriginalsDigest) != 64 || availability[0].OriginalsDigest == results[0].OriginalsDigest || results[0].OriginalsDigest == results[1].OriginalsDigest || len(a.cursors) != 1 || len(a.counters) != 1 || len(a.matches[0]) != 2 {
		t.Fatal("complete window provenance or bounded source state was lost")
	}
	if _, _, err := a.finish(ctx); err == nil {
		t.Fatal("completed calculation was reused")
	}
}

func TestClientReportSLIsRefuseForeignChangedAndPartialSources(t *testing.T) {
	aTenant, bTenant := uuid.NewString(), uuid.NewString()
	ctx, source, from, to := clientReportSLIFixture(t, aTenant)
	for _, name := range []string{"foreign context", "foreign observation", "changed generation", "unselected source", "duplicate original", "work admission"} {
		t.Run(name, func(t *testing.T) {
			a, err := newClientReportSLIAccumulator(ctx, aTenant, []store.IncidentConfiguredTest{source}, nil, from, to, 64<<10, 10)
			if err != nil {
				t.Fatal(err)
			}
			read := clientReportSLIRead(source, 1, from, true)
			callCtx := ctx
			switch name {
			case "foreign context":
				callCtx = tenancy.WithTenant(ctx, tenancy.ID(bTenant))
			case "foreign observation":
				read.TenantID = bTenant
			case "changed generation":
				read.SourceGeneration++
			case "unselected source":
				read.TestID = uuid.NewString()
			case "duplicate original":
				if err := a.observe(ctx, read); err != nil {
					t.Fatal(err)
				}
			case "work admission":
				a.work = 0
			}
			want := entity.ErrScopeMismatch
			if name == "changed generation" || name == "duplicate original" {
				want = entity.ErrConflictingEvidence
			}
			if name == "work admission" {
				want = store.ErrClientReportBudget
			}
			if err := a.observe(callCtx, read); !errors.Is(err, want) {
				t.Fatal("untrusted or incomplete source calculation did not refuse for its own cause", err)
			}
			if availability, slos, err := a.finish(ctx); err == nil || len(availability) != 0 || len(slos) != 0 {
				t.Fatal("failed source calculation published a plausible prefix")
			}
		})
	}
	foreign := source
	foreign.TenantID = bTenant
	if _, err := newClientReportSLIAccumulator(ctx, aTenant, []store.IncidentConfiguredTest{foreign}, nil, from, to, 64<<10, 10); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatal("foreign source selection was accepted", err)
	}
	bCtx, bSource, _, _ := clientReportSLIFixture(t, bTenant)
	b, err := newClientReportSLIAccumulator(bCtx, bTenant, []store.IncidentConfiguredTest{bSource}, nil, from, to, 64<<10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.observe(bCtx, clientReportSLIRead(bSource, 1, from, true)); err != nil {
		t.Fatal(err)
	}
	availability, _, err := b.finish(bCtx)
	if err != nil || len(availability) != 1 || availability[0].TenantID != bTenant || availability[0].Counts.Successful != "1" || availability[0].Source.ContextID != bSource.ContextID {
		t.Fatal("sibling tenant lost its independent positive source", err)
	}
}
