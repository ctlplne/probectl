// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func carrierSLAMeasureFixture(t *testing.T, tenant string) (context.Context, *carrierSLAAccumulator, []store.IncidentTestMeasurement, flow.CarrierSLATerms) {
	t.Helper()
	from := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	source := store.IncidentConfiguredTest{TenantID: tenant, SourceGeneration: 1, ContextID: "context", EntityID: "device", AgentID: "agent", TestID: "test", CurrentSince: from.Add(-time.Hour)}
	a, err := newCarrierSLAAccumulator(ctx, []store.IncidentConfiguredTest{source}, from, to, 8<<20, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	reads := []store.IncidentTestMeasurement{}
	for i, samples := range [][]uint64{{1, 3, 5}, {}, {7, 9}} {
		at := from.Add(time.Duration(i+1) * 10 * time.Second)
		m := &entity.ICMPMeasurement{Version: 3, StartedAt: at.Add(-time.Second), CompletedAt: at, Requested: 3, Attempted: 3, Transmitted: 3, Replies: uint32(len(samples)), ReadComplete: true, RoundTrips: &entity.ICMPRoundTrips{Nanos: samples, ExecutionNanos: 1e9}}
		reads = append(reads, store.IncidentTestMeasurement{TenantID: tenant, SourceGeneration: 1, ContextID: source.ContextID, EntityID: source.EntityID, AgentID: source.AgentID, TestID: source.TestID, EvidenceID: strconv.Itoa(i + 1), ObservedAt: at, Available: true, ICMP: m})
	}
	terms := flow.CarrierSLATerms{Carrier: "carrier", CircuitID: "circuit", Currency: "USD", MonthlyCharge: "100.125", CreditCapRatio: "1.25", Aggregation: "maximum"}
	for _, rule := range []struct{ id, metric, basis, good, threshold, ratio string }{
		{"availability", "availability", "original_execution_ratio", "at_least", "0.99", "0.1"},
		{"loss", "loss", "original_packet_ratio", "at_most", "0.01", "0.2"},
		{"mean", "latency_nanos", "original_rtt_mean", "at_most", "4", "0.05"},
		{"p95", "latency_nanos", "original_rtt_p95", "at_most", "8", "0.05"},
		{"repair", "repair_nanos", "original_failure_interval", "at_most", "9000000000", "0.1"},
	} {
		terms.Rules = append(terms.Rules, flow.CarrierSLARule{ID: rule.id, Metric: rule.metric, Basis: rule.basis, GoodWhen: rule.good, Threshold: rule.threshold, CreditBands: []flow.CarrierSLACreditBand{{From: "0", CreditRatio: rule.ratio}}})
	}
	return ctx, a, reads, terms
}

func TestCarrierSLAMonthMeasuresCompleteExactOriginalPopulation(t *testing.T) {
	ctx, a, reads, terms := carrierSLAMeasureFixture(t, "11111111-1111-4111-8111-111111111111")
	for _, read := range reads {
		if err := a.observe(ctx, read); err != nil {
			t.Fatal(err)
		}
	}
	credit, populations, err := a.finish(ctx, terms, 8<<20, 8<<20)
	if err != nil || !credit.Complete || credit.ExactCredit == nil || *credit.ExactCredit != "801/40" || len(credit.Assessments) != 5 || len(populations) != 1 {
		t.Fatal("complete original month lost exact conditional credit", credit, err)
	}
	for i, value := range []string{"2/3", "4/9", "5", "9", "10000000000"} {
		if credit.Assessments[i].State != "breached" || credit.Assessments[i].Value != value || len(credit.Assessments[i].Citations) != 1 {
			t.Fatal("exact observed metric or provenance changed", credit.Assessments[i])
		}
	}
	p := populations[0]
	if p.Originals != "3" || p.Successful != "2" || p.Failed != "1" || p.Unknown != "0" || p.Transmitted != "9" || p.Lost != "4" || p.RTTSamples != "5" || len(p.Digest) != 64 {
		t.Fatal("original population was shortened or approximated", p)
	}
	_, other, changed, _ := carrierSLAMeasureFixture(t, "11111111-1111-4111-8111-111111111111")
	changed[0].ICMP.RoundTrips.Nanos[0] = 2
	for _, read := range changed {
		if err := other.observe(ctx, read); err != nil {
			t.Fatal(err)
		}
	}
	_, second, err := other.finish(ctx, terms, 8<<20, 8<<20)
	if err != nil || second[0].Digest == p.Digest {
		t.Fatal("changed typed originals survived the complete replay digest", err)
	}
}

func TestCarrierSLAMonthKeepsIncompleteAndUnobservedTimeUnknown(t *testing.T) {
	for _, kind := range []string{"no originals", "canceled", "legacy RTT", "open failure", "local IO", "unsupported basis", "unfinished period"} {
		t.Run(kind, func(t *testing.T) {
			ctx, a, reads, terms := carrierSLAMeasureFixture(t, "11111111-1111-4111-8111-111111111111")
			switch kind {
			case "no originals":
				reads = nil
			case "canceled":
				reads[0].ICMP.Canceled = true
			case "legacy RTT":
				reads[0].ICMP.Version = 2
				reads[0].ICMP.RoundTrips = nil
			case "open failure":
				reads = reads[:2]
			case "local IO":
				reads[0].ICMP.ReadComplete = false
			case "unsupported basis":
				terms.Rules[0].Basis = "continuous_unmeasured_uptime"
			case "unfinished period":
				a.partial = true
			}
			for _, read := range reads {
				if err := a.observe(ctx, read); err != nil {
					t.Fatal(err)
				}
			}
			credit, _, err := a.finish(ctx, terms, 8<<20, 8<<20)
			if err != nil || credit.Complete || credit.ExactCredit != nil {
				t.Fatal("incomplete monthly population acquired exact credit", kind, credit, err)
			}
		})
	}
}

func TestCarrierSLAMonthKeepsTwoTenantOriginalsAndSourceEpochsSeparate(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		ctx, a, reads, terms := carrierSLAMeasureFixture(t, tenant)
		foreign := reads[0]
		foreign.TenantID = "foreign"
		if err := a.observe(ctx, foreign); !errors.Is(err, entity.ErrScopeMismatch) {
			t.Fatal("foreign original crossed tenant boundary", err)
		}
		wrong := reads[0]
		wrong.AgentID = "sibling"
		if err := a.observe(ctx, wrong); !errors.Is(err, entity.ErrScopeMismatch) {
			t.Fatal("sibling original entered selected population", err)
		}
		stale := reads[0]
		stale.SourceGeneration++
		if err := a.observe(ctx, stale); err == nil {
			t.Fatal("old source epoch was accepted")
		}
		for _, read := range reads {
			if err := a.observe(ctx, read); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.observe(ctx, reads[2]); err == nil {
			t.Fatal("duplicate original was counted twice")
		}
		credit, populations, err := a.finish(ctx, terms, 8<<20, 8<<20)
		if err != nil || !credit.Complete || populations[0].Originals != "3" {
			t.Fatal("tenant boundary control damaged the valid source population", err)
		}
	}
}
