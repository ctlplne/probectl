// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestChangeEffectMeasurementsKeepOriginalBeforeAfterLossLatencyAndTenantBoundary(t *testing.T) {
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	from, to := at.Add(-time.Minute), at.Add(time.Minute)
	for _, tenant := range []string{"primary", "paired"} {
		source := store.IncidentConfiguredTest{TenantID: tenant, ContextID: "context", EntityID: "router", TestID: "test", AgentID: "agent"}
		read := func(id string, end time.Time, rtts []uint64) store.IncidentTestMeasurement {
			return store.IncidentTestMeasurement{TenantID: tenant, ContextID: source.ContextID, EntityID: source.EntityID, TestID: source.TestID, AgentID: source.AgentID, EvidenceID: id, ObservationID: "observation-" + id, CaptureDigest: [32]byte{byte(len(id))}, ObservedAt: end, Available: true, Reason: "original_attested_test_observation", ICMP: &entity.ICMPMeasurement{Version: 3, StartedAt: end.Add(-time.Second), CompletedAt: end, Requested: 3, Attempted: 3, Transmitted: 3, Replies: uint32(len(rtts)), ReadComplete: true, RoundTrips: &entity.ICMPRoundTrips{Nanos: rtts, ExecutionNanos: uint64(time.Second)}}}
		}
		before := read("before", at.Add(-5*time.Second), []uint64{100, 200})
		after := read("after", at.Add(5*time.Second), []uint64{900, 1200, 1500})
		result, err := summarizeChangeEffectTests(context.Background(), tenant, []store.IncidentConfiguredTest{source}, []store.IncidentTestMeasurement{before, after}, from, at, to, 1<<20)
		if err != nil || len(result) != 1 {
			t.Fatal("original comparison unavailable", err)
		}
		if result[0].Before.LossRatio == nil || *result[0].Before.LossRatio != "1/3" || result[0].After.LossRatio == nil || *result[0].After.LossRatio != "0" || result[0].Before.Latency == nil || result[0].Before.Latency.MeanNanos != "150" || result[0].After.Latency.MeanNanos != "1200" {
			t.Fatal("before/after values were rounded, conflated or inferred", result[0])
		}
		if len(result[0].Before.Observations) != 1 || result[0].Before.Observations[0].RoundTrips.Nanos[1] != "200" || result[0].After.Observations[0].EvidenceID != "after" {
			t.Fatal("comparison lost original values/citations")
		}
		legacy := before
		copyMeasurement := *before.ICMP
		legacy.ICMP = &copyMeasurement
		legacy.ICMP.Version = 1
		legacy.ICMP.RoundTrips = nil
		result, err = summarizeChangeEffectTests(t.Context(), tenant, []store.IncidentConfiguredTest{source}, []store.IncidentTestMeasurement{legacy}, from, at, to, 1<<20)
		if err != nil || result[0].Before.Latency != nil || result[0].Before.LossRatio == nil || result[0].Before.LatencyCoverage != "unavailable_original_round_trips" {
			t.Fatal("legacy data gained invented latency or lost its original packets", err)
		}
		crossing := after
		crossing.EvidenceID = "crossing"
		m := *after.ICMP
		m.StartedAt = at.Add(-time.Second)
		crossing.ICMP = &m
		result, err = summarizeChangeEffectTests(t.Context(), tenant, []store.IncidentConfiguredTest{source}, []store.IncidentTestMeasurement{crossing}, from, at, to, 1<<20)
		if err != nil || result[0].After.Latency != nil || result[0].After.LossRatio != nil || result[0].After.Observations[0].Reason != "execution_straddles_comparison_boundary" {
			t.Fatal("a straddling execution was assigned to one side", err)
		}
		foreign := before
		foreign.TenantID = "foreign"
		if result, err := summarizeChangeEffectTests(t.Context(), tenant, []store.IncidentConfiguredTest{source}, []store.IncidentTestMeasurement{foreign}, from, at, to, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) || result != nil {
			t.Fatal("foreign measurement entered comparison", err)
		}
		if result, err := summarizeChangeEffectTests(t.Context(), tenant, []store.IncidentConfiguredTest{source}, []store.IncidentTestMeasurement{before, after}, from, at, to, 4096); !errors.Is(err, flowstore.ErrExplorerBudget) || result != nil {
			t.Fatal("under-admitted comparison returned a partial population", err)
		}
		preciseFrom := from.Add(100 * time.Nanosecond)
		precise := read("precise", preciseFrom.Add(200*time.Nanosecond), []uint64{50})
		precise.ICMP.StartedAt = precise.ICMP.CompletedAt.Add(-100 * time.Nanosecond)
		precise.ICMP.RoundTrips.ExecutionNanos = 100
		precise.ObservedAt = precise.ICMP.CompletedAt.Truncate(time.Microsecond)
		result, err = summarizeChangeEffectTests(t.Context(), tenant, []store.IncidentConfiguredTest{source}, []store.IncidentTestMeasurement{precise}, preciseFrom, at, to, 1<<20)
		if err != nil || result[0].Before.Latency == nil || result[0].Before.Latency.MeanNanos != "50" || len(result[0].Before.Observations) != 1 {
			t.Fatal("quantized index lost an included exact original", err)
		}
		precise.ICMP.Version, precise.ICMP.RoundTrips = 1, nil
		precise.ICMP.CompletedAt = precise.ObservedAt
		result, err = summarizeChangeEffectTests(t.Context(), tenant, []store.IncidentConfiguredTest{source}, []store.IncidentTestMeasurement{precise}, preciseFrom, at, to, 1<<20)
		if err != nil || result[0].Before.LossRatio != nil || result[0].Before.Latency != nil || result[0].Before.Observations[0].Reason != "ambiguous_quantized_window_boundary" {
			t.Fatal("a legacy clock acquired sub-microsecond membership", err)
		}
	}
}
