// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/testspec"
)

func TestCarrierProjectionKeepsSingleWindowOriginalsAndActualTraceVantage(t *testing.T) {
	to := time.Now().UTC()
	from := to.Add(-7 * 24 * time.Hour)
	at := from.Add(time.Hour)
	for _, tenant := range []string{"primary", "paired"} {
		source := store.IncidentConfiguredTest{TenantID: tenant, ContextID: "context", EntityID: "router", TestID: "test", AgentID: "agent", Target: "198.51.100.7", CurrentSince: from.Add(-time.Hour), Definition: testspec.ExecutableDefinition{ID: "test", Type: "icmp", Target: "198.51.100.7"}}
		source.PathBinding = &store.PathTestBinding{Scope: entity.Scope{TenantID: tenant, ContextID: source.ContextID}, Target: source.Target, AssignedAt: source.CurrentSince}
		measurement := store.IncidentTestMeasurement{TenantID: tenant, ContextID: source.ContextID, EntityID: source.EntityID, TestID: source.TestID, AgentID: source.AgentID, EvidenceID: "original-evidence", ObservationID: "original-observation", CaptureDigest: [32]byte{1}, ObservedAt: at, Available: true,
			ICMP: &entity.ICMPMeasurement{Version: 3, Requested: 3, Attempted: 3, Transmitted: 3, Replies: 2, ReadComplete: true, StartedAt: at.Add(-time.Second), CompletedAt: at, RoundTrips: &entity.ICMPRoundTrips{Nanos: []uint64{100, 300}, ExecutionNanos: uint64(time.Second)}}}
		completion := at.Add(time.Second)
		original := pathstore.Snapshot{ID: "actual-control-round", ObservedAt: at, CompletedAt: &completion, TrustedDiscoveryTime: true, Path: path.Path{Target: source.Target, TargetIP: source.Target, Vantage: path.VantageControlPlane, Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: source.Target, Sent: 3, Received: 2}}}}}}
		snapshot := incidentVerdictSnapshot{inputs: &store.IncidentImpactInputs{TenantID: tenant, IncidentID: "incident"}, evidence: incidentVerdictEvidence{tenantID: tenant, from: from, to: to}, tests: []store.IncidentConfiguredTest{source}, outcomes: []store.IncidentTestMeasurement{measurement}, pathGroups: []incidentVerdictPathGroup{{Target: source.Target, Rounds: []pathstore.Snapshot{original}}}}
		result, err := projectIncidentCarrier(t.Context(), tenant, "incident", from, to, snapshot, 1<<20)
		if err != nil || result.ContractVersion != incident.CarrierContractVersion || len(result.Vantages) != 1 {
			t.Fatal("complete original carrier projection unavailable", err)
		}
		v := result.Vantages[0]
		if !v.Measurements.From.Equal(from) || !v.Measurements.To.Equal(to) || v.Measurements.Packets == nil || v.Measurements.Packets.Transmitted != "3" || v.Measurements.Packets.Lost != "1" || v.Measurements.LossRatio == nil || *v.Measurements.LossRatio != "1/3" || v.Measurements.Latency == nil || v.Measurements.Latency.MeanNanos != "200" || v.Measurements.Observations[0].RoundTrips.Nanos[1] != "300" {
			t.Fatal("carrier window lost exact original packets/RTTs")
		}
		if len(v.Traces) != 1 || v.Traces[0].Vantage != path.VantageControlPlane || v.Traces[0].Path.Vantage != path.VantageControlPlane || result.Coverage.Traces != "control_plane_only" || !strings.Contains(result.Summary, "1 complete packet executions") {
			t.Fatal("carrier relabeled a control trace or lost original coverage")
		}
		foreign := snapshot
		foreign.inputs = &store.IncidentImpactInputs{TenantID: "foreign", IncidentID: "incident"}
		if got, err := projectIncidentCarrier(t.Context(), tenant, "incident", from, to, foreign, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) || got.ContractVersion != "" {
			t.Fatal("foreign incident populated a carrier attachment", err)
		}
		foreign = snapshot
		copyRead := measurement
		copyRead.TenantID = "foreign"
		foreign.outcomes = []store.IncidentTestMeasurement{copyRead}
		if got, err := projectIncidentCarrier(t.Context(), tenant, "incident", from, to, foreign, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) || got.ContractVersion != "" {
			t.Fatal("foreign original populated carrier measurements", err)
		}
	}
}
