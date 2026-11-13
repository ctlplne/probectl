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
)

func verdictOriginalPath(input incidentVerdictEvidence) incidentVerdictPath {
	completed := input.from.Add(time.Second)
	return incidentVerdictPath{source: store.IncidentConfiguredTest{TenantID: input.tenantID, ContextID: "9df966f1-6882-4654-8cd4-7d3cc7898e73", EntityID: "71e9f275-fbf2-4eca-bc75-1fb0e27b8724"},
		binding: store.PathTestBinding{Scope: entity.Scope{TenantID: input.tenantID, ContextID: "9df966f1-6882-4654-8cd4-7d3cc7898e73"}, Target: "service.example", AssignedAt: input.from.Add(-time.Hour)}, since: input.from.Add(-time.Hour),
		rounds: []pathstore.Snapshot{{ID: "01234567890123456789abcdefabcdef", ObservedAt: input.from.Add(time.Second), CompletedAt: &completed, TrustedDiscoveryTime: true,
			Path: path.Path{Target: "service.example", TargetIP: "192.0.2.1", Mode: "icmp", MeasurementFidelity: &path.MeasurementFidelity{Version: 1, ProbeTransport: "icmp", AcquisitionMode: "raw_icmp", TimingSource: "application_monotonic", HopVisibility: "full"}, Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: "192.0.2.1", Sent: 1, Received: 1}}}}}}}}
}

func TestIncidentVerdictPathsKeepOriginNamespaceAndScope(t *testing.T) {
	ctx, input := verdictClassifierFixture()
	input.paths = []incidentVerdictPath{verdictOriginalPath(input)}
	got, err := classifyIncidentVerdict(ctx, input, 1<<20)
	if err != nil || got.Domain != incident.FaultUnknown || len(got.Hypotheses[1].Against) != 1 || len(got.Hypotheses[2].Against) != 1 {
		t.Fatal("control-plane response was lost or invented an agent/carrier verdict", got.Domain, err)
	}
	cite := got.Hypotheses[1].Against[0]
	if cite.SourceKind != "control_plane_path" || cite.AgentID != "control_plane" || cite.EvidenceID != "" || cite.PathRoundID != input.paths[0].rounds[0].ID {
		t.Fatal("original control-plane round was relabelled")
	}
	for _, mutate := range []func(*incidentVerdictPath){
		func(p *incidentVerdictPath) { p.binding.Scope.TenantID = "foreign" },
		func(p *incidentVerdictPath) { p.binding.Scope.ContextID = "foreign" },
	} {
		value := verdictOriginalPath(input)
		mutate(&value)
		input.paths = []incidentVerdictPath{value}
		if _, err := classifyIncidentVerdict(ctx, input, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) {
			t.Fatal("foreign path binding escaped source scope validation", err)
		}
	}
	for _, mutate := range []func(*incidentVerdictPath){
		func(p *incidentVerdictPath) { p.rounds[0].TrustedDiscoveryTime = false },
		func(p *incidentVerdictPath) { p.rounds[0].Path.Hops[0].Nodes[0].Received = 0 },
		func(p *incidentVerdictPath) { p.rounds[0].Path.Vantage = "agent-a" },
		func(p *incidentVerdictPath) { p.rounds[0].Path.MeasurementFidelity = nil },
		func(p *incidentVerdictPath) { p.since = input.to },
		func(p *incidentVerdictPath) { p.rounds[0].CompletedAt = nil },
		func(p *incidentVerdictPath) { at := input.to; p.rounds[0].CompletedAt = &at },
	} {
		value := verdictOriginalPath(input)
		mutate(&value)
		input.paths = []incidentVerdictPath{value}
		got, err := classifyIncidentVerdict(ctx, input, 1<<20)
		if err != nil || got.Domain != incident.FaultUnknown || len(got.Hypotheses[1].Against) != 0 || len(got.Hypotheses[2].Against) != 0 {
			t.Fatal("unmeasured, pre-binding or foreign-vantage path became contrary proof", err)
		}
	}
	if _, err := (incident.VerdictCitation{SourceKind: "control_plane_path", PathRoundID: strings.Repeat("1", 32), EvidenceID: "borrowed", AgentID: "control_plane"}).SourceReference(); err == nil {
		t.Fatal("two observation namespaces were accepted as one citation")
	}
}
