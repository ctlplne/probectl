// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/pipeline"
)

// RTP-02: the flow-derived consumers (NDR, cost, compliance) verified batches
// with the NON-strict helper, so a forged batch from a registered (tenant,
// agent) pair on the shared pooled lane was accepted and raised detections /
// wrote another tenant's cost + ESG accounting; the carbon consumer did no
// verification at all. With strict-lane mode the shared lane is refused for all
// of them, even for a registered pair — matching the flow store's contract.

// strictLaneBinding: agent-real belongs to tenant-real; nothing else is bound.
type strictLaneBinding struct{}

func (strictLaneBinding) Verify(_ context.Context, tenantID, agentID string) error {
	if tenantID == "tenant-real" && agentID == "agent-real" {
		return nil
	}
	return errSLBNotBound
}

var errSLBNotBound = errBound("agent not bound to tenant")

type errBound string

func (e errBound) Error() string { return string(e) }

func TestNDRAndComplianceRefuseSharedLaneInStrictMode(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := strictLaneBinding{}
	registered := []pipeline.Identity{{Tenant: "tenant-real", Agent: "agent-real"}}

	ndr := (&NDRConsumer{log: log}).WithTenantBinding(b).WithStrictTenantLanes(true)
	// Shared lane (laneTenant ""): a REGISTERED pair is still refused in strict mode.
	if !ndr.rejectFlows(context.Background(), "flow", "", registered) {
		t.Fatal("NDR: a registered pair on the shared lane must be refused in strict mode (RTP-02)")
	}
	// The tenant's own namespaced lane with its own agent is admitted.
	if ndr.rejectFlows(context.Background(), "flow", "tenant-real", registered) {
		t.Fatal("NDR: the registered pair on its namespaced lane must be admitted")
	}

	comp := (&ComplianceConsumer{log: log}).WithTenantBinding(b).WithStrictTenantLanes(true)
	if !comp.rejectFlows(context.Background(), "flow", "", registered) {
		t.Fatal("compliance: a registered pair on the shared lane must be refused in strict mode (RTP-02)")
	}
	if comp.rejectFlows(context.Background(), "flow", "tenant-real", registered) {
		t.Fatal("compliance: the registered pair on its namespaced lane must be admitted")
	}
}

func TestCostRefusesForgedSharedLaneBatchInStrictMode(t *testing.T) {
	eng, on, err := BuildCost(costTestConfig(), intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildCost: %v", err)
	}
	correlator := incident.NewCorrelator(incident.NewMemoryStore(), time.Hour, intelTestLog())
	cc := NewCostConsumer(nil, eng, correlator, intelTestLog()).
		WithTenantBinding(strictLaneBinding{}).WithStrictTenantLanes(true)

	// A forged batch from a registered pair, claiming tenant-real, on the SHARED
	// lane. Strict mode refuses the shared lane, so no cost is attributed.
	raw, err := proto.Marshal(&flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId: "tenant-real", AgentId: "agent-real",
		SourceAddress: "10.0.1.5", DestinationAddress: "10.0.2.7",
		Bytes: 10 << 30, EndUnixNano: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatal(err)
	}
	if s := eng.Summary("tenant-real"); len(s.ByService) != 0 || len(s.ByTeam) != 0 {
		t.Fatalf("forged shared-lane batch was attributed: %+v", s.ByService)
	}
}

func TestCarbonVerifiesTenantAndCountsRejections(t *testing.T) {
	eng, on, err := BuildCarbon(&config.Config{CarbonEnabled: true, CarbonGridGCO2E: 400}, intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildCarbon: %v", err)
	}
	cc := NewCarbonConsumer(nil, eng, intelTestLog()).
		WithTenantBinding(strictLaneBinding{}).WithStrictTenantLanes(true)

	batch := func(tenant, agent string) []byte {
		raw, err := proto.Marshal(&flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
			TenantId: tenant, AgentId: agent,
			SourceAddress: "10.0.0.1", DestinationAddress: "203.0.113.9",
			Bytes: 1 << 30, EndUnixNano: time.Now().UnixNano(),
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	// 1. Forged on the SHARED lane by a registered pair → refused (strict mode).
	if err := cc.handleLane(context.Background(), bus.Message{Value: batch("tenant-real", "agent-real")}, ""); err != nil {
		t.Fatal(err)
	}
	// 2. Forged on the VICTIM's namespaced lane by an agent not bound to it → refused.
	if err := cc.handleLane(context.Background(), bus.Message{Value: batch("tenant-victim", "agent-real")}, "tenant-victim"); err != nil {
		t.Fatal(err)
	}
	if got := cc.RejectedFlowBatches(); got != 2 {
		t.Fatalf("carbon rejection counter = %d, want 2", got)
	}
	if s := eng.Summary("tenant-real"); s.TotalBytes != 0 {
		t.Fatalf("forged shared-lane batch wrote tenant-real carbon: %d bytes", s.TotalBytes)
	}
	if s := eng.Summary("tenant-victim"); s.TotalBytes != 0 {
		t.Fatalf("unregistered agent wrote tenant-victim carbon: %d bytes", s.TotalBytes)
	}

	// 3. Legitimate: tenant-real's own namespaced lane with its registered agent.
	if err := cc.handleLane(context.Background(), bus.Message{Value: batch("tenant-real", "agent-real")}, "tenant-real"); err != nil {
		t.Fatal(err)
	}
	if got := cc.RejectedFlowBatches(); got != 2 {
		t.Fatalf("legitimate namespaced batch was rejected (counter=%d)", got)
	}
	if s := eng.Summary("tenant-real"); s.TotalBytes != 1<<30 {
		t.Fatalf("legitimate carbon sample missing: %d bytes", s.TotalBytes)
	}
}
