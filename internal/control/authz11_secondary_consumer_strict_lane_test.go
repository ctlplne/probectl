// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

// AUTHZ-11 (RTP-02, WIRE-001, docs/guardrails.md G7-1): the SECONDARY bus
// consumers — NDR, eBPF TLS posture, carbon, and the BGP-derived incident /
// topology consumers — each consume a shared pooled lane whose tenant is only
// producer-asserted (the payload tenant_id, or, for BGP, the forgeable message
// key). In a strict (regulated / multi-tenant) profile that shared lane must be
// refused outright, so a forged-tenant batch raises NO record under the victim
// tenant: no detection, no incident, no SIEM export, no TLS posture row, no
// carbon accounting, no routing edge. Each case drives the REAL consumer entry
// point and asserts both the refusal and a positive control (the same input on
// the tenant's namespaced lane IS recorded), so the test fails if the consumer
// ever silently stops verifying.

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/siem"
	"github.com/ctlplne/probectl/internal/threat"
	"github.com/ctlplne/probectl/internal/topology"
)

// TestNDRRefusesForgedSharedLaneFlowInStrictMode: a flow to a known botnet C2
// (feodo 192.0.2.66) from a REGISTERED pair would normally raise an egress-intel
// detection + incident. On the shared lane in strict mode the batch is refused,
// so neither is produced; on the tenant's namespaced lane the detection stands.
func TestNDRRefusesForgedSharedLaneFlowInStrictMode(t *testing.T) {
	intel := loadedIOCStore()
	store := incident.NewMemoryStore()
	correlator := incident.NewCorrelator(store, time.Hour, intelTestLog())
	detections := threat.NewDetectionStore(0)
	cs := NewNDRConsumer(nil, ndrEngine(t, intel), correlator, intelTestLog()).
		withDetections(detections).
		WithTenantBinding(ndrFakeBinding{"agent-real": "tenant-real"}).
		WithStrictTenantLanes(true)

	raw := mustAuthz11FlowBatch(t, "tenant-real", "agent-real", "192.0.2.66")

	// Shared pooled lane (laneTenant ""): refused in strict mode — no side effect.
	if err := cs.handleFlowBatchLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatalf("handleFlowBatchLane (shared): %v", err)
	}
	if got := detections.Len("tenant-real"); got != 0 {
		t.Fatalf("forged shared-lane flow raised %d detection(s) under tenant-real; want 0", got)
	}
	if open, err := store.OpenIncidents(context.Background(), "tenant-real"); err != nil || len(open) != 0 {
		t.Fatalf("forged shared-lane flow correlated %d incident(s) (err=%v); want 0", len(open), err)
	}

	// Positive control: the SAME batch on the tenant's own namespaced lane IS a
	// detection — proving the input would have scored, so the refusal above is
	// the lane check and not an inert fixture.
	if err := cs.handleFlowBatchLane(context.Background(), bus.Message{Value: raw}, "tenant-real"); err != nil {
		t.Fatalf("handleFlowBatchLane (namespaced): %v", err)
	}
	if got := detections.Len("tenant-real"); got != 1 {
		t.Fatalf("namespaced-lane flow raised %d detection(s); want 1 (positive control)", got)
	}
}

// TestEBPFTLSPostureRefusesForgedSharedLaneBatchInStrictMode: a registered pair
// on the shared lane would project a TLS posture row pre-fix (non-strict
// registry check). Strict mode refuses the shared lane, so no row is projected;
// the namespaced lane still projects it.
func TestEBPFTLSPostureRefusesForgedSharedLaneBatchInStrictMode(t *testing.T) {
	postures := threat.NewPostureStore(0)
	cs := NewEBPFTLSPostureConsumer(nil, postures, buildTLSAnalyzer(&config.Config{}), intelTestLog()).
		WithTenantBinding(ndrFakeBinding{"agent-a": "tenant-a"}).
		WithStrictTenantLanes(true)

	raw := mustAuthz11TLSBatch(t, "tenant-a", "agent-a")

	// Shared pooled lane: refused in strict mode — no posture row.
	if err := cs.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatalf("handleLane (shared): %v", err)
	}
	if got := postures.Len("tenant-a"); got != 0 {
		t.Fatalf("forged shared-lane eBPF batch projected %d TLS posture row(s); want 0", got)
	}

	// Positive control: the namespaced lane projects the observed posture.
	if err := cs.handleLane(context.Background(), bus.Message{Value: raw}, "tenant-a"); err != nil {
		t.Fatalf("handleLane (namespaced): %v", err)
	}
	if got := postures.Len("tenant-a"); got != 1 {
		t.Fatalf("namespaced-lane eBPF batch projected %d posture row(s); want 1 (positive control)", got)
	}
}

// TestCarbonRefusesForgedSharedLaneFlowInStrictMode: the real consumer entry
// point drops a forged shared-lane flow batch in strict mode, so no bytes land
// in the victim tenant's ESG accounting; the namespaced lane still accounts them.
func TestCarbonRefusesForgedSharedLaneFlowInStrictMode(t *testing.T) {
	eng, on, err := BuildCarbon(&config.Config{CarbonEnabled: true, CarbonGridGCO2E: 400}, intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildCarbon: on=%v err=%v", on, err)
	}
	cc := NewCarbonConsumer(nil, eng, intelTestLog()).
		WithTenantBinding(ndrFakeBinding{"agent-real": "tenant-real"}).
		WithStrictTenantLanes(true)

	raw := mustAuthz11FlowBatch(t, "tenant-real", "agent-real", "203.0.113.9")

	// Shared pooled lane: refused — no carbon accounting.
	if err := cc.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatalf("handleLane (shared): %v", err)
	}
	if s := eng.Summary("tenant-real"); s.TotalBytes != 0 {
		t.Fatalf("forged shared-lane flow wrote %d carbon bytes under tenant-real; want 0", s.TotalBytes)
	}
	if got := cc.RejectedFlowBatches(); got != 1 {
		t.Fatalf("carbon rejection counter = %d, want 1", got)
	}

	// Positive control: the namespaced lane accounts the bytes.
	if err := cc.handleLane(context.Background(), bus.Message{Value: raw}, "tenant-real"); err != nil {
		t.Fatalf("handleLane (namespaced): %v", err)
	}
	if s := eng.Summary("tenant-real"); s.TotalBytes == 0 {
		t.Fatal("namespaced-lane flow wrote no carbon bytes; want > 0 (positive control)")
	}
}

// TestBGPIncidentRefusesForgedSharedLaneEventInStrictMode: a BGP event on the
// shared lane carries its tenant only in the forgeable message key. Strict mode
// refuses the shared lane, so neither an incident nor a SIEM export is produced;
// the namespaced lane still correlates and exports it.
func TestBGPIncidentRefusesForgedSharedLaneEventInStrictMode(t *testing.T) {
	snk := &capSender{}
	fmtr, _ := siem.NewFormatter("cef")
	fw := siem.NewForwarder(fmtr, snk, siem.Config{BufferSize: 8, RetryBackoff: time.Millisecond}, testLog())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = fw.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	store := incident.NewMemoryStore()
	cs := NewBGPIncidentConsumer(nil, incident.NewCorrelator(store, time.Hour, testLog()), testLog()).
		WithSIEM(fw).
		WithStrictTenantLanes(true)

	raw := mustAuthz11BGPEvent(t, "tenant-victim")
	key := bus.TenantKey("tenant-victim", "rrc00")

	// Shared pooled lane (laneTenant ""): refused in strict mode — no record.
	if err := cs.handleLane(ctx, bus.Message{Key: key, Value: raw}, ""); err != nil {
		t.Fatalf("handleLane (shared): %v", err)
	}
	if open, err := store.OpenIncidents(ctx, "tenant-victim"); err != nil || len(open) != 0 {
		t.Fatalf("forged shared-lane BGP event correlated %d incident(s) (err=%v); want 0", len(open), err)
	}
	if got := len(snk.records()); got != 0 {
		t.Fatalf("forged shared-lane BGP event emitted %d SIEM record(s); want 0", got)
	}

	// Positive control: the tenant's namespaced lane correlates + exports it.
	if err := cs.handleLane(ctx, bus.Message{Key: key, Value: raw}, "tenant-victim"); err != nil {
		t.Fatalf("handleLane (namespaced): %v", err)
	}
	waitFor(t, func() bool { return len(snk.records()) == 1 })
	if open, err := store.OpenIncidents(ctx, "tenant-victim"); err != nil || len(open) != 1 {
		t.Fatalf("namespaced-lane BGP event correlated %d incident(s) (err=%v); want 1 (positive control)", len(open), err)
	}
}

// TestTopologyBGPRefusesForgedSharedLaneEventInStrictMode: the topology
// consumer's BGP handler also derives the shared-lane tenant from the message
// key. Strict mode refuses the shared lane, so no routing edge is stored (the
// rejection is counted); the namespaced lane still stores it.
func TestTopologyBGPRefusesForgedSharedLaneEventInStrictMode(t *testing.T) {
	ctx := context.Background()
	raw := mustAuthz11BGPEvent(t, "tenant-victim")
	key := bus.TenantKey("tenant-victim", "rrc00")

	tc := NewTopologyConsumer(nil, topology.NewMemoryStore(), intelTestLog()).
		WithStrictTenantLanes(true)

	// Shared pooled lane: refused in strict mode — nothing stored, rejection counted.
	if err := tc.handleBGP(ctx, bus.Message{Key: key, Value: raw}); err != nil {
		t.Fatalf("handleBGP (shared): %v", err)
	}
	if stats := tc.integrityStats(); stats.BGP.Received != 1 || stats.BGP.Rejected != 1 || stats.BGP.Stored != 0 {
		t.Fatalf("forged shared-lane BGP topology stats = %+v, want received=1 rejected=1 stored=0", stats.BGP)
	}

	// Positive control: a fresh consumer stores the same event on its namespaced lane.
	tc2 := NewTopologyConsumer(nil, topology.NewMemoryStore(), intelTestLog()).
		WithStrictTenantLanes(true)
	if err := tc2.handleBGPLane(ctx, bus.Message{Key: key, Value: raw}, "tenant-victim"); err != nil {
		t.Fatalf("handleBGPLane (namespaced): %v", err)
	}
	if stats := tc2.integrityStats(); stats.BGP.Stored != 1 || stats.BGP.Rejected != 0 {
		t.Fatalf("namespaced-lane BGP topology stats = %+v, want stored=1 rejected=0 (positive control)", stats.BGP)
	}
}

func mustAuthz11FlowBatch(t *testing.T, tenant, agent, dst string) []byte {
	t.Helper()
	raw, err := proto.Marshal(&flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId:           tenant,
		AgentId:            agent,
		SourceAddress:      "10.0.0.4",
		DestinationAddress: dst,
		DestinationPort:    443,
		Bytes:              2048,
		EndUnixNano:        time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano(),
		ObservedAtUnixNano: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustAuthz11TLSBatch(t *testing.T, tenant, agent string) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := proto.Marshal(&ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{{
		TenantId: tenant, AgentId: agent, Destination: "10.0.0.8", DestinationPort: 443,
		TlsVisibility: "observed", TlsVersion: "1.3", TlsCipher: "TLS_AES_128_GCM_SHA256",
		TlsServerName: "api.example", TlsObservationSource: "fixture",
		TlsHandshakeUnixNano: now.UnixNano(), TlsConfidence: 94,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustAuthz11BGPEvent(t *testing.T, tenant string) []byte {
	t.Helper()
	raw, err := proto.Marshal(&bgpv1.BGPEvent{
		TenantId: tenant, EventType: bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
		Severity: bgpv1.Severity_SEVERITY_CRITICAL, Prefix: "216.75.128.0/25",
		Message: "sub-prefix 216.75.128.0/25 announced by unexpected AS65010", NewOriginAsn: 65010,
		Collector: "rrc00", DetectedAtUnixNano: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
