// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/threat"
)

func ndrEngine(t *testing.T, intel threat.IntelSource) *threat.Engine {
	t.Helper()
	eng, on, err := BuildNDR(&config.Config{NDREnabled: true}, intel, nil, intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildNDR: on=%v err=%v", on, err)
	}
	return eng
}

func TestBuildNDRDisabledAndFailClosed(t *testing.T) {
	if _, on, err := BuildNDR(&config.Config{NDREnabled: false}, nil, nil, intelTestLog()); on || err != nil {
		t.Fatalf("disabled: on=%v err=%v", on, err)
	}
	// A rules dir the operator pointed at but that is unreadable must abort.
	if _, _, err := BuildNDR(&config.Config{NDREnabled: true, NDRRulesDir: "/does/not/exist"}, nil, nil, intelTestLog()); err == nil {
		t.Fatal("missing rules dir must fail startup")
	}
}

// A flow batch whose destination sits on a threat-intel feed becomes a
// detection in the triage store AND a correlated incident — the full export
// path, as a signal (nothing blocks; guardrail 9).
func TestNDRConsumerFlowToDetectionAndIncident(t *testing.T) {
	intel := loadedIOCStore() // 192.0.2.66 = feodo botnet C2 (confidence 90)
	detections := threat.NewDetectionStore(0)
	correlator := incident.NewCorrelator(incident.NewMemoryStore(), time.Hour, intelTestLog())
	cs := NewNDRConsumer(nil, ndrEngine(t, intel), correlator, intelTestLog()).WithDetections(detections)

	batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId:           "t1",
		SourceAddress:      "10.0.0.4",
		DestinationAddress: "192.0.2.66",
		DestinationPort:    443,
		Bytes:              2048,
		ObservedAtUnixNano: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano(),
	}}}
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.handleFlowBatch(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}

	items := detections.List("t1")
	if len(items) != 1 {
		t.Fatalf("detections = %d, want 1", len(items))
	}
	d := items[0]
	if d.Kind != "ndr.egress_intel" || d.Source != "ndr-egress-intel-default" ||
		d.Category != "botnet_c2" || d.Type != "ip" || d.License != "abuse.ch CC0" ||
		d.Indicator != "192.0.2.66" {
		t.Fatalf("detection = %+v", d)
	}
	if d.IncidentID == "" {
		t.Fatal("detection not correlated into an incident")
	}
	if d.Confidence < 60 {
		t.Fatalf("confidence = %d", d.Confidence)
	}
	// Tenant isolation on the read side.
	if leak := detections.List("other-tenant"); len(leak) != 0 {
		t.Fatalf("cross-tenant detections: %+v", leak)
	}
}

// eBPF L7 DNS calls feed the DGA detector: a host resolving a stream of
// generated-looking names raises one confidence-scored detection.
func TestNDRConsumerEBPFDNSToDGADetection(t *testing.T) {
	detections := threat.NewDetectionStore(0)
	cs := NewNDRConsumer(nil, ndrEngine(t, nil), nil, intelTestLog()).WithDetections(detections)

	calls := make([]*ebpfv1.L7Call, 0, 25)
	for i := 0; i < 25; i++ {
		calls = append(calls, &ebpfv1.L7Call{
			TenantId: "t1", Source: "host-7", Protocol: "dns",
			Resource:      fmt.Sprintf("xq%dk7vz0my%dwt3hjb%dfp8c.evil-rendezvous.example", i*7+13, i*31+5, i*17+3),
			StartUnixNano: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).UnixNano(),
		})
	}
	raw, err := proto.Marshal(&ebpfv1.FlowBatch{L7Calls: calls})
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.handleEBPFBatch(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}
	items := detections.List("t1")
	if len(items) != 1 {
		t.Fatalf("detections = %d, want 1 (suppression after the first)", len(items))
	}
	if items[0].Kind != "ndr.dns_dga" || items[0].Entity != "host-7" {
		t.Fatalf("detection = %+v", items[0])
	}
}

// Records without a tenant are DROPPED, never guessed into a tenant
// (guardrail 1: fail closed at the boundary).
func TestNDRConsumerDropsUnscopedRecords(t *testing.T) {
	detections := threat.NewDetectionStore(0)
	intel := loadedIOCStore()
	cs := NewNDRConsumer(nil, ndrEngine(t, intel), nil, intelTestLog()).WithDetections(detections)

	batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		// no TenantId
		SourceAddress: "10.0.0.4", DestinationAddress: "192.0.2.66", DestinationPort: 443,
		ObservedAtUnixNano: time.Now().UnixNano(),
	}}}
	raw, _ := proto.Marshal(batch)
	if err := cs.handleFlowBatch(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", "t1", "default"} {
		if got := detections.List(tenant); len(got) != 0 {
			t.Fatalf("unscoped record produced detections under %q: %+v", tenant, got)
		}
	}
}
