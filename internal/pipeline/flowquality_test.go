// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

func qualityProto(t *testing.T, tenant, agent, exporter string) *flowv1.FlowIngestQualityReceipt {
	t.Helper()
	end := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	last := end.Add(-time.Second)
	receipt := flow.EvaluateQualityState(flow.QualityReceipt{
		TenantID: tenant, AgentID: agent, ExporterAddress: exporter,
		Protocol: flow.ProtoIPFIX, WindowStartedAt: end.Add(-time.Minute),
		WindowEndedAt: end, LastPacketAt: last, LastValidRecordAt: &last,
		PacketsReceived: 4, RecordsDecoded: 8,
		TemplateState: flow.QualityTemplateReady,
		SamplingState: flow.QualitySamplingUnsampled,
	}, end)
	valid, err := flow.ValidateQualityReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return valid.ToProto()
}

func qualityMessage(t *testing.T, receipts ...*flowv1.FlowIngestQualityReceipt) bus.Message {
	t.Helper()
	raw, err := proto.Marshal(&flowv1.FlowIngestQualityBatch{
		ContractVersion: flow.QualityContractVersion,
		Receipts:        receipts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Topic: bus.FlowIngestQualityTopic, Value: raw}
}

func TestFlowQualityConsumerVerifiesIdentityAndKeepsTwoTenantsIsolated(t *testing.T) {
	store := flow.NewMemoryQualityStore()
	binding := &fakeBinding{pairs: map[[2]string]bool{
		{"tenant-a", "agent-a"}: true,
		{"tenant-b", "agent-b"}: true,
	}}
	consumer := NewFlowQualityConsumer(nil, store, nil).WithTenantBinding(binding)
	ctx := context.Background()
	if err := consumer.handle(ctx, qualityMessage(t, qualityProto(t, "tenant-a", "agent-a", "192.0.2.10"))); err != nil {
		t.Fatal(err)
	}
	if err := consumer.handle(ctx, qualityMessage(t, qualityProto(t, "tenant-b", "agent-b", "198.51.100.20"))); err != nil {
		t.Fatal(err)
	}
	// A credential for agent-a cannot inject a receipt under tenant-b.
	if err := consumer.handle(ctx, qualityMessage(t, qualityProto(t, "tenant-b", "agent-a", "203.0.113.30"))); err != nil {
		t.Fatal(err)
	}
	rowsA, _, err := store.ListQualityReceipts(ctx, "tenant-a", flow.QualityFilter{})
	if err != nil || len(rowsA) != 1 || rowsA[0].ExporterAddress != "192.0.2.10" {
		t.Fatalf("tenant-a rows=%+v err=%v", rowsA, err)
	}
	rowsB, _, err := store.ListQualityReceipts(ctx, "tenant-b", flow.QualityFilter{})
	if err != nil || len(rowsB) != 1 || rowsB[0].ExporterAddress != "198.51.100.20" {
		t.Fatalf("tenant-b rows=%+v err=%v", rowsB, err)
	}
}

func TestFlowQualityConsumerLaneTenantOverridesPayloadAndRejectsMixedAgentBatch(t *testing.T) {
	store := flow.NewMemoryQualityStore()
	consumer := NewFlowQualityConsumer(nil, store, nil)
	msg := qualityMessage(t, qualityProto(t, "forged", "agent-a", "192.0.2.10"))
	if err := consumer.handleLane(context.Background(), msg, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	rows, _, err := store.ListQualityReceipts(context.Background(), "tenant-a", flow.QualityFilter{})
	if err != nil || len(rows) != 1 || rows[0].TenantID != "tenant-a" {
		t.Fatalf("lane-stamped rows=%+v err=%v", rows, err)
	}

	mixed := qualityMessage(t,
		qualityProto(t, "tenant-a", "agent-a", "192.0.2.11"),
		qualityProto(t, "tenant-a", "agent-b", "192.0.2.12"),
	)
	if err := consumer.handleLane(context.Background(), mixed, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	rows, _, _ = store.ListQualityReceipts(context.Background(), "tenant-a", flow.QualityFilter{})
	if len(rows) != 1 {
		t.Fatalf("mixed-agent batch persisted: %+v", rows)
	}
}

func TestFlowQualityConsumerRejectsUnknownContractAndFreeFormFields(t *testing.T) {
	store := flow.NewMemoryQualityStore()
	consumer := NewFlowQualityConsumer(nil, store, nil)
	receipt := qualityProto(t, "tenant-a", "agent-a", "192.0.2.10")
	receipt.Reason = "raw decoder error containing packet text"
	raw, err := proto.Marshal(&flowv1.FlowIngestQualityBatch{
		ContractVersion: flow.QualityContractVersion,
		Receipts:        []*flowv1.FlowIngestQualityReceipt{receipt},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.handle(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}
	unknown, err := proto.Marshal(&flowv1.FlowIngestQualityBatch{
		ContractVersion: "future/v99",
		Receipts:        []*flowv1.FlowIngestQualityReceipt{qualityProto(t, "tenant-a", "agent-a", "192.0.2.11")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.handle(context.Background(), bus.Message{Value: unknown}); err != nil {
		t.Fatal(err)
	}
	missingTime := qualityProto(t, "tenant-a", "agent-a", "192.0.2.12")
	missingTime.LastPacketAtUnixNano = 0
	if err := consumer.handle(context.Background(), qualityMessage(t, missingTime)); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := store.ListQualityReceipts(context.Background(), "tenant-a", flow.QualityFilter{})
	if len(rows) != 0 {
		t.Fatalf("invalid receipt batches persisted: %+v", rows)
	}
}
