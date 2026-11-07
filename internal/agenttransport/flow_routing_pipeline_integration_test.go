// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/flow"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real issued mTLS and routed Postgres with a memory bus/flow store and modeled
// unowned source. This proves runtime ordering, not a physical routing join or
// ClickHouse persistence.
func proveFlowRoutingRuntimeOrdering(t *testing.T, pool *pgxpool.Pool, tenant, sender string, client *agent.EvidenceClient) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	b := bus.NewMemory()
	rows := flowstore.NewMemory()
	budget := store.BGPRoutingBudget{MemoryBytes: 256 << 20, WorkUnits: 256 << 20, StateBytes: 1 << 30, LeaseDuration: time.Minute}
	consumer := pipeline.NewFlowConsumer(b, rows, nil, nil).
		WithTenantBinding(pipeline.NewRegistryBinding(pool)).
		WithRoutingCaptureStore(pool, budget)
	done := make(chan error, 1)
	go func() { done <- consumer.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		_ = b.Close()
	})
	if !b.WaitForSubscribers(ctx, bus.FlowEventsTopic, 1) {
		t.Fatal("runtime flow consumer did not subscribe")
	}
	for _, authFirst := range []bool{false, true} {
		record := &flowv1.FlowRecord{TenantId: tenant, AgentId: sender, ExporterAddress: "192.0.2.1", SourceAddress: "203.0.113.1", DestinationAddress: "2001:db8::1", FlowProtocol: "ipfix", ObservationDomain: ^uint32(0), Bytes: 41, BytesScaled: 41, EndUnixNano: time.Now().Add(time.Hour).UnixNano()}
		record.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
		if authFirst {
			record.SourcePort = 42
		}
		digest, input, err := flow.RoutingCaptureWitness(ctx, record, budget.MemoryBytes, budget.WorkUnits)
		if err != nil {
			t.Fatal(err)
		}
		witness := &agentv1.FlowRoutingWitness{RawDigest: digest[:], ExporterAddress: input.Exporter.String(), SourceAddress: input.Source.String(), DestinationAddress: input.Destination.String(), FlowProtocol: input.Protocol, ObservationDomain: input.Domain}
		attest := func() *agentv1.FlowRoutingCapture {
			t.Helper()
			refs, err := client.SubmitFlowRouting(ctx, []*agentv1.FlowRoutingWitness{witness})
			if err != nil || len(refs) != 1 {
				t.Fatal("runtime original witness lost its restricted sender channel", err)
			}
			return refs[0]
		}
		var receipt *agentv1.FlowRoutingCapture
		if authFirst {
			receipt = attest()
		}
		body, err := proto.Marshal(&flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{record}})
		if err != nil {
			t.Fatal(err)
		}
		publish := func() {
			t.Helper()
			if err := b.Publish(ctx, bus.FlowEventsTopic, []byte(tenant), body); err != nil {
				t.Fatal(err)
			}
			if err := b.Flush(ctx); err != nil || b.HandlerErrors() != 0 {
				t.Fatal("runtime flow staging failed or retried", err, b.HandlerErrors())
			}
		}
		publish()
		if !authFirst {
			receipt = attest()
		}
		publish()
		var exported bytes.Buffer
		if _, err := rows.ExportTenant(ctx, tenant, &exported); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(&exported)
		matched := 0
		for decoder.More() {
			var row flowstore.Row
			if err := decoder.Decode(&row); err != nil {
				t.Fatal(err)
			}
			if row.RawFlowDigest != hex.EncodeToString(digest[:]) {
				continue
			}
			matched++
			if row.TenantID != tenant || row.RoutingCaptureKey != hex.EncodeToString(receipt.Key) || row.RoutingCapturedUnixNanos != receipt.CapturedUnixNanos || row.Bytes != 41 {
				t.Fatal("runtime raw/evidence race changed original bytes, first clock or tenant")
			}
		}
		if matched != 1 {
			t.Fatal("runtime raw retry lost or duplicated the original flow", matched)
		}
		// TS is deliberately excluded from the portable Row JSON. Verify the
		// real analytics axis through an exact first-clock query instead.
		at := time.Unix(0, receipt.CapturedUnixNanos)
		points, err := rows.TopTalkers(ctx, flowstore.TopQuery{TenantID: tenant, By: flowstore.ByExporter, Window: time.Nanosecond, Now: at})
		if err != nil || len(points) != 1 || points[0].Flows != 1 || points[0].Bytes != 41 {
			t.Fatal("runtime raw/evidence race changed the first analytics clock", points, err)
		}
		if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var outcome string
			var payloads int
			err := sc.Q.QueryRow(ctx, `SELECT outcome,(SELECT count(*) FROM bgp_flow_capture_payloads) FROM bgp_flow_capture_receipts WHERE flow_key=$1`, receipt.Key).Scan(&outcome, &payloads)
			if err == nil && (outcome != "unavailable" || payloads != 0) {
				t.Fatal("runtime unowned raw tuple invented canonical route evidence")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if rows.Len() != 2 {
		t.Fatal("runtime original flow observations were conflated or lost", rows.Len())
	}
}
