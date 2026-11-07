// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const flowCaptureTenantA = "11111111-1111-4111-8111-111111111111"
const flowCaptureTenantB = "22222222-2222-4222-8222-222222222222"
const flowCaptureSender = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

type changingCaptureEnricher struct{ calls uint32 }

func (e *changingCaptureEnricher) Enrich(context.Context, string) (opendata.Enrichment, error) {
	e.calls++
	return opendata.Enrichment{ASN: 64500 + e.calls, ASName: "changed after raw fingerprint", CountryCode: "US"}, nil
}

func flowCaptureBatchForTest(count int) *flowv1.FlowBatch {
	batch := &flowv1.FlowBatch{Flows: make([]*flowv1.FlowRecord, count)}
	for i := range batch.Flows {
		batch.Flows[i] = &flowv1.FlowRecord{TenantId: "original-payload-tenant", AgentId: flowCaptureSender, ExporterAddress: "192.0.2.1", FlowProtocol: []string{"netflow5", "netflow9", "ipfix", "sflow5"}[i%4], ObservationDomain: ^uint32(0) - uint32(i), SourceAddress: "203.0.113.1", DestinationAddress: "2001:db8::1", SourcePort: uint32(i + 1), EndUnixNano: time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano(), BytesScaled: 1}
		batch.Flows[i].ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
	}
	return batch
}

func captureBatchMessageForTest(t *testing.T, batch *flowv1.FlowBatch) bus.Message {
	t.Helper()
	body, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Topic: bus.FlowEventsTopic, Value: body}
}

func TestFlowCaptureConsumerKeepsOriginalDigestFrozenClockAndTenant(t *testing.T) {
	const count = 501
	batch := flowCaptureBatchForTest(count)
	message := captureBatchMessageForTest(t, batch)
	originalBytes := bytes.Clone(message.Value)
	firstAt := time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)
	expected := map[[32]byte]entity.FlowCaptureInput{}
	for _, record := range batch.Flows {
		digest, err := flow.OriginalFlowDigest(t.Context(), record, 16<<20, 16<<20)
		if err != nil {
			t.Fatal(err)
		}
		input, ok := flowCaptureTuple(record)
		if !ok {
			t.Fatal("invalid golden tuple")
		}
		expected[digest] = input
	}
	var resolutions int
	resolve := func(ctx context.Context, sender string, digest [32]byte, input entity.FlowCaptureInput) (entity.FlowCaptureReference, error) {
		tenant, ok := tenancy.FromContext(ctx)
		if !ok || (tenant.String() != flowCaptureTenantA && tenant.String() != flowCaptureTenantB) || sender != flowCaptureSender || expected[digest] != input {
			t.Fatal("capture consumer lost verified tenant or original raw digest before enrichment")
		}
		key, err := entity.FlowCaptureKey(tenant.String(), sender, digest, input)
		resolutions++
		return entity.FlowCaptureReference{Key: key, CapturedAt: firstAt}, err
	}
	store := flowstore.NewMemory()
	consumer := NewFlowConsumer(nil, store, &changingCaptureEnricher{}, nil).WithRoutingCaptures(resolve, 16<<20, 16<<20)
	consumer.WithTenantBinding(&fakeBinding{pairs: map[[2]string]bool{{flowCaptureTenantA, flowCaptureSender}: true, {flowCaptureTenantB, flowCaptureSender}: true}})
	for _, tenant := range []string{flowCaptureTenantA, flowCaptureTenantA, flowCaptureTenantB} {
		if err := consumer.handleLane(t.Context(), message, message.Topic, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if resolutions != count*3 || store.Len() != count*2 || !bytes.Equal(message.Value, originalBytes) {
		t.Fatal("capture consumer lost complete population, raw bytes or enrichment-stable dedup", resolutions, store.Len())
	}
	for _, tenant := range []string{flowCaptureTenantA, flowCaptureTenantB} {
		rows, err := store.TopTalkers(t.Context(), flowstore.TopQuery{TenantID: tenant, By: flowstore.ByExporter, Window: time.Minute, Now: firstAt.Add(time.Second)})
		if err != nil || len(rows) != 1 || rows[0].Flows != count || rows[0].Bytes != count {
			t.Fatal("capture consumer replaced frozen first clock or crossed tenant", rows, err)
		}
		var out bytes.Buffer
		if n, err := store.ExportTenant(t.Context(), tenant, &out); err != nil || n != count {
			t.Fatal(n, err)
		}
		decoder := json.NewDecoder(&out)
		for decoder.More() {
			var row flowstore.Row
			if err := decoder.Decode(&row); err != nil {
				t.Fatal(err)
			}
			raw, err := hex.DecodeString(row.RawFlowDigest)
			if err != nil || len(raw) != 32 || row.TenantID != tenant || row.RoutingCaptureKey == "" || row.RoutingCapturedUnixNanos != firstAt.UnixNano() {
				t.Fatal("capture consumer omitted persisted immutable reference")
			}
		}
	}
}

func TestFlowCaptureConsumerRefusesPartialUnscopedAndMismatchedResolution(t *testing.T) {
	message := captureBatchMessageForTest(t, flowCaptureBatchForTest(3))
	for _, mode := range []string{"memory", "work", "aggregate-memory", "wrong-key", "missing-clock", "resolver-failure", "foreign-context"} {
		t.Run(mode, func(t *testing.T) {
			store := flowstore.NewMemory()
			calls := 0
			resolve := func(_ context.Context, sender string, digest [32]byte, input entity.FlowCaptureInput) (entity.FlowCaptureReference, error) {
				calls++
				key, err := entity.FlowCaptureKey(flowCaptureTenantA, sender, digest, input)
				ref := entity.FlowCaptureReference{Key: key, CapturedAt: time.Unix(1700000000, 123456789)}
				switch mode {
				case "wrong-key":
					ref.Key[0] ^= 1
				case "missing-clock":
					ref.CapturedAt = time.Time{}
				case "resolver-failure":
					return entity.FlowCaptureReference{}, errors.New("first receipt storage unavailable")
				}
				return ref, err
			}
			memory, work := int64(1<<20), int64(1<<20)
			if mode == "memory" {
				memory = 1
			}
			if mode == "work" {
				work = 1
			}
			if mode == "aggregate-memory" {
				memory = 256*3 + int64(proto.Size(flowCaptureBatchForTest(3).Flows[0]))*4 + 64
			}
			consumer := NewFlowConsumer(nil, store, nil, nil).WithRoutingCaptures(resolve, memory, work)
			ctx := t.Context()
			if mode == "foreign-context" {
				ctx = tenancy.WithTenant(ctx, tenancy.ID(flowCaptureTenantB))
			}
			err := consumer.handleLane(ctx, message, message.Topic, flowCaptureTenantA)
			if err == nil || store.Len() != 0 || ((mode == "memory" || mode == "work" || mode == "aggregate-memory" || mode == "foreign-context") && calls != 0) {
				t.Fatal("partial or foreign capture batch reached storage or was acknowledged", err, store.Len(), calls)
			}
		})
	}
}
