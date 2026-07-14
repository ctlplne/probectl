// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pipeline

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

// stubEnricher returns a fixed enrichment for any IP.
type stubEnricher struct{ calls int }

func (s *stubEnricher) Enrich(_ context.Context, ip string) (opendata.Enrichment, error) {
	s.calls++
	return opendata.Enrichment{IP: ip, ASN: 64999, ASName: "STUB-NET", CountryCode: "DE"}, nil
}

// TestFlowConsumerEndToEnd publishes a FlowBatch on the memory bus and asserts
// enriched rows land in the flow store — the full ingest path the control
// plane runs (bus -> enrich -> ClickHouse-equivalent store).
func TestFlowConsumerEndToEnd(t *testing.T) {
	b := bus.NewMemory()
	st := flowstore.NewMemory()
	en := &stubEnricher{}
	c := NewFlowConsumer(b, st, en, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	time.Sleep(20 * time.Millisecond) // let the subscription attach

	end := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{
		{ // device asserted its own AS: enrichment must NOT override it
			TenantId: "t-a", AgentId: "a1", ExporterAddress: "203.0.113.10", FlowProtocol: "netflow5",
			EndUnixNano: end.UnixNano(), SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2",
			SourceAsn: 64500, SourceAsName: "DEVICE-SAYS", Bytes: 100, BytesScaled: 100, PacketsScaled: 1,
			InputInterface: 1,
		},
		{ // no AS from the device: enrichment fills it
			TenantId: "t-a", AgentId: "a1", ExporterAddress: "203.0.113.10", FlowProtocol: "ipfix",
			EndUnixNano: end.UnixNano(), SourceAddress: "10.0.0.3", DestinationAddress: "10.0.0.4",
			BytesScaled: 200, PacketsScaled: 2, InputInterface: 1,
		},
	}}
	value, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, bus.FlowEventsTopic, []byte("t-a"), value); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for st.Len() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("rows did not land (have %d)", st.Len())
		}
		time.Sleep(5 * time.Millisecond)
	}

	top, err := st.TopTalkers(ctx, flowstore.TopQuery{TenantID: "t-a", By: flowstore.BySrcASN, Window: time.Hour, Now: end.Add(time.Minute)})
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	asns := map[string]string{}
	for _, r := range top {
		asns[r.Key] = r.Detail
	}
	if asns["64500"] != "DEVICE-SAYS" {
		t.Errorf("device-asserted ASN overridden: %v", asns)
	}
	if asns["64999"] != "STUB-NET" {
		t.Errorf("enrichment did not fill missing ASN: %v", asns)
	}
	if en.calls == 0 {
		t.Error("enricher never called")
	}

	// Malformed payloads are dropped without wedging the consumer.
	if err := b.Publish(ctx, bus.FlowEventsTopic, []byte("t-a"), []byte("garbage")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if st.Len() != 2 {
		t.Errorf("garbage changed the store: %d rows", st.Len())
	}
}

// TestFlowConsumerNilEnricher: enrichment is opt-in; nil must pass records
// through untouched (sovereignty default — no external lookups).
func TestFlowConsumerNilEnricher(t *testing.T) {
	b := bus.NewMemory()
	st := flowstore.NewMemory()
	c := NewFlowConsumer(b, st, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)

	end := time.Now().UTC()
	value, _ := proto.Marshal(&flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId: "t-a", SourceAddress: "10.0.0.9", EndUnixNano: end.UnixNano(), BytesScaled: 5, PacketsScaled: 1,
	}}})
	_ = b.Publish(ctx, bus.FlowEventsTopic, []byte("t-a"), value)

	deadline := time.Now().Add(2 * time.Second)
	for st.Len() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("row did not land")
		}
		time.Sleep(5 * time.Millisecond)
	}
	top, _ := st.TopTalkers(ctx, flowstore.TopQuery{TenantID: "t-a", By: flowstore.BySrcASN, Window: time.Hour, Now: end.Add(time.Minute)})
	if len(top) != 0 {
		t.Errorf("ASN appeared without enrichment: %+v", top)
	}
}
