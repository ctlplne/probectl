// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

const witnessTenant = "11111111-1111-4111-8111-111111111111"
const witnessAgent = "22222222-2222-4222-8222-222222222222"

func routingEvidenceRecordForTest(at time.Time) Record {
	return Record{TenantID: witnessTenant, AgentID: witnessAgent, Exporter: "192.0.2.1", Protocol: ProtoIPFIX, ObservationDomain: ^uint32(0), ObservedAt: at, Start: at, End: at, SrcAddr: netip.MustParseAddr("203.0.113.1"), DstAddr: netip.MustParseAddr("2001:db8::1"), Bytes: ^uint64(0), Packets: 1, SamplingRate: 1}
}

func TestFlowEvidencePreservesEveryConfiguredDomainBeyondTransportAndCachePages(t *testing.T) {
	at := time.Now().UTC()
	c := &Collector{cfg: &Config{TenantID: witnessTenant, AgentID: witnessAgent, BatchSize: 5001}, evidenceSources: map[string]struct{}{"192.0.2.1": {}}}
	batch := make([]Record, 5001)
	for i := range batch {
		batch[i] = routingEvidenceRecordForTest(at)
		batch[i].ObservationDomain = uint32(i)
	}
	claims, keys := c.flowEvidenceClaims(batch, nil, nil, nil, at)
	if len(keys) != len(batch) || len(claims) != len(batch)*2 {
		t.Fatalf("complete configured source batch lost identity evidence: claims=%d keys=%d records=%d", len(claims), len(keys), len(batch))
	}
	for i, key := range keys {
		if key.domain != uint32(i) || claims[i*2+1].SourceRef != "flow:ipfix:domain:"+strconv.FormatUint(uint64(i), 10) {
			t.Fatal("complete configured source order or domain changed")
		}
	}
}

type routingWitnessCapture struct {
	entered  chan []*agentv1.FlowRoutingWitness
	release  chan struct{}
	identity atomic.Uint64
	pages    atomic.Uint64
	partial  bool
}

func (r *routingWitnessCapture) Submit(_ context.Context, claims []entity.Observation) (int, int, error) {
	if len(claims) > 64 || len(claims)%2 != 0 {
		return 0, 0, errors.New("invalid source transport page")
	}
	r.identity.Add(uint64(len(claims)))
	r.pages.Add(1)
	return len(claims), 0, nil
}
func (r *routingWitnessCapture) SubmitFlowRouting(ctx context.Context, raw []*agentv1.FlowRoutingWitness) ([]*agentv1.FlowRoutingCapture, error) {
	owned := make([]*agentv1.FlowRoutingWitness, len(raw))
	for i, v := range raw {
		owned[i] = proto.Clone(v).(*agentv1.FlowRoutingWitness)
	}
	select {
	case r.entered <- owned:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-r.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if r.partial {
		return nil, nil
	}
	out := make([]*agentv1.FlowRoutingCapture, len(raw))
	for i := range out {
		out[i] = &agentv1.FlowRoutingCapture{Key: make([]byte, 32), CapturedUnixNanos: 1}
	}
	return out, nil
}

func TestFlowRoutingWorkerKeepsCompleteEligibleRecordsWithoutWaitingOnRPC(t *testing.T) {
	at := time.Now().UTC()
	raw := &routingRawCapture{}
	sink := &routingWitnessCapture{entered: make(chan []*agentv1.FlowRoutingWitness, 2), release: make(chan struct{})}
	c := &Collector{cfg: &Config{TenantID: witnessTenant, AgentID: witnessAgent, BatchSize: 502}, emit: raw, log: slog.New(slog.NewTextHandler(io.Discard, nil)), evidence: sink, evidenceSources: map[string]struct{}{"192.0.2.1": {}}, evidenceQueue: make(chan []Record, 1), clock: func() time.Time { return at }}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); c.evidenceLoop(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	batch := make([]Record, 502)
	for i := range batch {
		batch[i] = routingEvidenceRecordForTest(at)
		batch[i].ObservationDomain = uint32(i)
		batch[i].Bytes = uint64(i)
	}
	batch[501].Exporter = "192.0.2.99" // raw telemetry stays complete; no configured witness
	flushed := make(chan struct{})
	go func() { c.flushBatch(ctx, batch); close(flushed) }()
	select {
	case <-flushed:
	case <-time.After(time.Second):
		t.Fatal("raw flow delivery waited for evidence RPC")
	}
	var first []*agentv1.FlowRoutingWitness
	select {
	case first = <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("complete source identity pages never reached witness worker")
	}
	if len(first) != 501 || sink.identity.Load() != 1002 || sink.pages.Load() != 16 || raw.count.Load() != 502 {
		t.Fatal("worker truncated configured records or source transport pages", len(first), sink.identity.Load(), sink.pages.Load(), raw.count.Load())
	}
	for i, witness := range first {
		digest, _, err := RoutingCaptureWitness(ctx, batch[i].ToProto(), 128<<20, 128<<20)
		if err != nil || !bytes.Equal(witness.RawDigest, digest[:]) || witness.ObservationDomain != uint32(i) {
			t.Fatal("producer witness changed complete original record identity", i, err)
		}
	}
	// A blocked metadata RPC cannot delay another raw batch. Its bounded queue
	// retains one pending batch, which must still get a witness after release.
	c.flushBatch(ctx, batch[:1])
	if raw.count.Load() != 503 {
		t.Fatal("blocked witness worker dropped raw flow")
	}
	close(sink.release)
	select {
	case second := <-sink.entered:
		if len(second) != 1 {
			t.Fatal("queued complete flow lost witness")
		}
	case <-time.After(time.Second):
		t.Fatal("identity throttle suppressed a new routing witness")
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for c.stats.RoutingWitnessReceipts.Load() != 502 {
		select {
		case <-deadline.C:
			t.Fatal("witness worker did not finish its complete queued batch")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
	stats := c.StatsSnapshot()
	if stats.RoutingWitnessReceipts != 502 || stats.RoutingWitnessErrors != 0 || stats.DroppedRecords != 0 || sink.identity.Load() != 1002 {
		t.Fatal("witness accounting or source throttle changed raw delivery", stats, sink.identity.Load())
	}
}

func TestFlowRoutingWitnessProducerRefusesForeignUnconfiguredAndPartialMetadata(t *testing.T) {
	at := time.Now().UTC()
	sink := &routingWitnessCapture{entered: make(chan []*agentv1.FlowRoutingWitness, 1), release: make(chan struct{}), partial: true}
	close(sink.release)
	c := &Collector{cfg: &Config{TenantID: witnessTenant, AgentID: witnessAgent, BatchSize: 2}, evidence: sink, evidenceSources: map[string]struct{}{"192.0.2.1": {}}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	record := routingEvidenceRecordForTest(at)
	for _, mutate := range []func(*Record){func(r *Record) { r.TenantID = "foreign" }, func(r *Record) { r.AgentID = "foreign" }, func(r *Record) { r.SrcAddr = netip.Addr{} }} {
		changed := record
		mutate(&changed)
		if partial, err := c.routingWitnesses(t.Context(), []Record{record, changed}); err == nil || partial != nil {
			t.Fatal("foreign or malformed source exposed partial routing witnesses", err)
		}
	}
	unconfigured := record
	unconfigured.Exporter = "192.0.2.99"
	if got, err := c.routingWitnesses(t.Context(), []Record{unconfigured}); err != nil || len(got) != 0 {
		t.Fatal("unconfigured exporter authored routing witness", err)
	}
	c.sendRoutingWitnesses(t.Context(), []Record{record})
	if stats := c.StatsSnapshot(); stats.RoutingWitnessReceipts != 0 || stats.RoutingWitnessErrors != 1 {
		t.Fatal("partial RPC response counted as a complete routing witness", stats)
	}
}
