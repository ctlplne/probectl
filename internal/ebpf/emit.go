// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/ebpf/l7"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/version"
)

// Emitter publishes a batch of observed flows + the current service edges. The
// agent emits OTel-shaped records; BusEmitter marshals them to protobuf and
// publishes to probectl.ebpf.flows, but the seam lets a future OTLP exporter (S22)
// drop in without touching the runtime.
type Emitter interface {
	Emit(ctx context.Context, flows []Flow, edges []ServiceEdge, l7 []L7Record) error
}

// DefaultMaxBatchBytes bounds one published FlowBatch record (DPR-071). Kafka
// rejects a record above the client's 1,000,012-byte batch limit (and the
// broker's 1 MiB message.max.bytes) with MESSAGE_TOO_LARGE — asynchronously,
// after Publish has already returned nil. The service map is a CUMULATIVE
// snapshot that travels with every flush, so on a busy host a single record
// grows past that limit within minutes; the agent then "emits" forever while
// nothing arrives. 768 KiB leaves headroom for record framing and compression
// metadata under both defaults.
const DefaultMaxBatchBytes = 768 * 1024

// BusEmitter publishes FlowBatches to the bus, tenant-keyed (pooled tagging).
type BusEmitter struct {
	bus      bus.Bus
	tenant   string
	topic    string // shared, or the tenant's namespaced lane (TENANT-107)
	maxBytes int    // per-record bound; 0 = one record per flush (unbounded)
}

// WithMaxBatchBytes bounds each published record to n encoded bytes; a flush
// larger than that is split into several FlowBatch records (DPR-071). n <= 0
// disables the bound (one record per flush — lightweight/test only).
func (e *BusEmitter) WithMaxBatchBytes(n int) *BusEmitter {
	if n < 0 {
		n = 0
	}
	e.maxBytes = n
	return e
}

// NewBusEmitter returns an Emitter that publishes to probectl.ebpf.flows.
func NewBusEmitter(b bus.Bus, tenant string) *BusEmitter {
	e, _ := NewNamespacedBusEmitter(b, tenant, "")
	return e
}

// NewNamespacedBusEmitter publishes to the tenant's namespaced lane when
// namespace is set (TENANT-107). A malformed namespace refuses construction
// (RED-006: never a silent shared-lane fallback).
func NewNamespacedBusEmitter(b bus.Bus, tenant, namespace string) (*BusEmitter, error) {
	topic, err := bus.TopicFor(namespace, bus.EBPFFlowsTopic)
	if err != nil {
		return nil, fmt.Errorf("ebpf: refusing to start: %w", err)
	}
	return &BusEmitter{bus: b, tenant: tenant, topic: topic, maxBytes: DefaultMaxBatchBytes}, nil
}

// Emit marshals the batch and publishes it — as one record when it fits the
// per-record bound, otherwise as several FlowBatch records that together carry
// exactly the flush (DPR-071). An empty batch is a no-op.
func (e *BusEmitter) Emit(ctx context.Context, flows []Flow, edges []ServiceEdge, l7calls []L7Record) error {
	if len(flows) == 0 && len(edges) == 0 && len(l7calls) == 0 {
		return nil
	}
	pflows := make([]*ebpfv1.Flow, 0, len(flows))
	for i := range flows {
		pflows = append(pflows, flows[i].toProto())
	}
	pedges := make([]*ebpfv1.ServiceEdge, 0, len(edges))
	for i := range edges {
		pedges = append(pedges, edges[i].toProto())
	}
	pl7 := make([]*ebpfv1.L7Call, 0, len(l7calls))
	for i := range l7calls {
		pl7 = append(pl7, l7calls[i].toProto())
	}
	entropy := ""
	if len(flows) > 0 {
		entropy = flows[0].AgentID
	}
	key := bus.TenantKey(e.tenant, entropy)
	// DPR-093: every record names the agent's build version so the fleet view
	// and staged rollouts learn it from the batches themselves.
	chunks := chunkFlowBatches(pflows, pedges, pl7, e.maxBytes, version.Get().Version)
	for i, batch := range chunks {
		value, err := proto.Marshal(batch)
		if err != nil {
			return fmt.Errorf("ebpf: marshal flow batch: %w", err)
		}
		if err := e.bus.Publish(ctx, e.topic, key, value); err != nil {
			return fmt.Errorf("ebpf: publish flow batch %d/%d: %w", i+1, len(chunks), err)
		}
	}
	return nil
}

// encodedSize is the wire size of one repeated-field element inside a
// FlowBatch: a one-byte tag (field numbers 1–3), the length varint, the body.
func encodedSize(m proto.Message) int {
	n := proto.Size(m)
	return 1 + protowire.SizeVarint(uint64(n)) + n
}

// chunkFlowBatches splits one flush into FlowBatch records of at most limit
// encoded bytes (limit <= 0: a single record). Edges are packed first; flows
// and L7 calls are then dealt round-robin across those records so every record
// that carries edges also carries flows whenever the flush has enough of them —
// the topology view verifies a batch's tenant through its flows and rejects an
// edges-only batch under strict binding (TENANT-006), so an edges-only record
// must never be manufactured by the split. Elements that do not fit alongside
// the edges spill into additional records.
func chunkFlowBatches(flows []*ebpfv1.Flow, edges []*ebpfv1.ServiceEdge, l7 []*ebpfv1.L7Call, limit int, agentVersion string) []*ebpfv1.FlowBatch {
	if limit <= 0 {
		return []*ebpfv1.FlowBatch{{Flows: flows, Edges: edges, L7Calls: l7, AgentVersion: agentVersion}}
	}
	// DPR-093: every record carries the agent's build version; its wire bytes
	// count against the bound like any other field.
	overhead := 0
	if agentVersion != "" {
		overhead = 1 + protowire.SizeVarint(uint64(len(agentVersion))) + len(agentVersion)
	}
	// Reserve room in every edge record for at least one flow and one L7 call.
	reserve := 0
	for _, f := range flows {
		if n := encodedSize(f); n > reserve {
			reserve = n
		}
	}
	maxL7 := 0
	for _, c := range l7 {
		if n := encodedSize(c); n > maxL7 {
			maxL7 = n
		}
	}
	reserve += maxL7
	edgeBudget := limit - reserve
	if edgeBudget < limit/4 {
		edgeBudget = limit / 4
	}
	type chunk struct {
		batch *ebpfv1.FlowBatch
		size  int
	}
	var chunks []*chunk
	newChunk := func() *chunk {
		c := &chunk{batch: &ebpfv1.FlowBatch{AgentVersion: agentVersion}, size: overhead}
		chunks = append(chunks, c)
		return c
	}
	cur := newChunk()
	for _, e := range edges {
		n := encodedSize(e)
		if cur.size > 0 && cur.size+n > edgeBudget {
			cur = newChunk()
		}
		cur.batch.Edges = append(cur.batch.Edges, e)
		cur.size += n
	}
	edgeChunks := len(chunks)
	// Deal the remaining elements round-robin over the edge records; whatever
	// does not fit spills into fresh records (greedy).
	var spill *chunk
	deal := func(n int, add func(*ebpfv1.FlowBatch)) {
		for i := 0; i < edgeChunks; i++ {
			c := chunks[i]
			if c.size+n <= limit {
				add(c.batch)
				c.size += n
				return
			}
		}
		if spill == nil || spill.size+n > limit {
			spill = newChunk()
		}
		add(spill.batch)
		spill.size += n
	}
	next := 0
	dealFrom := func(n int, add func(*ebpfv1.FlowBatch)) {
		// Rotate the starting record so consecutive elements land on
		// different records (round-robin), then fall back to any with room.
		for i := 0; i < edgeChunks; i++ {
			c := chunks[(next+i)%edgeChunks]
			if c.size+n <= limit {
				add(c.batch)
				c.size += n
				next = (next + i + 1) % edgeChunks
				return
			}
		}
		deal(n, add)
	}
	for _, f := range flows {
		f := f
		dealFrom(encodedSize(f), func(b *ebpfv1.FlowBatch) { b.Flows = append(b.Flows, f) })
	}
	for _, c := range l7 {
		c := c
		dealFrom(encodedSize(c), func(b *ebpfv1.FlowBatch) { b.L7Calls = append(b.L7Calls, c) })
	}
	out := make([]*ebpfv1.FlowBatch, 0, len(chunks))
	for _, c := range chunks {
		if len(c.batch.Flows) == 0 && len(c.batch.Edges) == 0 && len(c.batch.L7Calls) == 0 {
			continue
		}
		out = append(out, c.batch)
	}
	return out
}

func (f Flow) toProto() *ebpfv1.Flow {
	return &ebpfv1.Flow{
		TenantId:           f.TenantID,
		AgentId:            f.AgentID,
		Host:               f.Host,
		ObservedAtUnixNano: unixNano(f.Observed),
		SourceAddress:      f.Source.Address,
		SourcePort:         f.Source.Port,
		DestinationAddress: f.Destination.Address,
		DestinationPort:    f.Destination.Port,
		NetworkTransport:   f.Transport,
		NetworkType:        f.NetworkType,
		Pid:                f.Source.PID,
		ProcessName:        f.Source.Process,
		ContainerId:        f.Source.Container,
		Workload:           f.Source.Workload,
		Bytes:              f.Bytes,
		Packets:            f.Packets,
		Direction:          f.Direction,
		State:              f.State,
	}
}

func (e ServiceEdge) toProto() *ebpfv1.ServiceEdge {
	return &ebpfv1.ServiceEdge{
		TenantId:          e.TenantID,
		Source:            e.Source,
		Destination:       e.Destination,
		DestinationPort:   e.DestPort,
		NetworkTransport:  e.Transport,
		Connections:       e.Connections,
		Bytes:             e.Bytes,
		Packets:           e.Packets,
		FirstSeenUnixNano: unixNano(e.FirstSeen),
		LastSeenUnixNano:  unixNano(e.LastSeen),
		L7Protocol:        e.L7Protocol,
		L7Calls:           e.L7Calls,
		L7Errors:          e.L7Errors,
		L7LatencySumNano:  e.L7LatencySum.Nanoseconds(),
		L7LatencyMaxNano:  e.L7LatencyMax.Nanoseconds(),
	}
}

// L7Record is one parsed L7 call plus the connection/edge context the agent
// stamps it with (the client→server orientation), ready to emit and roll up.
type L7Record struct {
	TenantID    string
	AgentID     string
	Source      Endpoint
	Destination Endpoint
	Transport   string
	Encrypted   bool
	TLS         TLSMetadata
	Call        l7.Call
}

// TLSMetadata is privacy-minimized handshake/certificate context. It carries
// no application payload and is safe to project into the TLS posture plane.
// Unknown visibility remains explicit instead of being guessed from a port.
type TLSMetadata struct {
	Visibility   string
	Version      string
	Cipher       string
	ServerName   string
	PeerCertDER  []byte
	Verification string
	Source       string
	HandshakeAt  time.Time
	Confidence   uint32
}

func (r L7Record) toProto() *ebpfv1.L7Call {
	return &ebpfv1.L7Call{
		TenantId:              r.TenantID,
		AgentId:               r.AgentID,
		Source:                r.Source.ID(),
		Destination:           r.Destination.ID(),
		DestinationPort:       r.Destination.Port,
		Protocol:              r.Call.Protocol,
		Method:                r.Call.Method,
		Resource:              r.Call.Resource,
		Status:                r.Call.Status,
		Error:                 r.Call.Error,
		Encrypted:             r.Encrypted,
		StartUnixNano:         unixNano(r.Call.Start),
		LatencyNano:           r.Call.Latency.Nanoseconds(),
		RequestBytes:          r.Call.ReqBytes,
		ResponseBytes:         r.Call.RespBytes,
		TlsVisibility:         r.TLS.Visibility,
		TlsVersion:            r.TLS.Version,
		TlsCipher:             r.TLS.Cipher,
		TlsServerName:         r.TLS.ServerName,
		TlsPeerCertificateDer: append([]byte(nil), r.TLS.PeerCertDER...),
		TlsVerification:       r.TLS.Verification,
		TlsObservationSource:  r.TLS.Source,
		TlsHandshakeUnixNano:  unixNano(r.TLS.HandshakeAt),
		TlsConfidence:         r.TLS.Confidence,
	}
}

func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
