// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ctlplne/probectl/internal/bus"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/l7redact"
	"github.com/ctlplne/probectl/internal/metrics"
)

// The control-plane ingest strip (D-43, the second layer): whatever an agent
// sent, every L7 record is reduced to its tenant's redaction floor at ingest —
// after the lane tenant is stamped and before any consumer projects or persists
// it — with the SAME function the agent applies (l7redact.Minimize), so the
// two layers cannot disagree. A misconfigured, outdated or hostile producer
// therefore cannot put payload into a store. Under the regulated profile every
// tenant's floor is at least metadata. Fields the schema does not know (proto
// unknown fields — where a newer or forged producer would carry header values
// or body bytes) are dropped from every message in the batch.

// L7StripMetric is the strip counter: one series per strip label, never a value
// from the record.
const L7StripMetric = "probectl_ebpf_l7_ingest_stripped_total"

// stripUnknownField is the counter label for dropped unknown proto fields.
const stripUnknownField = "unknown_field"

// l7FloorReader resolves a tenant's effective floor (govern.PolicyStore).
type l7FloorReader interface {
	L7CaptureFloor(ctx context.Context, tenantID string, regulated bool) (string, error)
}

// Floor cache bounds: a read per tenant per window, never per record; a failed
// read is retried soon and meanwhile applies metadata (fail closed).
const (
	l7FloorTTL      = 30 * time.Second
	l7FloorErrorTTL = 5 * time.Second
)

// L7IngestStrip is the shared ingest door every eBPF batch consumer decodes
// through. The zero value and a nil *L7IngestStrip are usable: with no floor
// reader every tenant gets the metadata default.
type L7IngestStrip struct {
	floors    l7FloorReader
	regulated bool
	log       *slog.Logger

	mu    sync.Mutex
	cache map[string]cachedFloor

	counts   map[string]*atomic.Uint64
	counters map[string]*metrics.Counter
}

type cachedFloor struct {
	mode    string
	expires time.Time
}

// NewL7IngestStrip builds the strip over the tenants' governance rows.
func NewL7IngestStrip(floors *govern.PolicyStore, regulated bool, log *slog.Logger) *L7IngestStrip {
	s := newL7IngestStrip(nil, regulated, log)
	if floors != nil {
		s.floors = floors
	}
	return s
}

func newL7IngestStrip(floors l7FloorReader, regulated bool, log *slog.Logger) *L7IngestStrip {
	counts := map[string]*atomic.Uint64{}
	for _, f := range append(l7redact.StripFields(), stripUnknownField) {
		counts[f] = &atomic.Uint64{}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &L7IngestStrip{floors: floors, regulated: regulated, log: log, cache: map[string]cachedFloor{}, counts: counts}
}

// WithMetrics registers the strip counter on the control plane's /metrics.
func (s *L7IngestStrip) WithMetrics(reg *metrics.Registry) *L7IngestStrip {
	if s != nil && reg != nil {
		s.counters = reg.LabeledCounter(L7StripMetric,
			"L7 record fields the control-plane ingest strip removed before anything persisted, by kind (D-43).",
			"field", append(l7redact.StripFields(), stripUnknownField))
	}
	return s
}

// Counts returns the strip totals by label (the support bundle reports them).
func (s *L7IngestStrip) Counts() map[string]uint64 {
	out := map[string]uint64{}
	if s == nil {
		return out
	}
	for k, v := range s.counts {
		out[k] = v.Load()
	}
	return out
}

// WithL7IngestStrip lets the server report the deployment's ingest strip
// counters (the support bundle's l7-capture section).
func (s *Server) WithL7IngestStrip(st *L7IngestStrip) *Server {
	s.l7strip = st
	return s
}

// defaultL7Strip serves consumers that were not wired with one: metadata for
// every tenant, which is the strictest-useful default (fail closed).
var defaultL7Strip = newL7IngestStrip(nil, false, nil)

func (s *L7IngestStrip) orDefault() *L7IngestStrip {
	if s == nil {
		return defaultL7Strip
	}
	return s
}

// floor returns the tenant's effective floor, cached.
func (s *L7IngestStrip) floor(ctx context.Context, tenant string) string {
	if s.floors == nil || tenant == "" {
		return govern.EffectiveL7CaptureFloor("", s.regulated)
	}
	now := time.Now()
	s.mu.Lock()
	c, ok := s.cache[tenant]
	s.mu.Unlock()
	if ok && now.Before(c.expires) {
		return c.mode
	}
	mode, err := s.floors.L7CaptureFloor(ctx, tenant, s.regulated)
	ttl := l7FloorTTL
	if err != nil {
		s.log.Warn("ebpf ingest: L7 redaction floor unavailable, stripping to metadata (fail closed)",
			"tenant_id", tenant, "error", err.Error())
		mode, ttl = l7redact.Stricter(l7redact.DefaultMode, govern.EffectiveL7CaptureFloor("", s.regulated)), l7FloorErrorTTL
	}
	s.mu.Lock()
	s.cache[tenant] = cachedFloor{mode: mode, expires: now.Add(ttl)}
	s.mu.Unlock()
	return mode
}

// Apply strips batch in place and counts what it removed (the persisting
// consumer's call). ApplyUncounted is the same strip for the read-model
// consumers, so one record is counted once per control plane, not once per
// consumer that reads it.
func (s *L7IngestStrip) Apply(ctx context.Context, batch *ebpfv1.FlowBatch) {
	s.orDefault().apply(ctx, batch, true)
}

// ApplyUncounted strips batch in place without counting.
func (s *L7IngestStrip) ApplyUncounted(ctx context.Context, batch *ebpfv1.FlowBatch) {
	s.orDefault().apply(ctx, batch, false)
}

func (s *L7IngestStrip) apply(ctx context.Context, batch *ebpfv1.FlowBatch, count bool) {
	if batch == nil {
		return
	}
	unknown := dropUnknownFields(batch)
	var fieldStrips l7redact.Strip
	fieldStrips |= clampRecordFields(batch)
	if count && fieldStrips != 0 {
		for _, f := range fieldStrips.Fields() {
			s.add(f, 1)
		}
	}
	for _, c := range batch.GetL7Calls() {
		mode := s.floor(ctx, c.GetTenantId())
		m, strip := l7redact.Minimize(l7redact.Call{
			Protocol: c.GetProtocol(), Method: c.GetMethod(), Resource: c.GetResource(), Status: c.GetStatus(),
		}, mode)
		c.Protocol, c.Method, c.Resource, c.Status = m.Protocol, m.Method, m.Resource, m.Status
		if count {
			for _, f := range strip.Fields() {
				s.add(f, 1)
			}
		}
	}
	if count && unknown > 0 {
		s.add(stripUnknownField, uint64(unknown))
	}
}

func (s *L7IngestStrip) add(field string, n uint64) {
	if c, ok := s.counts[field]; ok {
		c.Add(n)
	}
	if c, ok := s.counters[field]; ok {
		c.Add(n)
	}
}

// clampRecordFields validates every non-call free-text field of the batch that
// a consumer persists or projects (D-43 S4): enum fields to their vocabulary,
// identifier fields to an identifier's shape and bound. The edge's l7_protocol
// lands in the eBPF store and the topology graph, so it is an enum here like
// the call's protocol.
func clampRecordFields(batch *ebpfv1.FlowBatch) l7redact.Strip {
	var strip l7redact.Strip
	clamp := func(dst *string, fn func(string) (string, l7redact.Strip)) {
		v, st := fn(*dst)
		*dst, strip = v, strip|st
	}
	transport := func(v string) (string, l7redact.Strip) { return l7redact.Enum(v, "tcp", "udp") }
	for _, e := range batch.GetEdges() {
		clamp(&e.L7Protocol, l7redact.Protocol)
		clamp(&e.NetworkTransport, transport)
		clamp(&e.Source, l7redact.Label)
		clamp(&e.Destination, l7redact.Label)
	}
	for _, f := range batch.GetFlows() {
		clamp(&f.NetworkTransport, transport)
		clamp(&f.NetworkType, func(v string) (string, l7redact.Strip) { return l7redact.Enum(v, "ipv4", "ipv6") })
		clamp(&f.Direction, func(v string) (string, l7redact.Strip) { return l7redact.Enum(v, "ingress", "egress") })
		clamp(&f.State, func(v string) (string, l7redact.Strip) { return l7redact.Enum(v, "established", "close") })
		for _, p := range []*string{&f.Host, &f.SourceAddress, &f.DestinationAddress, &f.ProcessName, &f.ContainerId, &f.Workload} {
			clamp(p, l7redact.Label)
		}
	}
	for _, c := range batch.GetL7Calls() {
		clamp(&c.Protocol, l7redact.Protocol)
		clamp(&c.Source, l7redact.Label)
		clamp(&c.Destination, l7redact.Label)
	}
	return strip
}

// dropUnknownFields clears the unknown-field bytes of every message in the
// batch tree and returns how many messages carried any.
func dropUnknownFields(batch *ebpfv1.FlowBatch) int {
	n := 0
	drop := func(m protoreflect.Message) {
		if len(m.GetUnknown()) > 0 {
			m.SetUnknown(nil)
			n++
		}
	}
	drop(batch.ProtoReflect())
	for _, f := range batch.GetFlows() {
		drop(f.ProtoReflect())
	}
	for _, e := range batch.GetEdges() {
		drop(e.ProtoReflect())
	}
	for _, c := range batch.GetL7Calls() {
		drop(c.ProtoReflect())
	}
	return n
}

// decodeEBPFBatch is the one ingest door for probectl.ebpf.flows: unmarshal,
// stamp the lane tenant (a namespaced lane names its tenant and always wins),
// then strip L7 records to each tenant's floor — in that order, so the floor
// that applies is the lane tenant's, never a payload claim. counted selects
// whether this consumer's strip feeds the counter (only the persisting one).
func decodeEBPFBatch(ctx context.Context, strip *L7IngestStrip, msg bus.Message, laneTenant string, counted bool) (*ebpfv1.FlowBatch, error) {
	var batch ebpfv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		return nil, fmt.Errorf("decode ebpf batch: %w", err)
	}
	stampEBPFBatchLaneTenant(&batch, laneTenant)
	if counted {
		strip.Apply(ctx, &batch)
	} else {
		strip.ApplyUncounted(ctx, &batch)
	}
	return &batch, nil
}
