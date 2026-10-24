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
	"github.com/ctlplne/probectl/internal/pipeline"
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

// stripUnknownField is the counter label for dropped unknown proto fields;
// stripCallDropped counts L7 calls dropped whole under a length floor.
const (
	stripUnknownField = "unknown_field"
	stripCallDropped  = "call_dropped"
)

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

	// binding verifies a pooled-lane record's (tenant, agent) before its
	// tenant's floor is looked up (review S10); nil = unit tests and the
	// registry-less lightweight mode, where only UUID-shaped tenants are read.
	binding pipeline.TenantBinding

	mu    sync.Mutex
	cache map[string]cachedFloor
	order []string // insertion order, for the cache bound

	counts   map[string]*atomic.Uint64
	counters map[string]*metrics.Counter
	// byTenant is each verified tenant's own tally (bounded like the cache).
	byTenant    map[string]map[string]uint64
	tenantOrder []string
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
	for _, f := range append(l7redact.StripFields(), stripUnknownField, stripCallDropped) {
		counts[f] = &atomic.Uint64{}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &L7IngestStrip{floors: floors, regulated: regulated, log: log, cache: map[string]cachedFloor{}, counts: counts,
		byTenant: map[string]map[string]uint64{}}
}

// maxFloorCache bounds the floor cache (one entry per active tenant).
const maxFloorCache = 4096

// WithTenantBinding verifies a pooled-lane record's (tenant, agent) pair
// against the registry before the door reads that tenant's floor (S10): a
// sprayed fake tenant id costs no database read and no cache entry.
func (s *L7IngestStrip) WithTenantBinding(b pipeline.TenantBinding) *L7IngestStrip {
	if s != nil {
		s.binding = b
	}
	return s
}

// WithMetrics registers the strip counter on the control plane's /metrics.
func (s *L7IngestStrip) WithMetrics(reg *metrics.Registry) *L7IngestStrip {
	if s != nil && reg != nil {
		s.counters = reg.LabeledCounter(L7StripMetric,
			"L7 record fields the control-plane ingest strip removed before anything persisted, by kind (D-43).",
			"field", append(l7redact.StripFields(), stripUnknownField, stripCallDropped))
	}
	return s
}

// Counts returns the deployment-wide strip totals by label (/metrics and the
// provider plane's bundle; a tenant's bundle uses CountsFor).
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
	if _, ok := s.cache[tenant]; !ok {
		if len(s.order) >= maxFloorCache {
			delete(s.cache, s.order[0])
			s.order = s.order[1:]
		}
		s.order = append(s.order, tenant)
	}
	s.cache[tenant] = cachedFloor{mode: mode, expires: now.Add(ttl)}
	s.mu.Unlock()
	return mode
}

// trustedTenant reports whether a call's tenant may have its floor read: a
// namespaced lane names its tenant; on the pooled lane the (tenant, agent)
// pair must verify against the registry (memoized per batch). Anything else
// is stripped to the metadata default without a lookup — the consumers
// reject such a record anyway.
func (s *L7IngestStrip) trustedTenant(ctx context.Context, laneTenant string, c *ebpfv1.L7Call, memo map[[2]string]bool) bool {
	if laneTenant != "" {
		return true
	}
	key := [2]string{c.GetTenantId(), c.GetAgentId()}
	if v, ok := memo[key]; ok {
		return v
	}
	var ok bool
	if s.binding != nil {
		ok = s.binding.Verify(ctx, key[0], key[1]) == nil
	} else {
		ok = uuidShaped(key[0])
	}
	memo[key] = ok
	return ok
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// uuidShaped reports whether v is a canonical 8-4-4-4-12 hex id.
func uuidShaped(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch i {
		case 8, 13, 18, 23:
			if v[i] != '-' {
				return false
			}
		default:
			if !isHexDigit(v[i]) {
				return false
			}
		}
	}
	return true
}

// Apply strips batch in place. laneTenant is the namespaced lane's tenant
// ("" on the pooled lane); counted selects whether this strip feeds the
// counters — only the persisting consumer's, so one record is counted once per
// control plane, not once per consumer that reads it. A nil strip strips to
// the metadata default.
func (s *L7IngestStrip) Apply(ctx context.Context, batch *ebpfv1.FlowBatch, laneTenant string, counted bool) {
	s.orDefault().apply(ctx, batch, laneTenant, counted)
}

func (s *L7IngestStrip) apply(ctx context.Context, batch *ebpfv1.FlowBatch, laneTenant string, count bool) {
	if batch == nil {
		return
	}
	memo := map[[2]string]bool{}
	owner := s.batchTenant(ctx, laneTenant, batch, memo)
	unknown := dropUnknownFields(batch)
	var fieldStrips l7redact.Strip
	fieldStrips |= clampRecordFields(batch)
	if count && fieldStrips != 0 {
		for _, f := range fieldStrips.Fields() {
			s.add(owner, f, 1)
		}
	}
	kept := batch.L7Calls[:0]
	for _, c := range batch.GetL7Calls() {
		mode, who := govern.EffectiveL7CaptureFloor("", s.regulated), ""
		if s.trustedTenant(ctx, laneTenant, c, memo) {
			mode, who = s.floor(ctx, c.GetTenantId()), c.GetTenantId()
		}
		if !l7redact.Persists(mode) {
			// D-43 S7: a length floor persists no L7 call at all — no
			// method, route or status — whoever produced it.
			if count {
				s.add(who, stripCallDropped, 1)
			}
			continue
		}
		kept = append(kept, c)
		m, strip := l7redact.MinimizeWith(l7redact.Call{
			Protocol: c.GetProtocol(), Method: c.GetMethod(), Resource: c.GetResource(), Status: c.GetStatus(),
		}, mode, l7redact.Options{DNSRegisteredDomainOnly: s.regulated})
		if !validDNSFeatures(c.GetDnsFeatures()) {
			c.DnsFeatures, strip = nil, strip|l7redact.StripLabel
		}
		c.Protocol, c.Method, c.Resource, c.Status = m.Protocol, m.Method, m.Resource, m.Status
		if count {
			for _, f := range strip.Fields() {
				s.add(who, f, 1)
			}
		}
	}
	for i := len(kept); i < len(batch.L7Calls); i++ {
		batch.L7Calls[i] = nil
	}
	batch.L7Calls = kept
	if count && unknown > 0 {
		s.add(owner, stripUnknownField, uint64(unknown))
	}
}

// batchTenant is the verified tenant a whole batch belongs to — the lane
// tenant, or on the pooled lane the one tenant every record names when its
// (tenant, agent) pair verifies — or "" when it has none. Batch-level strips
// (fields, unknown fields) are attributed to it.
func (s *L7IngestStrip) batchTenant(ctx context.Context, laneTenant string, batch *ebpfv1.FlowBatch, memo map[[2]string]bool) string {
	if laneTenant != "" {
		return laneTenant
	}
	tenant, agent := "", ""
	note := func(t, a string) bool {
		if t == "" {
			return true
		}
		if tenant == "" {
			tenant = t
		}
		if agent == "" {
			agent = a
		}
		return t == tenant
	}
	for _, f := range batch.GetFlows() {
		if !note(f.GetTenantId(), f.GetAgentId()) {
			return ""
		}
	}
	for _, e := range batch.GetEdges() {
		if !note(e.GetTenantId(), "") {
			return ""
		}
	}
	for _, c := range batch.GetL7Calls() {
		if !note(c.GetTenantId(), c.GetAgentId()) {
			return ""
		}
	}
	if tenant == "" || !s.trustedTenant(ctx, "", &ebpfv1.L7Call{TenantId: tenant, AgentId: agent}, memo) {
		return ""
	}
	return tenant
}

// add counts one strip: on the deployment total (and /metrics), and on the
// verified tenant's own tally (review S11: a tenant's support bundle carries
// only its own counts; an unverified record counts on the total only).
func (s *L7IngestStrip) add(tenant, field string, n uint64) {
	if c, ok := s.counts[field]; ok {
		c.Add(n)
	}
	if c, ok := s.counters[field]; ok {
		c.Add(n)
	}
	if tenant == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.byTenant[tenant]
	if !ok {
		if len(s.tenantOrder) >= maxFloorCache {
			delete(s.byTenant, s.tenantOrder[0])
			s.tenantOrder = s.tenantOrder[1:]
		}
		m = map[string]uint64{}
		s.byTenant[tenant] = m
		s.tenantOrder = append(s.tenantOrder, tenant)
	}
	m[field] += n
}

// CountsFor returns one tenant's strip counts by label (every label present).
func (s *L7IngestStrip) CountsFor(tenant string) map[string]uint64 {
	out := map[string]uint64{}
	if s == nil {
		return out
	}
	for k := range s.counts {
		out[k] = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.byTenant[tenant] {
		out[k] = v
	}
	return out
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

// validDNSFeatures bounds the D-65 detector features a producer sends: real
// entropy and lengths, tokens of exactly the agent's token size — numbers and
// opaque 8-byte tokens, never a place to carry a name.
func validDNSFeatures(f *ebpfv1.DNSFeatures) bool {
	if f == nil {
		return true
	}
	if f.GetFirstLabelEntropy() < 0 || f.GetFirstLabelEntropy() > 8 || f.GetFirstLabelLength() > 255 || f.GetQnameBytes() > 255 {
		return false
	}
	for _, tok := range [][]byte{f.GetNameToken(), f.GetSubdomainToken()} {
		if len(tok) != 0 && len(tok) != dnsTokenBytes {
			return false
		}
	}
	return true
}

// dnsTokenBytes is the eBPF agent's DNS token size (internal/ebpf).
const dnsTokenBytes = 8

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
	strip.Apply(ctx, &batch, laneTenant, counted)
	return &batch, nil
}
