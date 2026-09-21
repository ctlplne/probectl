// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Memory is the in-process Store: the lightweight-mode backend, the test
// double, and the reference implementation the ClickHouse SQL must agree with.
// Rows are bounded (FIFO eviction) so an unconsumed dev deployment cannot grow
// without limit.
type Memory struct {
	mu   sync.Mutex
	rows []memoryRow
	seen map[string]int
	max  int
}

type memoryRow struct {
	row Row
	key string
}

// NewMemory builds a Memory store bounded to ~1M rows.
func NewMemory() *Memory {
	return NewMemoryWithLimit(1 << 20)
}

// NewMemoryWithLimit builds a Memory store with an explicit row cap. It is used
// by reference-scale harnesses that need to retain the whole measurement
// receipt while the product default remains bounded for lightweight mode.
func NewMemoryWithLimit(maxRows int) *Memory {
	if maxRows <= 0 {
		maxRows = 1 << 20
	}
	return &Memory{max: maxRows, seen: make(map[string]int)}
}

// Insert stores new rows, deduplicating at-least-once redeliveries by the same
// deterministic identity ClickHouse writes into row_id.
func (m *Memory) Insert(_ context.Context, rows []Row) error {
	if err := validateInsertRows(rows); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureSeenLocked()
	for _, row := range rows {
		key := flowRowID(row)
		if m.seen[key] > 0 {
			continue
		}
		m.rows = append(m.rows, memoryRow{row: row, key: key})
		m.seen[key]++
	}
	m.evictLocked()
	return nil
}

// Len reports stored rows (tests).
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

// inWindow snapshots the tenant's rows inside the query window — the tenant
// filter is applied before anything else (CLAUDE.md §6).
func (m *Memory) inWindow(tenant string, from, to time.Time) []Row {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Row, 0, 256)
	for _, entry := range m.rows {
		r := entry.row
		if r.TenantID != tenant {
			continue
		}
		if r.TS.Before(from) || r.TS.After(to) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// TopTalkers aggregates the window by the requested key.
func (m *Memory) TopTalkers(_ context.Context, q TopQuery) ([]TopRow, error) {
	if err := q.normalize(); err != nil {
		return nil, err
	}
	type agg struct {
		detail      string
		bytes, pkts uint64
		flows       uint64
		exporters   map[string]struct{}
	}
	groups := make(map[string]*agg)
	for _, r := range m.inWindow(q.TenantID, q.Now.Add(-q.Window), q.Now) {
		if !matchesFilters(r, q.Filters) {
			continue
		}
		key, detail, ok := groupRow(r, q.By)
		if !ok {
			continue
		}
		gk := groupKey(key, detail)
		g, ok := groups[gk]
		if !ok {
			g = &agg{detail: detail, exporters: make(map[string]struct{})}
			groups[gk] = g
		}
		g.bytes += r.BytesScaled
		g.pkts += r.PacketsScaled
		g.flows++
		addExporterIdentity(g.exporters, r.Exporter)
	}
	out := make([]TopRow, 0, len(groups))
	for gk, g := range groups {
		key := gk
		if i := indexByte(gk, 0); i >= 0 {
			key = gk[:i]
		}
		out = append(out, TopRow{
			Key:           key,
			Detail:        g.detail,
			Bytes:         g.bytes,
			Packets:       g.pkts,
			Flows:         g.flows,
			ExporterCount: uint64(len(g.exporters)),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// TopSeries aggregates the same filtered rows into aligned time buckets for
// the first six ranked contributors. The top list comes from TopTalkers, so
// the chart cannot disagree with the adjacent table about which keys are top.
func (m *Memory) TopSeries(_ context.Context, q TopQuery, top []TopRow) ([]SeriesPoint, error) {
	if err := q.normalize(); err != nil {
		return nil, err
	}
	keyLimit := seriesKeyLimit(top)
	if keyLimit == 0 {
		return []SeriesPoint{}, nil
	}
	selected := make(map[string]struct{}, keyLimit)
	for _, row := range top[:keyLimit] {
		selected[groupKey(row.Key, row.Detail)] = struct{}{}
	}
	type seriesKey struct {
		bucket int64
		key    string
		detail string
	}
	type agg struct {
		bytes, packets, flows uint64
		exporters             map[string]struct{}
	}
	groups := make(map[seriesKey]*agg)
	bucketSecs := int64(q.Bucket / time.Second)
	for _, r := range m.inWindow(q.TenantID, q.Now.Add(-q.Window), q.Now) {
		if !matchesFilters(r, q.Filters) {
			continue
		}
		key, detail, ok := groupRow(r, q.By)
		if !ok {
			continue
		}
		if _, ok := selected[groupKey(key, detail)]; !ok {
			continue
		}
		k := seriesKey{
			bucket: r.TS.Unix() / bucketSecs * bucketSecs,
			key:    key,
			detail: detail,
		}
		g := groups[k]
		if g == nil {
			g = &agg{exporters: make(map[string]struct{})}
			groups[k] = g
		}
		g.bytes += r.BytesScaled
		g.packets += r.PacketsScaled
		g.flows++
		addExporterIdentity(g.exporters, r.Exporter)
	}
	out := make([]SeriesPoint, 0, len(groups))
	for k, g := range groups {
		out = append(out, SeriesPoint{
			TS:            time.Unix(k.bucket, 0).UTC(),
			Key:           k.key,
			Detail:        k.detail,
			Bytes:         g.bytes,
			Packets:       g.packets,
			Flows:         g.flows,
			ExporterCount: uint64(len(g.exporters)),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].TS.Equal(out[j].TS) {
			return out[i].TS.Before(out[j].TS)
		}
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Detail < out[j].Detail
	})
	return out, nil
}

// addExporterIdentity preserves an aggregate when provenance is missing while
// refusing to turn an empty or whitespace-only value into a real observer.
// Trimming also makes the reference backend agree with ClickHouse for the
// untrusted stored value " edge-a " versus "edge-a".
func addExporterIdentity(exporters map[string]struct{}, raw string) {
	if exporter := strings.TrimSpace(raw); exporter != "" {
		exporters[exporter] = struct{}{}
	}
}

func groupKey(key, detail string) string { return key + "\x00" + detail }

func flowASNameGroupKey(r Row) string {
	if r.DstASName != "" {
		return r.DstASName
	}
	return r.SrcASName
}

func flowPortGroupKey(r Row) uint16 {
	if r.DstPort != 0 {
		return r.DstPort
	}
	return r.SrcPort
}

func groupRow(r Row, by string) (key, detail string, ok bool) {
	switch by {
	case BySrc:
		key = r.SrcAddr
	case ByDst:
		key = r.DstAddr
	case ByPair:
		key, detail = r.SrcAddr, r.DstAddr
	case BySrcASN:
		if r.SrcASN != 0 {
			key, detail = strconv.FormatUint(uint64(r.SrcASN), 10), r.SrcASName
		}
	case ByDstASN:
		if r.DstASN != 0 {
			key, detail = strconv.FormatUint(uint64(r.DstASN), 10), r.DstASName
		}
	case ByASName:
		key = flowASNameGroupKey(r)
	case BySrcCountry:
		key = r.SrcCountry
	case ByDstCountry:
		key = r.DstCountry
	case ByPort:
		port := flowPortGroupKey(r)
		if port != 0 {
			key = strconv.FormatUint(uint64(port), 10)
		}
	case ByProtocol:
		key = r.Protocol
	case ByExporter:
		key = r.Exporter
	}
	return key, detail, key != ""
}

func matchesFilters(r Row, filters []Filter) bool {
	for _, filter := range filters {
		var match bool
		switch filter.Field {
		case FilterSrc:
			match = r.SrcAddr == filter.Value
		case FilterDst:
			match = r.DstAddr == filter.Value
		case FilterSrcASN:
			match = strconv.FormatUint(uint64(r.SrcASN), 10) == filter.Value
		case FilterDstASN:
			match = strconv.FormatUint(uint64(r.DstASN), 10) == filter.Value
		case FilterASName:
			match = r.SrcASName == filter.Value || r.DstASName == filter.Value
		case FilterGroupASName:
			match = flowASNameGroupKey(r) == filter.Value
		case FilterSrcCountry:
			match = r.SrcCountry == filter.Value
		case FilterDstCountry:
			match = r.DstCountry == filter.Value
		case FilterPort:
			match = strconv.FormatUint(uint64(r.SrcPort), 10) == filter.Value ||
				strconv.FormatUint(uint64(r.DstPort), 10) == filter.Value
		case FilterGroupPort:
			match = strconv.FormatUint(uint64(flowPortGroupKey(r)), 10) == filter.Value
		case FilterProtocol:
			match = r.Protocol == filter.Value
		case FilterExporter:
			match = r.Exporter == filter.Value
		}
		if !match {
			return false
		}
	}
	return true
}

// Capacity buckets the window into per-(exporter, iface) throughput points.
func (m *Memory) Capacity(_ context.Context, q CapacityQuery) ([]CapacityPoint, error) {
	if err := q.normalize(); err != nil {
		return nil, err
	}
	return m.capacitySeries(q), nil
}

func (m *Memory) capacitySeries(q CapacityQuery) []CapacityPoint {
	type key struct {
		exporter string
		iface    uint32
		bucket   int64
	}
	type agg struct{ bytes, pkts uint64 }
	bucketSecs := int64(q.Bucket / time.Second)
	groups := make(map[key]*agg)
	for _, r := range m.inWindow(q.TenantID, q.Now.Add(-q.Window), q.Now) {
		if q.Exporter != "" && r.Exporter != q.Exporter {
			continue
		}
		iface := r.InIf
		if q.Direction == "out" {
			iface = r.OutIf
		}
		k := key{r.Exporter, iface, r.TS.Unix() / bucketSecs * bucketSecs}
		g, ok := groups[k]
		if !ok {
			g = &agg{}
			groups[k] = g
		}
		g.bytes += r.BytesScaled
		g.pkts += r.PacketsScaled
	}
	out := make([]CapacityPoint, 0, len(groups))
	for k, g := range groups {
		out = append(out, CapacityPoint{
			TS:       time.Unix(k.bucket, 0).UTC(),
			Exporter: k.exporter,
			Iface:    k.iface,
			Bps:      float64(g.bytes) * 8 / float64(bucketSecs),
			Pps:      float64(g.pkts) / float64(bucketSecs),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].TS.Equal(out[j].TS) {
			return out[i].TS.Before(out[j].TS)
		}
		if out[i].Exporter != out[j].Exporter {
			return out[i].Exporter < out[j].Exporter
		}
		return out[i].Iface < out[j].Iface
	})
	return out
}

// Anomalies runs the shared detector over the capacity series.
func (m *Memory) Anomalies(_ context.Context, q AnomalyQuery) ([]Anomaly, error) {
	if err := q.normalize(); err != nil {
		return nil, err
	}
	return detectAnomalies(m.capacitySeries(q.capacityQuery()), q), nil
}

// Close is a no-op.
// DeleteTenant removes every flow of one tenant (S-T5).
func (m *Memory) DeleteTenant(_ context.Context, tenantID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.rows[:0]
	for _, entry := range m.rows {
		if entry.row.TenantID != tenantID {
			kept = append(kept, entry)
		}
	}
	m.rows = kept
	m.rebuildSeenLocked()
	var remaining int64
	for _, entry := range m.rows {
		r := entry.row
		if r.TenantID == tenantID {
			remaining++
		}
	}
	return remaining, nil
}

// DeleteSubject removes flows for one tenant that mention subject in the
// identity-like fields a data subject can reasonably name: endpoint IPs,
// exporter, next-hop, country/ASN labels, and agent id. The tenant filter is
// applied before the subject predicate.
func (m *Memory) DeleteSubject(_ context.Context, tenantID, subject string) (deleted, remaining int64, err error) {
	if tenantID == "" {
		return 0, -1, ErrNoTenant
	}
	subject = strings.ToLower(strings.TrimSpace(subject))
	if subject == "" {
		return 0, -1, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.rows[:0]
	for _, entry := range m.rows {
		r := entry.row
		if r.TenantID == tenantID && flowRowMatchesSubject(r, subject) {
			deleted++
			continue
		}
		kept = append(kept, entry)
	}
	m.rows = kept
	m.rebuildSeenLocked()
	for _, entry := range m.rows {
		r := entry.row
		if r.TenantID == tenantID && flowRowMatchesSubject(r, subject) {
			remaining++
		}
	}
	return deleted, remaining, nil
}

// DeleteTenantBefore removes one tenant's flows older than cutoff (S-T5).
func (m *Memory) DeleteTenantBefore(_ context.Context, tenantID string, cutoff time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.rows[:0]
	for _, entry := range m.rows {
		r := entry.row
		if r.TenantID == tenantID && r.TS.Before(cutoff) {
			continue
		}
		kept = append(kept, entry)
	}
	m.rows = kept
	m.rebuildSeenLocked()
	return nil
}

// ExportTenant streams one tenant's flows as JSON Lines (S-T5).
func (m *Memory) ExportTenant(_ context.Context, tenantID string, w io.Writer) (int64, error) {
	m.mu.Lock()
	rows := make([]Row, 0)
	for _, entry := range m.rows {
		r := entry.row
		if r.TenantID == tenantID {
			rows = append(rows, r)
		}
	}
	m.mu.Unlock()
	enc := json.NewEncoder(w)
	for i := range rows {
		if err := enc.Encode(rows[i]); err != nil {
			return int64(i), err
		}
	}
	return int64(len(rows)), nil
}

func (m *Memory) Close() error { return nil }

func (m *Memory) ensureSeenLocked() {
	if m.seen != nil {
		return
	}
	m.rebuildSeenLocked()
}

func (m *Memory) evictLocked() {
	if over := len(m.rows) - m.max; over > 0 {
		for _, entry := range m.rows[:over] {
			m.forgetLocked(entry.key)
		}
		m.rows = append([]memoryRow(nil), m.rows[over:]...)
	}
}

func (m *Memory) forgetLocked(key string) {
	if m.seen[key] <= 1 {
		delete(m.seen, key)
		return
	}
	m.seen[key]--
}

func (m *Memory) rebuildSeenLocked() {
	m.seen = make(map[string]int, len(m.rows))
	for i := range m.rows {
		if m.rows[i].key == "" {
			m.rows[i].key = flowRowID(m.rows[i].row)
		}
		m.seen[m.rows[i].key]++
	}
}

func flowRowMatchesSubject(r Row, subject string) bool {
	for _, v := range []string{
		r.AgentID, r.Exporter, r.SrcAddr, r.DstAddr, r.NextHop,
		r.SrcASName, r.DstASName, r.SrcCountry, r.DstCountry,
		strconv.FormatUint(uint64(r.SrcASN), 10),
		strconv.FormatUint(uint64(r.DstASN), 10),
	} {
		if strings.Contains(strings.ToLower(v), subject) {
			return true
		}
	}
	return false
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
