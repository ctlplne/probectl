// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package flowstore persists normalized flow records (S38, F17) and serves the
// flow-analytics queries: top-talkers, per-exporter/interface capacity, and
// anomaly baselines. Two implementations share one contract: Memory (default,
// lightweight mode and tests) and ClickHouse (high-volume production), reached
// over the ClickHouse HTTP interface like pathstore — TLS in transit via an
// https URL (CLAUDE.md §7 guardrail 12).
//
// Tenancy: every row carries tenant_id; it leads the ClickHouse partition AND
// ORDER BY, and every query is tenant-scoped before anything else (CLAUDE.md
// §6 — never a data path that can return cross-tenant rows).
package flowstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/anomaly"
)

// Row is one stored flow record (post-decode, post-enrichment).
type Row struct {
	TenantID  string `json:"tenant_id"`
	AgentID   string `json:"agent_id"`
	Exporter  string `json:"exporter"`
	ObsDomain uint32 `json:"obs_domain"`
	Protocol  string `json:"protocol"`

	TS      time.Time `json:"-"` // analytics time axis (flow end)
	StartTS time.Time `json:"-"`

	SrcAddr   string `json:"src_addr"`
	DstAddr   string `json:"dst_addr"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Transport string `json:"transport"`
	NetType   string `json:"net_type"`

	InIf     uint32 `json:"in_if"`
	OutIf    uint32 `json:"out_if"`
	VLAN     uint16 `json:"vlan"`
	ToS      uint8  `json:"tos"`
	TCPFlags uint8  `json:"tcp_flags"`
	NextHop  string `json:"next_hop"`

	Bytes         uint64 `json:"bytes"`
	Packets       uint64 `json:"packets"`
	Sampling      uint64 `json:"sampling"`
	BytesScaled   uint64 `json:"bytes_scaled"`
	PacketsScaled uint64 `json:"packets_scaled"`

	SrcASN     uint32 `json:"src_asn"`
	SrcASName  string `json:"src_as_name"`
	SrcCountry string `json:"src_country"`
	DstASN     uint32 `json:"dst_asn"`
	DstASName  string `json:"dst_as_name"`
	DstCountry string `json:"dst_country"`
}

// Top-talker groupings.
const (
	BySrc    = "src"
	ByDst    = "dst"
	ByPair   = "pair"
	BySrcASN = "src_asn"
	ByDstASN = "dst_asn"
)

// TopQuery selects the top-N traffic contributors within a window.
type TopQuery struct {
	TenantID string
	By       string // src | dst | pair | src_asn | dst_asn
	Window   time.Duration
	Limit    int
	Now      time.Time // zero = time.Now()
}

// TopRow is one top-talkers result. Key is the group (address or ASN); Detail
// carries the pair's destination or the AS organization name.
type TopRow struct {
	Key     string `json:"key"`
	Detail  string `json:"detail,omitempty"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// MarshalJSON additionally emits the counters as STRINGS (bytes_str, ...)
// alongside the numbers (CORRECT-016): a flow byte total can exceed 2^53, where
// a JSON-number client (JavaScript's JSON.parse → float64) silently loses
// precision. The numeric fields stay for existing consumers; precision-sensitive
// clients read the string fields. Additive, so it never breaks the wire.
func (r TopRow) MarshalJSON() ([]byte, error) {
	type alias TopRow // avoid recursion
	return json.Marshal(struct {
		alias
		BytesStr   string `json:"bytes_str"`
		PacketsStr string `json:"packets_str"`
		FlowsStr   string `json:"flows_str"`
	}{
		alias:      alias(r),
		BytesStr:   strconv.FormatUint(r.Bytes, 10),
		PacketsStr: strconv.FormatUint(r.Packets, 10),
		FlowsStr:   strconv.FormatUint(r.Flows, 10),
	})
}

// CapacityQuery selects per-exporter/interface throughput over time buckets.
type CapacityQuery struct {
	TenantID  string
	Exporter  string // optional filter
	Direction string // in | out (which interface to group by); default in
	Window    time.Duration
	Bucket    time.Duration
	Now       time.Time
}

// CapacityPoint is one (exporter, interface, bucket) throughput sample,
// sampling-corrected.
type CapacityPoint struct {
	TS       time.Time `json:"ts"`
	Exporter string    `json:"exporter"`
	Iface    uint32    `json:"iface"`
	Bps      float64   `json:"bps"`
	Pps      float64   `json:"pps"`
}

// AnomalyQuery flags (exporter, interface) pairs whose latest bucket departs
// from their own baseline by more than Sensitivity standard deviations.
type AnomalyQuery struct {
	TenantID    string
	Exporter    string // optional filter
	Direction   string // in | out
	Window      time.Duration
	Bucket      time.Duration
	Sensitivity float64 // k in mean + k*stddev; default 3
	MinBps      float64 // ignore tiny links; default 1000
	Now         time.Time
}

// Anomaly is one flagged interface.
type Anomaly struct {
	Exporter         string                 `json:"exporter"`
	Iface            uint32                 `json:"iface"`
	TS               time.Time              `json:"ts"`
	CurrentBps       float64                `json:"current_bps"`
	BaselineBps      float64                `json:"baseline_bps"`
	StdDevBps        float64                `json:"stddev_bps"`
	Sigma            float64                `json:"sigma"`
	Model            string                 `json:"model,omitempty"`
	TrainingWindow   anomaly.TrainingWindow `json:"training_window,omitempty"`
	FeatureCitations []anomaly.Citation     `json:"feature_citations,omitempty"`
	Features         map[string]float64     `json:"features,omitempty"`
}

// Store is the flow persistence + analytics contract.
type Store interface {
	Insert(ctx context.Context, rows []Row) error
	TopTalkers(ctx context.Context, q TopQuery) ([]TopRow, error)
	Capacity(ctx context.Context, q CapacityQuery) ([]CapacityPoint, error)
	Anomalies(ctx context.Context, q AnomalyQuery) ([]Anomaly, error)
	// DeleteTenant removes EVERY flow of one tenant (S-T5 verifiable
	// deletion; routed: a siloed tenant's database is dropped) and returns
	// the remaining count for that tenant (0 = verified gone).
	DeleteTenant(ctx context.Context, tenantID string) (remaining int64, err error)
	// DeleteTenantBefore removes one tenant's flows older than cutoff
	// (S-T5 per-tenant retention).
	DeleteTenantBefore(ctx context.Context, tenantID string, cutoff time.Time) error
	// ExportTenant streams one tenant's flows as JSON Lines into w
	// (S-T5 portability export).
	ExportTenant(ctx context.Context, tenantID string, w io.Writer) (int64, error)
	Close() error
}

// New builds a Store. "memory" (or empty) is in-process; "clickhouse" persists
// to the ClickHouse HTTP endpoint at url. retentionDays > 0 adds a delete-TTL
// to the ClickHouse table (high-volume retention, S38).
func New(mode, url string, retentionDays int) (Store, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "clickhouse":
		if url == "" {
			return nil, errors.New("flowstore: clickhouse mode requires PROBECTL_FLOWSTORE_URL")
		}
		return NewClickHouse(url, retentionDays)
	default:
		return nil, fmt.Errorf("flowstore: unknown mode %q (want memory|clickhouse)", mode)
	}
}

// --- query normalization (shared by both implementations) -------------------

func (q *TopQuery) normalize() error {
	if q.TenantID == "" {
		return errors.New("flowstore: tenant required")
	}
	switch q.By {
	case "":
		q.By = BySrc
	case BySrc, ByDst, ByPair, BySrcASN, ByDstASN:
	default:
		return fmt.Errorf("flowstore: unknown top-talkers grouping %q", q.By)
	}
	if q.Window <= 0 {
		q.Window = time.Hour
	}
	if q.Limit <= 0 {
		q.Limit = 10
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}
	if q.Now.IsZero() {
		q.Now = time.Now()
	}
	return nil
}

func (q *CapacityQuery) normalize() error {
	if q.TenantID == "" {
		return errors.New("flowstore: tenant required")
	}
	switch q.Direction {
	case "":
		q.Direction = "in"
	case "in", "out":
	default:
		return fmt.Errorf("flowstore: unknown direction %q", q.Direction)
	}
	if q.Window <= 0 {
		q.Window = time.Hour
	}
	if q.Bucket <= 0 {
		q.Bucket = q.Window / 20
	}
	if q.Bucket < time.Minute {
		q.Bucket = time.Minute
	}
	if q.Now.IsZero() {
		q.Now = time.Now()
	}
	return nil
}

func (q *AnomalyQuery) normalize() error {
	c := CapacityQuery{TenantID: q.TenantID, Direction: q.Direction, Window: q.Window, Bucket: q.Bucket, Now: q.Now}
	if err := c.normalize(); err != nil {
		return err
	}
	q.Direction, q.Window, q.Bucket, q.Now = c.Direction, c.Window, c.Bucket, c.Now
	if q.Sensitivity <= 0 {
		q.Sensitivity = 3
	}
	if q.MinBps <= 0 {
		q.MinBps = 1000
	}
	return nil
}

func (q AnomalyQuery) capacityQuery() CapacityQuery {
	return CapacityQuery{TenantID: q.TenantID, Exporter: q.Exporter, Direction: q.Direction,
		Window: q.Window, Bucket: q.Bucket, Now: q.Now}
}
