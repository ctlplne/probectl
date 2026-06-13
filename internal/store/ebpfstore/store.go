// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package ebpfstore persists eBPF host/L7 flow + service-edge AGGREGATES
// (ARCH-008) and serves their tenant-scoped queries. Until now the eBPF plane —
// probectl's differentiator — built only an in-RAM service map that vanished on
// restart and had no history; CLAUDE.md's "ClickHouse (… eBPF …)" claim was
// therefore not true. This store makes it true: two implementations share one
// contract — Memory (lightweight mode + tests) and ClickHouse (high-volume
// production over the HTTP interface, like flowstore/otelstore).
//
// Tenancy: every row carries tenant_id; it leads the ClickHouse partition AND
// ORDER BY, every query is tenant-scoped first (CLAUDE.md §6/§7.1), and
// DeleteTenant is the verifiable-erasure hook (S-T5). Rows are dedup-keyed
// (ReplacingMergeTree) like the flow store (CORRECT-002 discipline).
package ebpfstore

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Edge is one eBPF service-edge aggregate over a window: bytes/packets/conns
// between a source and destination workload, optionally with an L7 protocol.
type Edge struct {
	TenantID    string    `json:"tenant_id"`
	AgentID     string    `json:"agent_id"`
	WindowStart time.Time `json:"window_start"`
	SrcWorkload string    `json:"src_workload"`
	DstWorkload string    `json:"dst_workload"`
	DstPort     uint16    `json:"dst_port"`
	L7Protocol  string    `json:"l7_protocol,omitempty"` // http|dns|... ("" = L3/L4 only)
	Bytes       uint64    `json:"bytes"`
	Packets     uint64    `json:"packets"`
	Connections uint64    `json:"connections"`
}

// EdgeQuery filters a tenant's aggregates. Zero values mean "any".
type EdgeQuery struct {
	Since   time.Time
	Until   time.Time
	SrcLike string
	Limit   int // <=0 => default 100, capped at 1000
}

// Store is the eBPF-aggregate persistence contract.
type Store interface {
	// Insert persists a batch of aggregates (tenant-scoped per row).
	Insert(ctx context.Context, edges []Edge) error
	// TopEdges returns a tenant's heaviest edges in the window, bytes-desc.
	TopEdges(ctx context.Context, tenantID string, q EdgeQuery) ([]Edge, error)
	// DeleteTenant removes EVERY aggregate of one tenant (verifiable erasure,
	// S-T5) and returns the remaining count (0 = verified gone).
	DeleteTenant(ctx context.Context, tenantID string) (remaining int64, err error)
	Close() error
}

// ErrNoTenant refuses any tenant-keyed operation without a tenant (defense in
// depth: the predicate can never be omitted).
var ErrNoTenant = errors.New("ebpfstore: tenant_id is required (refusing an unscoped query)")

// New selects the backend (flowstore/otelstore convention): "" | "memory" for
// the in-process store, "clickhouse" for production. retentionDays>0 adds the
// ClickHouse delete-TTL.
func New(mode, url string, retentionDays int) (Store, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "clickhouse":
		if url == "" {
			return nil, errors.New("ebpfstore: clickhouse mode requires PROBECTL_EBPFSTORE_URL")
		}
		return NewClickHouse(url, retentionDays)
	default:
		return nil, fmt.Errorf("ebpfstore: unknown mode %q (want memory|clickhouse)", mode)
	}
}

func clampLimit(n int) int {
	if n <= 0 {
		return 100
	}
	if n > 1000 {
		return 1000
	}
	return n
}
