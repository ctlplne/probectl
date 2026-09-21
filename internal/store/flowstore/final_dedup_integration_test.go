// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestFlowFinalDedupRealRoundTrip proves CORRECT-003 against a real ClickHouse:
// inserting the SAME flow batch twice (an at-least-once redelivery) without an
// OPTIMIZE FINAL must NOT double the bytes returned by TopTalkers, because the
// aggregation reads the ReplacingMergeTree with FINAL. Pre-fix (no FINAL) the
// two not-yet-merged parts each contribute and the bytes double.
//
// Runs in the integration job (PROBECTL_FLOWSTORE_URL points at the test
// ClickHouse); SkipOrFatal fails the build when PROBECTL_TEST_REQUIRE_SERVICES=1
// but CH is unavailable, so it can never pass by silently skipping in CI.
func TestFlowFinalDedupRealRoundTrip(t *testing.T) {
	url := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — flow FINAL dedup gate runs in CI")
	}
	c, err := NewClickHouse(url, 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	tenant := fmt.Sprintf("itest-final-%d", time.Now().UnixNano())
	now := time.Now().UTC()

	batch := []Row{{
		TenantID: tenant, AgentID: "a1", Exporter: "e1", Protocol: "netflow5",
		TS: now.Add(-time.Minute), StartTS: now.Add(-2 * time.Minute),
		SrcAddr: "10.0.0.1", DstAddr: "10.0.0.9", SrcPort: 40000, DstPort: 443,
		Transport: "tcp", Bytes: 1000, Packets: 10, BytesScaled: 10_000, PacketsScaled: 10,
		InIf: 1, OutIf: 2,
	}}
	// Redeliver the identical batch twice (same row_id → ReplacingMergeTree dups).
	if err := c.Insert(ctx, batch); err != nil {
		t.Fatalf("insert 1: %v", err)
	}
	if err := c.Insert(ctx, batch); err != nil {
		t.Fatalf("insert 2 (redelivery): %v", err)
	}

	top, err := c.TopTalkers(ctx, TopQuery{TenantID: tenant, By: BySrc, Window: time.Hour, Now: now})
	if err != nil {
		t.Fatalf("top talkers: %v", err)
	}
	if len(top) != 1 {
		t.Fatalf("want 1 talker, got %d (%+v)", len(top), top)
	}
	if top[0].Bytes != 10_000 {
		t.Fatalf("redelivered flow double-counted: bytes=%d, want 10000 (FINAL must dedup before sum)", top[0].Bytes)
	}
}
