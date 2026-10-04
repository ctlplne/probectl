// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package ebpfstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// RTP-16: the ClickHouse service-map backend must honor the since/until window
// AND the source-workload filter, exactly as the memory backend does. Before
// the fix the source filter was silently dropped, so a scoped query returned
// every source.
func TestTopEdgesSinceUntilSourceFiltersCH(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_EBPFSTORE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_EBPFSTORE_URL not set — ClickHouse service-map gate runs in CI")
	}
	c, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	tenant := fmt.Sprintf("rtp16_%d", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = c.DeleteTenant(ctx, tenant) })

	newer := time.Now().UTC().Truncate(time.Second)
	older := newer.Add(-1 * time.Hour)
	if err := c.Insert(ctx, []Edge{
		{TenantID: tenant, AgentID: "n1", WindowStart: older, SrcWorkload: "web", DstWorkload: "db", DstPort: 5432, L7Protocol: "tcp", Bytes: 100, Packets: 1, Connections: 1},
		{TenantID: tenant, AgentID: "n1", WindowStart: newer, SrcWorkload: "web", DstWorkload: "cache", DstPort: 6379, L7Protocol: "tcp", Bytes: 200, Packets: 2, Connections: 1},
		{TenantID: tenant, AgentID: "n1", WindowStart: newer, SrcWorkload: "api", DstWorkload: "db", DstPort: 5432, L7Protocol: "tcp", Bytes: 300, Packets: 3, Connections: 1},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	srcSet := func(edges []Edge) map[string]int {
		m := map[string]int{}
		for _, e := range edges {
			m[e.SrcWorkload]++
		}
		return m
	}

	// Source filter: only "web" edges (both windows), never "api".
	webOnly, err := c.TopEdges(ctx, tenant, EdgeQuery{SrcLike: "web"})
	if err != nil {
		t.Fatalf("source-filtered query: %v", err)
	}
	if got := srcSet(webOnly); got["api"] != 0 || got["web"] != 2 {
		t.Fatalf("source filter must return only web edges, got %v (%+v)", got, webOnly)
	}

	// Window filter: only the newer window (web+cache and api+db), never the
	// older web+db edge.
	sinceNewer, err := c.TopEdges(ctx, tenant, EdgeQuery{Since: newer})
	if err != nil {
		t.Fatalf("since-filtered query: %v", err)
	}
	if len(sinceNewer) != 2 {
		t.Fatalf("since filter must return the 2 newer edges, got %d (%+v)", len(sinceNewer), sinceNewer)
	}

	// Combined: source=web AND since=newer → only the newer web+cache edge.
	combined, err := c.TopEdges(ctx, tenant, EdgeQuery{SrcLike: "web", Since: newer})
	if err != nil {
		t.Fatalf("combined query: %v", err)
	}
	if len(combined) != 1 || combined[0].SrcWorkload != "web" || combined[0].DstWorkload != "cache" {
		t.Fatalf("combined source+since filter must return only the newer web->cache edge, got %+v", combined)
	}
}
