// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package ebpfstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestPooledTenantEraseVerifiesTheSharedTable: a pooled tenant's eBPF
// aggregates live in the shared edges table, so tenant erasure is a ClickHouse
// mutation there. The mutation ran asynchronously and the verification count
// followed at once, so it counted rows the mutation had not removed yet and the
// erasure attestation reported them as remaining. The erase must return once
// the rows are gone, and leave the other tenant's rows alone.
func TestPooledTenantEraseVerifiesTheSharedTable(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_EBPFSTORE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_EBPFSTORE_URL not set — the ClickHouse eBPF erase test runs in CI")
	}
	c, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	gone, kept := fmt.Sprintf("ebpf-erase-gone-%d", stamp), fmt.Sprintf("ebpf-erase-kept-%d", stamp)
	t.Cleanup(func() { _, _ = c.DeleteTenant(context.Background(), kept) })

	now := time.Now().UTC().Truncate(time.Second)
	var edges []Edge
	for _, tenant := range []string{gone, kept} {
		for i := 0; i < 50; i++ {
			edges = append(edges, Edge{
				TenantID: tenant, AgentID: "node-1", WindowStart: now.Add(-time.Duration(i) * time.Minute),
				SrcWorkload: fmt.Sprintf("web-%d", i), DstWorkload: "db", DstPort: 5432, L7Protocol: "tcp",
				Bytes: 100, Packets: 1, Connections: 1,
			})
		}
	}
	if err := c.Insert(ctx, edges); err != nil {
		t.Fatalf("insert: %v", err)
	}

	remaining, err := c.DeleteTenant(ctx, gone)
	if err != nil || remaining != 0 {
		t.Fatalf("erase the pooled tenant = %d remaining, %v; want 0 verified at return", remaining, err)
	}
	if left, err := c.TopEdges(ctx, gone, EdgeQuery{Limit: 100}); err != nil || len(left) != 0 {
		t.Fatalf("the erased tenant still reads %d edges (%v)", len(left), err)
	}
	if kept, err := c.TopEdges(ctx, kept, EdgeQuery{Limit: 100}); err != nil || len(kept) != 50 {
		t.Fatalf("the other tenant reads %d of its 50 edges after the erase (%v)", len(kept), err)
	}
}
