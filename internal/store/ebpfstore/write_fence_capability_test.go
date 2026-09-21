// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpfstore

import (
	"context"
	"testing"
	"time"
)

type ebpfSubjectDeleter interface {
	DeleteSubject(
		context.Context,
		string,
		string,
	) (deleted, remaining int64, err error)
}

// TestEBPFWriteFencePreservesLifecycleCapabilitiesTwoTenant guards lifecycle
// capability discovery across the ingest-only write-fence decorator. Subject
// deletion must retain its tenant-first predicate.
func TestEBPFWriteFencePreservesLifecycleCapabilitiesTwoTenant(t *testing.T) {
	ctx := context.Background()
	memory := NewMemory()
	now := time.Now().UTC()
	const (
		tenantA = "tenant-a"
		tenantB = "tenant-b"
		subject = "payments-api"
	)
	if err := memory.Insert(ctx, []Edge{
		{TenantID: tenantA, WindowStart: now, SrcWorkload: subject, DstWorkload: "db", Bytes: 10},
		{TenantID: tenantA, WindowStart: now.Add(time.Second), SrcWorkload: "orders-api", DstWorkload: "db", Bytes: 20},
		{TenantID: tenantB, WindowStart: now.Add(2 * time.Second), SrcWorkload: subject, DstWorkload: "db", Bytes: 30},
	}); err != nil {
		t.Fatalf("seed eBPF edges: %v", err)
	}

	deleter, ok := UnderlyingStore(
		WithTenantWriteFence(memory, nil),
	).(ebpfSubjectDeleter)
	if !ok {
		t.Fatal("write-fenced eBPF store hid DeleteSubject from lifecycle")
	}
	deleted, remaining, err := deleter.DeleteSubject(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("delete tenant A subject: %v", err)
	}
	if deleted != 1 || remaining != 0 {
		t.Fatalf(
			"tenant A subject delete = (%d deleted, %d remaining), want (1, 0)",
			deleted,
			remaining,
		)
	}
	rowsA, err := memory.TopEdges(ctx, tenantA, EdgeQuery{})
	if err != nil {
		t.Fatalf("query tenant A: %v", err)
	}
	if len(rowsA) != 1 || rowsA[0].SrcWorkload != "orders-api" {
		t.Fatalf("tenant A survivors = %+v, want unrelated edge only", rowsA)
	}
	rowsB, err := memory.TopEdges(ctx, tenantB, EdgeQuery{})
	if err != nil {
		t.Fatalf("query tenant B: %v", err)
	}
	if len(rowsB) != 1 || rowsB[0].SrcWorkload != subject {
		t.Fatalf("tenant B survivors = %+v, want matching foreign edge", rowsB)
	}
}
