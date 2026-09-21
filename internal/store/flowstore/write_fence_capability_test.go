// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"testing"
	"time"
)

type flowSubjectDeleter interface {
	DeleteSubject(
		context.Context,
		string,
		string,
	) (deleted, remaining int64, err error)
}

// TestWriteFencedStorePreservesSubjectDeleteTwoTenant guards the optional
// subject-erasure capability across the write-fence decorator. The delete must
// retain its tenant-first predicate: a matching foreign row and an unrelated
// row in the target tenant both survive.
func TestWriteFencedStorePreservesSubjectDeleteTwoTenant(t *testing.T) {
	ctx := context.Background()
	memory := NewMemory()
	now := time.Now().UTC()
	const (
		tenantA = "tenant-a"
		tenantB = "tenant-b"
		subject = "198.51.100.17"
	)
	if err := memory.Insert(ctx, []Row{
		{TenantID: tenantA, TS: now, SrcAddr: subject},
		{TenantID: tenantA, TS: now.Add(time.Second), SrcAddr: "192.0.2.8"},
		{TenantID: tenantB, TS: now.Add(2 * time.Second), SrcAddr: subject},
	}); err != nil {
		t.Fatalf("seed flows: %v", err)
	}

	deleter, ok := WithTenantWriteFence(memory, nil).(flowSubjectDeleter)
	if !ok {
		t.Fatal("write-fenced flow store lost DeleteSubject capability")
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
	if got := memory.Len(); got != 2 {
		t.Fatalf("rows after tenant A subject delete = %d, want 2", got)
	}

	topA, err := memory.TopTalkers(ctx, TopQuery{
		TenantID: tenantA,
		By:       BySrc,
		Window:   time.Hour,
		Now:      now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("query tenant A: %v", err)
	}
	if len(topA) != 1 || topA[0].Key != "192.0.2.8" {
		t.Fatalf("tenant A survivors = %+v, want unrelated row only", topA)
	}
	topB, err := memory.TopTalkers(ctx, TopQuery{
		TenantID: tenantB,
		By:       BySrc,
		Window:   time.Hour,
		Now:      now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("query tenant B: %v", err)
	}
	if len(topB) != 1 || topB[0].Key != subject {
		t.Fatalf("tenant B survivors = %+v, want matching foreign row", topB)
	}
}
