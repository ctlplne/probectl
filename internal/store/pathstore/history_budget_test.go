// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCompleteClickHouseHistoryUsesScopedBudgetAndExactClock(t *testing.T) {
	f, ch := newFakeCH(t)
	from := time.Date(2026, 11, 1, 0, 0, 0, 1, time.UTC)
	got, err := ch.History(t.Context(), "tenant-a", "dns.example", HistoryQuery{From: from, To: from.Add(time.Nanosecond), Limit: 1, MaxBytes: 16 << 20})
	if err != nil || len(got) != 1 {
		t.Fatal("complete scoped ClickHouse reader failed", len(got), err)
	}
	f.mu.Lock()
	queries := append([]string(nil), f.queries...)
	f.mu.Unlock()
	found := false
	for _, query := range queries {
		if !strings.Contains(query, "GROUP BY path_id") {
			continue
		}
		found = true
		if !strings.Contains(query, "tenant_id={tenant:String}") || !strings.Contains(query, "/*param_tenant=tenant-a*/") || !strings.Contains(query, "DateTime64(9,'UTC')") || !strings.Contains(query, ".000000001") || !strings.Contains(query, ".000000002") || strings.Contains(query, "/*param_limit=1*/") {
			t.Fatal("complete path selector lost tenant, exact time or memory-derived admission")
		}
	}
	if !found {
		t.Fatal("complete history did not read round metadata")
	}
	if partial, err := ch.History(t.Context(), "tenant-a", "dns.example", HistoryQuery{MaxBytes: 4096}); err == nil || partial != nil {
		t.Fatal("wire-budget failure returned partial evidence", len(partial), err)
	}
}

func TestCompletePathHistoryKeepsWholeWindowAndTenantSelectors(t *testing.T) {
	m := NewMemory()
	at := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Hour)
	for _, tenant := range []string{"red", "blue"} {
		for i := range 257 {
			p := samplePath()
			p.TargetIP = tenant
			if err := m.Save(WithDiscoveryStartedAt(t.Context(), at.Add(time.Duration(i)*time.Millisecond)), tenant, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	query := HistoryQuery{From: at, To: at.Add(256 * time.Millisecond), Limit: 1, MaxBytes: 16 << 20}
	ids := map[string]string{}
	for _, tenant := range []string{"red", "blue"} {
		got, err := m.History(t.Context(), tenant, "8.8.8.8", query)
		if err != nil || len(got) != 257 {
			t.Fatal("complete history inherited a browser page or lost its window", len(got), err)
		}
		for _, round := range got {
			if round.Path.TargetIP != tenant || !round.TrustedDiscoveryTime {
				t.Fatal("history borrowed another tenant or lost its original clock")
			}
		}
		ids[tenant] = got[0].ID
		query.MaxBytes = 8192
		if partial, err := m.History(t.Context(), tenant, "8.8.8.8", query); !errors.Is(err, ErrHistoryBudget) || partial != nil {
			t.Fatal("complete admission failure returned a plausible prefix", len(partial), err)
		}
		query.MaxBytes = 16 << 20
	}
	query.IDs = []string{ids["blue"]}
	if got, err := m.History(t.Context(), "red", "8.8.8.8", query); err != nil || len(got) != 0 {
		t.Fatal("foreign round selector disclosed path evidence", len(got), err)
	}
	query.IDs = nil
	query.From, query.To = at, at.Add(time.Nanosecond)
	if got, err := m.History(t.Context(), "red", "8.8.8.8", query); err != nil || len(got) != 1 || !got[0].ObservedAt.Equal(at) {
		t.Fatal("nanosecond selector lost the included discrete point", len(got), err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := m.History(ctx, "red", "8.8.8.8", query); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("canceled complete read returned data", err)
	}
}
