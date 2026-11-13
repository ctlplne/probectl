// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestPathCompletionClockSurvivesBatchHistoryAndTenantExport(t *testing.T) {
	m := NewMemory()
	batch := NewBatchingSaver(m, nil, time.Hour, 64)
	t.Cleanup(func() { _ = batch.Close() })
	start := time.Date(2026, 11, 1, 1, 2, 3, 123456789, time.UTC)
	for i, tenant := range []string{"red", "blue"} {
		completed := start.Add(time.Duration(47+i) * time.Nanosecond)
		ctx := WithDiscoveryCompletedAt(WithDiscoveryStartedAt(t.Context(), start), completed)
		if err := batch.Save(ctx, tenant, samplePath()); err != nil {
			t.Fatal(err)
		}
		got, err := batch.History(t.Context(), tenant, "8.8.8.8", HistoryQuery{MaxBytes: 1 << 20})
		if err != nil || len(got) != 1 || !got[0].ObservedAt.Equal(start) || got[0].CompletedAt == nil || !got[0].CompletedAt.Equal(completed) {
			t.Fatal("batch flush changed an original execution clock", len(got), err)
		}
		*got[0].CompletedAt = completed.Add(time.Hour)
		again, err := m.History(t.Context(), tenant, "8.8.8.8", HistoryQuery{MaxBytes: 1 << 20})
		if err != nil || !again[0].CompletedAt.Equal(completed) {
			t.Fatal("reader mutated the retained completion clock", err)
		}
		var body bytes.Buffer
		if _, err := m.ExportTenantHops(t.Context(), tenant, &body); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(&body)
		rows := 0
		for {
			var row map[string]any
			err := decoder.Decode(&row)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			rows++
			if row["tenant_id"] != tenant || row["discovery_started_at"] != start.Format("2006-01-02 15:04:05.000000000") || row["discovery_completed_at"] != completed.Format("2006-01-02 15:04:05.000000000") {
				t.Fatal("tenant export changed original interval or tenant")
			}
		}
		if rows != 2 {
			t.Fatal("tenant export omitted hop rows", rows)
		}
	}
	if err := m.Save(WithDiscoveryStartedAt(t.Context(), start), "legacy", samplePath()); err != nil {
		t.Fatal(err)
	}
	legacy, err := m.History(t.Context(), "legacy", "8.8.8.8", HistoryQuery{MaxBytes: 1 << 20})
	if err != nil || len(legacy) != 1 || legacy[0].CompletedAt != nil {
		t.Fatal("legacy start fabricated a completion", err)
	}
	f, ch := newFakeCH(t)
	if err := ch.SaveBatch(t.Context(), []PathItem{{TenantID: "red", P: samplePath(), ObservedAt: start, CompletedAt: start.Add(time.Nanosecond), TrustedDiscoveryTime: true}}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	queries := append([]string(nil), f.queries...)
	f.mu.Unlock()
	found := false
	for _, query := range queries {
		if strings.Contains(query, "ADD COLUMN IF NOT EXISTS discovery_completed_at Nullable(DateTime64(9") {
			found = true
		}
	}
	if !found {
		t.Fatal("completion clock migration was not applied")
	}
}
