// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tsdb

import (
	"context"
	"testing"
)

func TestMemoryWriteQuery(t *testing.T) {
	m := NewMemory()
	series := []Series{
		{Metric: "probectl_probe_success", Labels: map[string]string{"tenant_id": "t1"}, Value: 1, TimeMillis: 1000},
		{Metric: "probectl_probe_success", Labels: map[string]string{"tenant_id": "t2"}, Value: 0, TimeMillis: 1000},
	}
	if err := m.Write(context.Background(), series); err != nil {
		t.Fatal(err)
	}
	if m.Len() != 2 {
		t.Fatalf("len = %d, want 2", m.Len())
	}
	if got := m.Query("probectl_probe_success", map[string]string{"tenant_id": "t1"}); len(got) != 1 || got[0].Value != 1 {
		t.Errorf("query t1 = %+v", got)
	}
	if got := m.Query("probectl_probe_success", map[string]string{"tenant_id": "t2"}); len(got) != 1 || got[0].Value != 0 {
		t.Errorf("query t2 = %+v", got)
	}
	if got := m.Query("missing", nil); len(got) != 0 {
		t.Errorf("missing metric query = %+v", got)
	}
}

func TestMemoryWriteDedupsRedelivery(t *testing.T) {
	m := NewMemory()
	first := Series{
		Metric:     "probectl_probe_success",
		Labels:     map[string]string{"tenant_id": "t1", "agent_id": "a1"},
		Value:      1,
		TimeMillis: 1000,
	}
	redelivered := first
	redelivered.Value = 0
	if err := m.Write(context.Background(), []Series{first}); err != nil {
		t.Fatal(err)
	}
	if err := m.Write(context.Background(), []Series{redelivered}); err != nil {
		t.Fatal(err)
	}
	if got := m.Len(); got != 1 {
		t.Fatalf("redelivered sample appended duplicate: len=%d, want 1", got)
	}
	got := m.Query("probectl_probe_success", map[string]string{"tenant_id": "t1"})
	if len(got) != 1 || got[0].Value != 0 {
		t.Fatalf("redelivery should upsert latest value at same timestamp: %+v", got)
	}
}

func TestNewModes(t *testing.T) {
	if _, err := New("memory", ""); err != nil {
		t.Errorf("memory: %v", err)
	}
	if _, err := New("", ""); err != nil {
		t.Errorf("default: %v", err)
	}
	if _, err := New("prometheus", ""); err == nil {
		t.Error("prometheus without a URL should error")
	}
	if w, err := New("prometheus", "http://localhost:9090"); err != nil || w == nil {
		t.Errorf("prometheus: %v / %v", w, err)
	}
	if _, err := New("bogus", ""); err == nil {
		t.Error("unknown mode should error")
	}
}

// TestMemoryDeleteTenant (S-T5): tenant-labeled series are removed in place;
// other tenants' series survive; a re-delete reads zero (verification).
func TestMemoryDeleteTenant(t *testing.T) {
	m := NewMemory()
	_ = m.Write(context.Background(), []Series{
		{Metric: "probe_rtt", Labels: map[string]string{"tenant_id": "tnA"}, Value: 1},
		{Metric: "probe_rtt", Labels: map[string]string{"tenant_id": "tnA"}, Value: 2},
		{Metric: "probe_rtt", Labels: map[string]string{"tenant_id": "tnB"}, Value: 3},
		{Metric: "probe_up", Labels: nil, Value: 1}, // unlabeled survives too
	})
	n, err := m.DeleteTenant(context.Background(), "tnA")
	if err != nil || n != 2 {
		t.Fatalf("delete: n=%d err=%v", n, err)
	}
	if n, _ := m.DeleteTenant(context.Background(), "tnA"); n != 0 {
		t.Fatalf("re-delete must read zero: %d", n)
	}
	if n, _ := m.DeleteTenant(context.Background(), "tnB"); n != 1 {
		t.Fatalf("tenant B must have survived: %d", n)
	}
}
