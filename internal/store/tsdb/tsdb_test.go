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
