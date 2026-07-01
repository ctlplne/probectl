// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tsdb

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryWriteRejectsUnlabeledTenantSeries(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	tests := []Series{
		{Metric: "probe_up", Labels: nil, Value: 1},
		{Metric: "probe_up", Labels: map[string]string{}, Value: 1},
		{Metric: "probe_up", Labels: map[string]string{TenantLabel: ""}, Value: 1},
	}
	for _, s := range tests {
		if err := m.Write(ctx, []Series{s}); !errors.Is(err, ErrTenantRequired) {
			t.Fatalf("Write(%+v) error = %v, want ErrTenantRequired", s, err)
		}
	}
	if got := m.Len(); got != 0 {
		t.Fatalf("rejected unlabeled writes must not retain samples: len=%d", got)
	}
}

func TestPrometheusWriteRejectsUnlabeledBeforeNetwork(t *testing.T) {
	p := NewPrometheus("http://127.0.0.1:1")
	err := p.Write(context.Background(), []Series{{Metric: "probe_up", Labels: nil, Value: 1}})
	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("prometheus Write without tenant_id = %v, want ErrTenantRequired", err)
	}
}

func TestExplicitGlobalWriterPath(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	global := []Series{{Metric: "probectl_self_goroutines", Labels: map[string]string{}, Value: 9}}
	if err := m.Write(ctx, global); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("tenant Write for global series = %v, want ErrTenantRequired", err)
	}
	if err := WriteGlobal(ctx, m, global); err != nil {
		t.Fatalf("WriteGlobal: %v", err)
	}
	if got := m.Query("probectl_self_goroutines", nil); len(got) != 1 || got[0].Value != 9 {
		t.Fatalf("global series not retained via explicit path: %+v", got)
	}
	if err := WriteGlobal(ctx, m, []Series{{Metric: "probe_up", Labels: map[string]string{TenantLabel: "t1"}, Value: 1}}); !errors.Is(err, ErrGlobalTenantLabel) {
		t.Fatalf("WriteGlobal with tenant_id = %v, want ErrGlobalTenantLabel", err)
	}
}

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

// TestMemoryDeleteTenant (S-T5): every tenant-labeled series for the tenant is
// removed in place; other tenants and explicit global metrics survive; a
// re-delete reads zero (verification).
func TestMemoryDeleteTenant(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if err := m.Write(ctx, []Series{
		{Metric: "probe_rtt", Labels: map[string]string{"tenant_id": "tnA"}, Value: 1},
		{Metric: "probe_rtt", Labels: map[string]string{"tenant_id": "tnA"}, Value: 2},
		{Metric: "probe_up", Labels: map[string]string{"tenant_id": "tnA"}, Value: 1},
		{Metric: "probe_rtt", Labels: map[string]string{"tenant_id": "tnB"}, Value: 3},
	}); err != nil {
		t.Fatal(err)
	}
	if err := WriteGlobal(ctx, m, []Series{{Metric: "probectl_self_goroutines", Labels: nil, Value: 1}}); err != nil {
		t.Fatal(err)
	}
	n, err := m.DeleteTenant(ctx, "tnA")
	if err != nil || n != 3 {
		t.Fatalf("delete: n=%d err=%v", n, err)
	}
	if got := m.Query("probe_rtt", map[string]string{"tenant_id": "tnA"}); len(got) != 0 {
		t.Fatalf("tenant A probe_rtt survived delete: %+v", got)
	}
	if got := m.Query("probe_up", map[string]string{"tenant_id": "tnA"}); len(got) != 0 {
		t.Fatalf("tenant A probe_up survived delete: %+v", got)
	}
	if got := m.Query("probectl_self_goroutines", nil); len(got) != 1 || got[0].Labels[TenantLabel] != "" {
		t.Fatalf("explicit global series must survive tenant delete: %+v", got)
	}
	if n, _ := m.DeleteTenant(ctx, "tnA"); n != 0 {
		t.Fatalf("re-delete must read zero: %d", n)
	}
	if n, _ := m.DeleteTenant(ctx, "tnB"); n != 1 {
		t.Fatalf("tenant B must have survived: %d", n)
	}
}
