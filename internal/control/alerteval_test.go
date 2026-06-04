package control

import (
	"context"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

type fakeQuerier struct{ rows []tsdb.Series }

func (f fakeQuerier) Query(metric string, match map[string]string) []tsdb.Series {
	var out []tsdb.Series
	for _, s := range f.rows {
		if s.Metric != metric {
			continue
		}
		ok := true
		for k, v := range match {
			if s.Labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, s)
		}
	}
	return out
}

func TestMetricSourceLatestPerSeriesAndTenantScope(t *testing.T) {
	rows := []tsdb.Series{
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "a"}, Value: 0.1},
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "a"}, Value: 0.9}, // latest for a
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "b"}, Value: 0.2},
		{Metric: "m", Labels: map[string]string{"tenant_id": "t2", "server_address": "a"}, Value: 0.5}, // other tenant
	}
	src := metricSource{q: fakeQuerier{rows: rows}, tenant: "t1"}

	samples, err := src.Current(context.Background(), "m", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("got %d samples, want 2 (latest per series, tenant-scoped): %+v", len(samples), samples)
	}
	got := map[string]float64{}
	for _, s := range samples {
		if s.Labels["tenant_id"] != "t1" {
			t.Errorf("leaked another tenant's series: %+v", s.Labels)
		}
		got[s.Labels["server_address"]] = s.Value
	}
	if got["a"] != 0.9 || got["b"] != 0.2 {
		t.Errorf("latest values = %+v, want a=0.9 b=0.2", got)
	}
}

func TestMetricSourceAddsMatchLabels(t *testing.T) {
	rows := []tsdb.Series{
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "a"}, Value: 1},
		{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "b"}, Value: 2},
	}
	src := metricSource{q: fakeQuerier{rows: rows}, tenant: "t1"}
	samples, _ := src.Current(context.Background(), "m", map[string]string{"server_address": "b"})
	if len(samples) != 1 || samples[0].Value != 2 {
		t.Fatalf("match filter not applied: %+v", samples)
	}
}

var _ tsdbQuerier = fakeQuerier{}
var _ alert.MetricSource = metricSource{}
