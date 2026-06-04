//go:build integration

package tsdb_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// TestPrometheusRemoteWrite proves the remote-write path against a real
// Prometheus (started with --web.enable-remote-write-receiver). Set
// PROBECTL_PROM_URL (e.g. http://localhost:9090); the test skips when it is unset.
func TestPrometheusRemoteWrite(t *testing.T) {
	base := os.Getenv("PROBECTL_PROM_URL")
	if base == "" {
		t.Skip("set PROBECTL_PROM_URL to run the Prometheus remote-write test")
	}

	w := tsdb.NewPrometheus(base)
	want := float64(time.Now().UnixNano() % 1000) // a recognizable integer value
	labels := map[string]string{"tenant_id": "t-itest", "agent_id": "a1", "canary_type": "noop"}
	if err := w.Write(context.Background(), []tsdb.Series{
		{Metric: "probectl_probe_success", Labels: labels, Value: want, TimeMillis: time.Now().UnixMilli()},
	}); err != nil {
		t.Fatalf("remote-write: %v", err)
	}

	q := base + "/api/v1/query?query=" + url.QueryEscape(`probectl_probe_success{tenant_id="t-itest"}`)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if prometheusHasSample(q, want) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("sample %v not visible in Prometheus within timeout", want)
}

func prometheusHasSample(q string, want float64) bool {
	resp, err := http.Get(q) //nolint:gosec // localhost test query against a known URL
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var out struct {
		Data struct {
			Result []struct {
				Value [2]any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false
	}
	for _, r := range out.Data.Result {
		s, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil && f == want {
			return true
		}
	}
	return false
}
