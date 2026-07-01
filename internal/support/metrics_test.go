// SPDX-License-Identifier: LicenseRef-probectl-TBD

package support

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

type supportGlobalOnlyWriter struct {
	series []tsdb.Series
}

func (w *supportGlobalOnlyWriter) Write(context.Context, []tsdb.Series) error {
	return errors.New("tenant Write called for support global metrics")
}

func (w *supportGlobalOnlyWriter) WriteGlobal(_ context.Context, s []tsdb.Series) error {
	w.series = append(w.series, s...)
	return nil
}

func (w *supportGlobalOnlyWriter) Close() error { return nil }

// TestWriteSelfSeries: the self-monitoring series land in the TSDB (probectl
// observes probectl), including build_info with version labels.
func TestWriteSelfSeries(t *testing.T) {
	w := tsdb.NewMemory()
	if err := WriteSelfSeries(context.Background(), w, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if g := w.Query("probectl_self_goroutines", map[string]string{}); len(g) == 0 || g[0].Value < 1 {
		t.Fatalf("goroutines series: %+v", g)
	}
	if up := w.Query("probectl_self_uptime_seconds", map[string]string{}); len(up) == 0 || up[0].Value < 1 {
		t.Fatalf("uptime series: %+v", up)
	}
	bi := w.Query("probectl_build_info", map[string]string{})
	if len(bi) == 0 || bi[0].Value != 1 || bi[0].Labels["version"] == "" {
		t.Fatalf("build_info series must carry version + value 1: %+v", bi)
	}
	// nil writer is a no-op.
	if err := WriteSelfSeries(context.Background(), nil, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// TestRunSelfMetricsLoop: the loop writes on its ticker and stops on cancel.
func TestRunSelfMetricsLoop(t *testing.T) {
	w := tsdb.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RunSelfMetrics(ctx, w, time.Now(), 5*time.Millisecond, nil); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(w.Query("probectl_self_goroutines", map[string]string{})) > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	if len(w.Query("probectl_self_goroutines", map[string]string{})) == 0 {
		t.Fatal("the self-metrics loop must write series")
	}
}

func TestWriteSelfSeriesUsesExplicitGlobalWriter(t *testing.T) {
	w := &supportGlobalOnlyWriter{}
	if err := WriteSelfSeries(context.Background(), w, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(w.series) == 0 {
		t.Fatal("self metrics did not reach the explicit global writer")
	}
	for _, s := range w.series {
		if _, ok := s.Labels[tsdb.TenantLabel]; ok {
			t.Fatalf("support global metric carried tenant_id: %+v", s)
		}
	}
}
