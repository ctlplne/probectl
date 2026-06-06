package support

import (
	"context"
	"log/slog"
	"runtime"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// SelfSnapshot returns the self-monitoring metric values (probectl observes
// probectl) — included in the support bundle and emitted as TSDB series.
func SelfSnapshot(startedAt time.Time) map[string]float64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return map[string]float64{
		"goroutines":      float64(runtime.NumGoroutine()),
		"mem_alloc_bytes": float64(ms.Alloc),
		"mem_sys_bytes":   float64(ms.Sys),
		"num_gc":          float64(ms.NumGC),
		"uptime_seconds":  time.Since(startedAt).Seconds(),
		"max_procs":       float64(runtime.GOMAXPROCS(0)),
	}
}

// WriteSelfSeries emits the self-monitoring series into the TSDB (the
// self-monitoring dashboard reads these). build_info carries version/commit as
// labels with a constant value of 1 (the Prometheus build-info idiom).
func WriteSelfSeries(ctx context.Context, w tsdb.Writer, startedAt time.Time) error {
	if w == nil {
		return nil
	}
	now := time.Now().UnixMilli()
	var series []tsdb.Series
	for name, v := range SelfSnapshot(startedAt) {
		series = append(series, tsdb.Series{
			Metric: "probectl_self_" + name, Labels: map[string]string{}, Value: v, TimeMillis: now,
		})
	}
	info := version.Get()
	series = append(series, tsdb.Series{
		Metric: "probectl_build_info",
		Labels: map[string]string{"version": info.Version, "commit": info.Commit, "go": info.GoVersion},
		Value:  1, TimeMillis: now,
	})
	return w.Write(ctx, series)
}

// RunSelfMetrics emits the self series every interval until ctx is canceled.
func RunSelfMetrics(ctx context.Context, w tsdb.Writer, startedAt time.Time, interval time.Duration, log *slog.Logger) {
	if w == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := WriteSelfSeries(ctx, w, startedAt); err != nil && log != nil {
				log.Warn("self-metrics write failed", "error", err.Error())
			}
		}
	}
}
