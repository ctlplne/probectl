// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package support

import (
	"context"
	"log/slog"
	"runtime"
	"time"

	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/version"
)

// SelfMetrics is a point-in-time, deployment-local process snapshot. It
// contains no tenant labels or telemetry and is safe for the admin diagnostics
// surface and the secret-stripped support bundle.
type SelfMetrics struct {
	Goroutines    int     `json:"goroutines"`
	MemAllocBytes uint64  `json:"mem_alloc_bytes"`
	MemSysBytes   uint64  `json:"mem_sys_bytes"`
	NumGC         uint32  `json:"num_gc"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	MaxProcs      int     `json:"max_procs"`
}

// CollectSelfMetrics returns the typed process snapshot used by native
// diagnostics. Keep this as the single collector so the native surface, bundle,
// and optional metrics-protocol integrations report the same values.
func CollectSelfMetrics(startedAt time.Time) SelfMetrics {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	uptime := time.Since(startedAt).Seconds()
	if uptime < 0 {
		uptime = 0
	}
	return SelfMetrics{
		Goroutines:    runtime.NumGoroutine(),
		MemAllocBytes: ms.Alloc,
		MemSysBytes:   ms.Sys,
		NumGC:         ms.NumGC,
		UptimeSeconds: uptime,
		MaxProcs:      runtime.GOMAXPROCS(0),
	}
}

// SelfSnapshot returns the self-monitoring metric values (probectl observes
// probectl) — included in the support bundle and emitted as TSDB series.
func SelfSnapshot(startedAt time.Time) map[string]float64 {
	snapshot := CollectSelfMetrics(startedAt)
	return map[string]float64{
		"goroutines":      float64(snapshot.Goroutines),
		"mem_alloc_bytes": float64(snapshot.MemAllocBytes),
		"mem_sys_bytes":   float64(snapshot.MemSysBytes),
		"num_gc":          float64(snapshot.NumGC),
		"uptime_seconds":  snapshot.UptimeSeconds,
		"max_procs":       float64(snapshot.MaxProcs),
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
	return tsdb.WriteGlobal(ctx, w, series)
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
