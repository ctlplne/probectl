// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cluster

import (
	"context"
	"log/slog"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// WriteSeries snapshots the cluster state into the TSDB as region-labeled
// series (probectl observes probectl): multi-region health is visible in the
// same Grafana/federate surfaces as everything else. Every series carries the
// replica's region label so a global dashboard can break down by region.
func WriteSeries(ctx context.Context, w tsdb.Writer, m *Manager) error {
	if w == nil || m == nil {
		return nil
	}
	st := m.Status()
	now := time.Now().UnixMilli()
	labels := map[string]string{"region": st.Topology.Region}
	b2f := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}
	role2f := func(r Role) float64 {
		// writer=1 (healthy), reader=0, stale=-1, unknown=-2 — a single gauge
		// an alert can fire on (writer_role < 1 = this node can't write).
		switch r {
		case RoleWriter:
			return 1
		case RoleReader:
			return 0
		case RoleStale:
			return -1
		default:
			return -2
		}
	}
	series := []tsdb.Series{
		{Metric: "probectl_cluster_writes_usable", Labels: labels, Value: b2f(st.WritesUsable), TimeMillis: now},
		{Metric: "probectl_cluster_writer_role", Labels: labels, Value: role2f(st.Writer.Role), TimeMillis: now},
		{Metric: "probectl_cluster_epoch", Labels: labels, Value: float64(st.HighestEpoch), TimeMillis: now},
	}
	if st.Reader != nil {
		series = append(series, tsdb.Series{
			Metric: "probectl_cluster_replica_lag_seconds", Labels: labels,
			Value: st.Reader.LagSeconds, TimeMillis: now,
		})
	}
	return tsdb.WriteGlobal(ctx, w, series)
}

// RunMetrics writes cluster series every interval until ctx is canceled.
func RunMetrics(ctx context.Context, w tsdb.Writer, m *Manager, interval time.Duration, log *slog.Logger) {
	if w == nil || m == nil {
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
			if err := WriteSeries(ctx, w, m); err != nil && log != nil {
				log.Warn("cluster metrics write failed", "error", err.Error())
			}
		}
	}
}
