package fairness

import (
	"context"
	"log/slog"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// WriteSeries snapshots the gate's accounting into the TSDB as per-tenant
// series (probectl observes probectl): fairness is observable per tenant in
// the same Grafana/federate surfaces as every other probectl metric — the
// S-T7 "fairness accounting" contract. Counter semantics: cumulative since
// process start.
func WriteSeries(ctx context.Context, w tsdb.Writer, g *Gate) error {
	if w == nil || g == nil {
		return nil
	}
	now := time.Now().UnixMilli()
	var series []tsdb.Series
	add := func(metric, tenant, meter string, v float64) {
		labels := map[string]string{"tenant_id": tenant}
		if meter != "" {
			labels["meter"] = meter
		}
		series = append(series, tsdb.Series{Metric: metric, Labels: labels, Value: v, TimeMillis: now})
	}
	for _, snap := range g.SnapshotAll() {
		for meter, c := range snap.Ingest {
			add("probectl_fairness_admitted_units_total", snap.TenantID, meter, float64(c.AdmittedUnits))
			add("probectl_fairness_shed_units_total", snap.TenantID, meter, float64(c.ShedUnits))
		}
		add("probectl_fairness_queries_allowed_total", snap.TenantID, "", float64(snap.Queries.Allowed))
		add("probectl_fairness_queries_rejected_total", snap.TenantID, "",
			float64(snap.Queries.RejectedConcurrency+snap.Queries.RejectedBudget))
		add("probectl_fairness_queries_in_flight", snap.TenantID, "", float64(snap.Queries.InFlight))
	}
	if len(series) == 0 {
		return nil
	}
	return w.Write(ctx, series)
}

// RunMetrics writes fairness series every interval until ctx is canceled.
func RunMetrics(ctx context.Context, w tsdb.Writer, g *Gate, interval time.Duration, log *slog.Logger) {
	if w == nil || g == nil {
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
			if err := WriteSeries(ctx, w, g); err != nil && log != nil {
				log.Warn("fairness metrics write failed", "error", err.Error())
			}
		}
	}
}
