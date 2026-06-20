// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"regexp"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/promapi"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// metricsEvidenceSource adapts the production TSDB writer to ai.MetricsSource.
// It always injects tenant_id into the selector before reading. Unanchored
// questions return no metric rows instead of scanning every tenant series.
type metricsEvidenceSource struct{ writer tsdb.Writer }

type instantVectorSource interface {
	InstantVector(context.Context, string) ([]tsdb.LabeledSample, error)
}

var metricNameRE = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

func (s metricsEvidenceSource) QueryMetrics(ctx context.Context, tenant string, sel map[string]string, r ai.TimeRange, limit int) ([]ai.Row, error) {
	if s.writer == nil || !metricQueryAnchored(sel) {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	selector := metricsSelector(sel, tenant)
	if snap, ok := s.writer.(promSnapshotter); ok {
		return s.queryMemoryMetrics(snap.Snapshot(), selector, r, limit)
	}
	if upstream, ok := s.writer.(instantVectorSource); ok {
		samples, err := upstream.InstantVector(ctx, selector.String())
		if err != nil {
			return nil, err
		}
		rows := make([]ai.Row, 0, len(samples))
		for _, sample := range samples {
			if len(rows) >= limit {
				break
			}
			rows = append(rows, metricSampleRow(metricName(sample.Labels), sample.Labels, sample.Value, time.Time{}))
		}
		return rows, nil
	}
	return nil, nil
}

func (s metricsEvidenceSource) queryMemoryMetrics(snapshot []tsdb.Series, selector promapi.Selector, r ai.TimeRange, limit int) ([]ai.Row, error) {
	end := r.End
	if end.IsZero() {
		end = time.Now()
	}
	start := r.Start
	if start.IsZero() {
		start = end.Add(-time.Hour)
	}
	series, err := promapi.Range(snapshot, selector, start, end, limit)
	if err != nil {
		return nil, err
	}
	rows := make([]ai.Row, 0, len(series))
	for _, rs := range series {
		if len(rows) >= limit {
			break
		}
		if len(rs.Points) == 0 {
			continue
		}
		point := rs.Points[len(rs.Points)-1]
		rows = append(rows, metricSampleRow(rs.Metric, rs.Labels, point.Value, time.UnixMilli(point.TimeMillis).UTC()))
	}
	return rows, nil
}

func metricQueryAnchored(sel map[string]string) bool {
	for _, key := range []string{"metric", "target", "prefix", "node", "service", "agent_id", "instance", "job"} {
		if sel[key] != "" {
			return true
		}
	}
	return false
}

func metricsSelector(sel map[string]string, tenant string) promapi.Selector {
	out := promapi.Selector{}
	if metric := sel["metric"]; metricNameRE.MatchString(metric) {
		out.Metric = metric
	}
	for _, key := range []string{"target", "prefix", "node", "service", "agent_id", "instance", "job"} {
		if v := sel[key]; v != "" {
			out.Matchers = append(out.Matchers, promapi.Matcher{Name: key, Op: "=", Value: v})
		}
	}
	return promapi.ForceTenant(out, tenant)
}

func metricSampleRow(metric string, labels map[string]string, value float64, at time.Time) ai.Row {
	row := ai.Row{
		"metric": metric,
		"value":  value,
		"plane":  "metrics",
		"title":  metric,
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	row["timestamp"] = at
	for _, key := range []string{"target", "prefix", "node", "service", "agent_id", "instance", "job", "unit"} {
		if v := labels[key]; v != "" {
			row[key] = v
		}
	}
	if row["target"] == nil {
		if v := labels["instance"]; v != "" {
			row["target"] = v
		}
	}
	return row
}

func metricName(labels map[string]string) string {
	if labels == nil {
		return "metric"
	}
	if n := labels["__name__"]; n != "" {
		return n
	}
	if n := labels["metric"]; n != "" {
		return n
	}
	return "metric"
}
