// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"strings"
	"time"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/otel"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

const metricPrefix = "probectl_probe_"

// labelNames maps the OTel attributes promoted to (bounded-cardinality) metric
// labels to their Prometheus label names. tenant_id is a label in pooled mode;
// query-time tenant scoping (S23) enforces isolation at the TSDB.
var labelNames = map[string]string{
	otel.AttrTenantID:      "tenant_id",
	otel.AttrAgentID:       "agent_id",
	otel.AttrCanaryType:    "canary_type",
	otel.AttrServerAddress: "server_address",
}

// ResultToSeries converts a probe Result into time series with OTel-aligned,
// cardinality-bounded labels. It always emits probectl_probe_success and
// probectl_probe_duration_seconds, plus one probectl_probe_<name> per custom metric.
func ResultToSeries(r *resultv1.Result) []tsdb.Series {
	attrs := otel.ResultAttributes(r)
	labels := make(map[string]string, len(labelNames))
	for otelKey, promName := range labelNames {
		if v, ok := attrs[otelKey]; ok {
			labels[promName] = v
		}
	}

	now := time.Now().UnixMilli()
	tms := r.GetStartTimeUnixNano() / int64(time.Millisecond)
	if tms == 0 {
		// CORRECT-002 tms==0 policy: with no agent event time we stamp INGEST time.
		// Idempotency for results comes from the TSDB on (series, event-timestamp),
		// NOT from result_id (results are TSDB series, not ReplacingMergeTree rows
		// — the proto field doc spells this out). A result WITHOUT an event time is
		// therefore NOT idempotent across redelivery; agents set
		// start_time_unix_nano to get exactly-once-effective samples. Counted as a
		// future-clamp no-op (the timestamp is now, never future).
		tms = now
	} else {
		tms = clampFutureSample(tms, now) // CORRECT-012: clamp far-future agent clocks
	}

	out := []tsdb.Series{
		{Metric: metricPrefix + "success", Labels: labels, Value: boolFloat(r.GetSuccess()), TimeMillis: tms},
		{Metric: metricPrefix + "duration_seconds", Labels: labels, Value: float64(r.GetDurationNano()) / 1e9, TimeMillis: tms},
	}
	for name, val := range r.GetMetrics() {
		out = append(out, tsdb.Series{Metric: metricPrefix + sanitize(name), Labels: labels, Value: val, TimeMillis: tms})
	}
	return out
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// sanitize maps a string to a valid Prometheus metric/label character set
// (replacing any other rune, e.g. '.', with '_'): "rtt.avg.ms" -> "rtt_avg_ms".
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}
