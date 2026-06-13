// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// OTLPConsumer drains probectl.otlp.metrics into the TSDB (Sprint 16,
// SCALE-010 — the topic previously had NO consumer: externally-ingested OTLP
// was published and silently dropped). The receiver already authenticated the
// push and stamped the tenant (token → tenant, Sprint 6 coverage); messages
// arrive tenant-keyed with a marshaled ExportMetricsServiceRequest payload.
//
// Conversion scope (deliberate, documented): GAUGE and SUM number data points
// become series (the metric shapes OTel-instrumented infra overwhelmingly
// exports); histogram/summary points are counted and skipped until the
// Sprint 22 traces/logs/histogram plane lands. Labels are bounded (the
// busiest attributes win deterministically) and every series carries
// tenant_id — the same label contract as every other plane, so RBAC'd PromQL
// and Grafana federation see OTLP metrics exactly like native ones.
type OTLPConsumer struct {
	bus  bus.Bus
	tsdb tsdb.Writer
	log  *slog.Logger

	consumed atomic.Uint64
	skipped  atomic.Uint64 // unsupported point kinds (histogram/summary/exp-histogram)
	shed     atomic.Uint64 // series shed by the per-tenant fairness gate (SCALE-003)
	dlq      *otlpDLQ      // retry + dead-letter on store-write failure (SCALE-003)

	// SCALE-003: the OTLP plane gets the same per-tenant bounds as the native
	// planes. gate sheds an over-rate tenant's series (fairness); card caps a
	// tenant's distinct series identities (cardinality). OTLP has no agent id,
	// so cardinality is keyed by tenant alone (agent="").
	gate *fairness.Gate
	card *CardinalityLimiter
}

// otlpMaxLabels bounds per-series labels (cardinality stance, U-017).
const otlpMaxLabels = 12

// NewOTLPConsumer builds the consumer.
func NewOTLPConsumer(b bus.Bus, w tsdb.Writer, log *slog.Logger) *OTLPConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &OTLPConsumer{bus: b, tsdb: w, log: log,
		dlq: newOTLPDLQ(b, bus.DeadLetterOTLPMetricsTopic, "metrics", log)}
}

// WithMetrics surfaces this consumer's dead-letter/drop counters at /metrics
// (OPS-005). Returns the consumer for chaining.
func (c *OTLPConsumer) WithMetrics(reg *metrics.Registry) *OTLPConsumer {
	c.dlq.withMetrics(reg)
	return c
}

// WithFairness bounds per-tenant OTLP series admission (SCALE-003): an over-rate
// tenant's series are shed BEFORE the store write, so an OTLP-flooding tenant
// cannot starve others — the same contract as the native planes.
func (c *OTLPConsumer) WithFairness(g *fairness.Gate) *OTLPConsumer {
	c.gate = g
	return c
}

// WithCardinalityCaps bounds per-tenant distinct OTLP series identities
// (SCALE-003). OTLP carries no agent id, so the per-agent cap is unused and the
// per-tenant cap is the wall against a unique-attribute flood.
func (c *OTLPConsumer) WithCardinalityCaps(perTenant int) *OTLPConsumer {
	c.card = NewCardinalityLimiter(0, perTenant)
	return c
}

// Run subscribes until ctx is canceled. It blocks.
func (c *OTLPConsumer) Run(ctx context.Context) error {
	c.log.Info("otlp metrics consumer starting", "topic", bus.OTLPMetricsTopic)
	return c.bus.Subscribe(ctx, bus.OTLPMetricsTopic, "otlp-metrics", c.handle)
}

func (c *OTLPConsumer) handle(ctx context.Context, msg bus.Message) error {
	var req colmetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(msg.Value, &req); err != nil {
		c.log.Warn("dropping malformed OTLP payload", "error", err.Error())
		return nil
	}
	// The RECEIVER stamped/verified the tenant resource attribute (Sprint 6
	// covered the injection cases); the bus key carries the same tenant.
	tenant := string(tenantFromKey(msg.Key))
	series := c.convert(&req, tenant)
	if len(series) == 0 {
		return nil
	}
	// SCALE-003: per-tenant fairness shed BEFORE the expensive store write — an
	// OTLP-flooding tenant cannot starve others (identical to the native planes).
	if c.gate != nil && !c.gate.AdmitN(ctx, tenant, fairness.MeterOTLPSeries, int64(len(series))) {
		c.shed.Add(uint64(len(series)))
		c.log.Debug("otlp metrics shed by fairness bounds", "tenant_id", tenant, "series", len(series))
		return nil
	}
	// SCALE-003: per-tenant series-cardinality cap — a unique-attribute flood is
	// dropped+counted per series; known identities keep flowing.
	if c.card != nil {
		var dropped int
		series, dropped = c.card.Filter(tenant, "", series)
		if dropped > 0 {
			c.log.Warn("otlp series rejected by cardinality cap", "tenant_id", tenant, "rejected", dropped)
		}
		if len(series) == 0 {
			return nil
		}
	}
	// SCALE-003 / ARCH-002: retry the store write, then dead-letter the original
	// bytes (replayable) + count — no longer a silent best-effort drop.
	if stored := c.dlq.process(ctx, msg, func(ctx context.Context) error {
		return c.tsdb.Write(ctx, series)
	}); stored {
		c.consumed.Add(uint64(len(series)))
	}
	return nil
}

// Consumed reports stored series (the round-trip test's hook).
func (c *OTLPConsumer) Consumed() uint64 { return c.consumed.Load() }

// Shed reports series shed by the per-tenant fairness gate (SCALE-003).
func (c *OTLPConsumer) Shed() uint64 { return c.shed.Load() }

// tenantFromKey strips the Sprint 15 |bucket suffix if present.
func tenantFromKey(key []byte) []byte {
	for i, b := range key {
		if b == '|' {
			return key[:i]
		}
	}
	return key
}

// convert flattens gauge/sum number points into tenant-labeled series.
func (c *OTLPConsumer) convert(req *colmetricspb.ExportMetricsServiceRequest, tenant string) []tsdb.Series {
	var out []tsdb.Series
	for _, rm := range req.GetResourceMetrics() {
		// Resource attributes apply to every point underneath (bounded later).
		resAttrs := map[string]string{}
		for _, kv := range rm.GetResource().GetAttributes() {
			if v := kv.GetValue().GetStringValue(); v != "" {
				resAttrs[kv.GetKey()] = v
			}
		}
		if t := resAttrs["probectl.tenant.id"]; t != "" {
			tenant = t // the receiver-stamped truth wins over the bus key
		}
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				var points []*metricspb.NumberDataPoint
				delta := false // CORRECT-011: track DELTA-temporality sums
				switch d := m.GetData().(type) {
				case *metricspb.Metric_Gauge:
					points = d.Gauge.GetDataPoints()
				case *metricspb.Metric_Sum:
					points = d.Sum.GetDataPoints()
					// CORRECT-011: a DELTA sum reports the change since the last
					// export, NOT a running total — emitting it as a plain
					// Prometheus value (which readers treat as cumulative) would
					// be wrong. Tag delta series with otel_temporality="delta" so
					// a query can distinguish them and not sum deltas as if
					// cumulative; cumulative sums are unmarked (the common case).
					delta = d.Sum.GetAggregationTemporality() == metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
				case *metricspb.Metric_Histogram:
					// ARCH-006: convert OTLP explicit-bucket histograms to the
					// Prometheus _bucket/_sum/_count series triple instead of
					// dropping them, so histogram_quantile() works and latency
					// SLOs over OTLP histograms are queryable.
					// CORRECT-008: honor aggregation temporality. A DELTA histogram
					// reports the counts SINCE THE LAST EXPORT, not a monotonically
					// cumulative-over-time total. Emitting it as a plain Prometheus
					// histogram (which readers treat as cumulative and rate()) would
					// misread it — so DELTA points are tagged otel_temporality="delta"
					// exactly like the SUM path, letting a query distinguish them and
					// not apply rate()/increase() as if cumulative. The within-point
					// across-bucket cumulation (le buckets) is correct either way.
					histDelta := d.Histogram.GetAggregationTemporality() == metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
					out = append(out, c.histogramSeries(m.GetName(), d.Histogram.GetDataPoints(), tenant, resAttrs, histDelta)...)
					continue
				default:
					c.skipped.Add(1) // summary / exponential histogram: not yet converted
					continue
				}
				name := "probectl_otlp_" + sanitize(m.GetName())
				for _, p := range points {
					labels := map[string]string{"tenant_id": tenant}
					if delta {
						labels["otel_temporality"] = "delta" // CORRECT-011
					}
					addBounded(labels, resAttrs)
					pointAttrs := map[string]string{}
					for _, kv := range p.GetAttributes() {
						if v := kv.GetValue().GetStringValue(); v != "" {
							pointAttrs[kv.GetKey()] = v
						}
					}
					addBounded(labels, pointAttrs)
					var v float64
					switch nv := p.GetValue().(type) {
					case *metricspb.NumberDataPoint_AsDouble:
						v = nv.AsDouble
					case *metricspb.NumberDataPoint_AsInt:
						v = float64(nv.AsInt)
					}
					tms := int64(p.GetTimeUnixNano() / 1e6)
					now := time.Now().UnixMilli()
					if tms == 0 {
						tms = now
					} else {
						tms = clampFutureSample(tms, now) // CORRECT-006: clamp far-future push clocks
					}
					out = append(out, tsdb.Series{Metric: name, Labels: labels, Value: v, TimeMillis: tms})
				}
			}
		}
	}
	return out
}

// histogramSeries converts OTLP explicit-bucket histogram points into the
// Prometheus convention: cumulative <name>_bucket{le=...} series (with a +Inf
// bucket), plus <name>_sum and <name>_count (ARCH-006). Without this the points
// were dropped, so any latency/size histogram pushed over OTLP was invisible to
// queries and SLOs.
func (c *OTLPConsumer) histogramSeries(metricName string, points []*metricspb.HistogramDataPoint, tenant string, resAttrs map[string]string, delta bool) []tsdb.Series {
	base := "probectl_otlp_" + sanitize(metricName)
	var out []tsdb.Series
	for _, p := range points {
		labels := map[string]string{"tenant_id": tenant}
		if delta {
			labels["otel_temporality"] = "delta" // CORRECT-008: not cumulative-over-time
		}
		addBounded(labels, resAttrs)
		pointAttrs := map[string]string{}
		for _, kv := range p.GetAttributes() {
			if v := kv.GetValue().GetStringValue(); v != "" {
				pointAttrs[kv.GetKey()] = v
			}
		}
		addBounded(labels, pointAttrs)

		tms := int64(p.GetTimeUnixNano() / 1e6)
		now := time.Now().UnixMilli()
		if tms == 0 {
			tms = now
		} else {
			tms = clampFutureSample(tms, now) // CORRECT-006: clamp far-future push clocks
		}

		// Cumulative buckets with le labels. ExplicitBounds has N entries;
		// BucketCounts has N+1 (the last is the +Inf overflow bucket).
		bounds := p.GetExplicitBounds()
		counts := p.GetBucketCounts()
		var cumulative uint64
		for i, cnt := range counts {
			cumulative += cnt
			le := "+Inf"
			if i < len(bounds) {
				le = strconv.FormatFloat(bounds[i], 'g', -1, 64)
			}
			bl := make(map[string]string, len(labels)+1)
			for k, v := range labels {
				bl[k] = v
			}
			bl["le"] = le
			out = append(out, tsdb.Series{Metric: base + "_bucket", Labels: bl, Value: float64(cumulative), TimeMillis: tms})
		}
		out = append(out, tsdb.Series{Metric: base + "_count", Labels: labels, Value: float64(p.GetCount()), TimeMillis: tms})
		if p.Sum != nil {
			out = append(out, tsdb.Series{Metric: base + "_sum", Labels: labels, Value: p.GetSum(), TimeMillis: tms})
		}
	}
	return out
}

// addBounded merges attrs into labels (sanitized keys) up to otlpMaxLabels,
// deterministically (sorted) so series identities stay stable. tenant_id can
// never be overwritten.
func addBounded(labels map[string]string, attrs map[string]string) {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(labels) >= otlpMaxLabels {
			return
		}
		lk := sanitize(k)
		if lk == "tenant_id" || lk == "" {
			continue
		}
		if _, exists := labels[lk]; !exists {
			labels[lk] = attrs[k]
		}
	}
}
