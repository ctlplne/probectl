// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/otel"
)

// OTLP re-export redaction (RTP-06). The STORAGE path (convertSpansWithContext /
// convertLogsWithContext) runs every span name, log body and attribute value
// through govern.RedactTelemetry{Text,Attribute} before persistence — an
// Authorization header, a URL token or a known secret in an inbound span never
// reaches the otelstore in the clear. The re-export path forwarded the raw OTLP
// protobuf verbatim, so the very bytes storage masks were egressing to an
// external collector untouched. These helpers apply the SAME per-field govern
// calls to the OTLP request IN PLACE before export, so the exported payload
// carries exactly the redacted form storage would hold (docs/guardrails.md G7-1,
// §7 guardrail 6: secrets never cross a boundary).

// redactTracesForExport masks span names, span/event/link attributes and status
// messages in place with the storage-equivalent telemetry redaction. The
// authoritative probectl.tenant.id resource stamp is preserved (the collector
// needs it to attribute the spans to a tenant; storage drops it only because it
// has a dedicated tenant column).
func redactTracesForExport(ctx context.Context, req *coltracepb.ExportTraceServiceRequest, tenant string) {
	if req == nil {
		return
	}
	pol := govern.TelemetryPIIPolicy(ctx, tenant)
	for _, rs := range req.GetResourceSpans() {
		if rs == nil {
			continue
		}
		redactResourceAttrsForExport(pol, rs.GetResource().GetAttributes())
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				if sp == nil {
					continue
				}
				sp.Name = govern.RedactTelemetryText(pol, sp.GetName())
				redactKVAttrsForExport(pol, sp.GetAttributes())
				if st := sp.GetStatus(); st != nil {
					st.Message = govern.RedactTelemetryText(pol, st.GetMessage())
				}
				for _, ev := range sp.GetEvents() {
					if ev == nil {
						continue
					}
					ev.Name = govern.RedactTelemetryText(pol, ev.GetName())
					redactKVAttrsForExport(pol, ev.GetAttributes())
				}
				for _, ln := range sp.GetLinks() {
					if ln == nil {
						continue
					}
					redactKVAttrsForExport(pol, ln.GetAttributes())
				}
			}
		}
	}
}

// redactLogsForExport masks log bodies and log/resource attributes in place with
// the storage-equivalent telemetry redaction (mirrors convertLogsWithContext).
func redactLogsForExport(ctx context.Context, req *collogspb.ExportLogsServiceRequest, tenant string) {
	if req == nil {
		return
	}
	pol := govern.TelemetryPIIPolicy(ctx, tenant)
	for _, rl := range req.GetResourceLogs() {
		if rl == nil {
			continue
		}
		redactResourceAttrsForExport(pol, rl.GetResource().GetAttributes())
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				if lr == nil {
					continue
				}
				redactStringValueText(pol, lr.GetBody())
				redactKVAttrsForExport(pol, lr.GetAttributes())
			}
		}
	}
}

// redactMetricsForExport masks resource and data-point attribute values in place.
// The native metrics storage path flattens attributes into TSDB labels without
// the govern pass, but a re-export leaves the operator's network, so the
// always-mask secret floor (bearer/Authorization/credential shapes, carried by
// govern.RedactTelemetryAttribute) is applied here too: a metric label must
// never egress an Authorization header or a known secret.
func redactMetricsForExport(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest, tenant string) {
	if req == nil {
		return
	}
	pol := govern.TelemetryPIIPolicy(ctx, tenant)
	for _, rm := range req.GetResourceMetrics() {
		if rm == nil {
			continue
		}
		redactResourceAttrsForExport(pol, rm.GetResource().GetAttributes())
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				redactMetricPointAttrsForExport(pol, m)
			}
		}
	}
}

func redactMetricPointAttrsForExport(pol govern.Policy, m *metricspb.Metric) {
	switch d := m.GetData().(type) {
	case *metricspb.Metric_Gauge:
		for _, p := range d.Gauge.GetDataPoints() {
			redactKVAttrsForExport(pol, p.GetAttributes())
		}
	case *metricspb.Metric_Sum:
		for _, p := range d.Sum.GetDataPoints() {
			redactKVAttrsForExport(pol, p.GetAttributes())
		}
	case *metricspb.Metric_Histogram:
		for _, p := range d.Histogram.GetDataPoints() {
			redactKVAttrsForExport(pol, p.GetAttributes())
		}
	case *metricspb.Metric_ExponentialHistogram:
		for _, p := range d.ExponentialHistogram.GetDataPoints() {
			redactKVAttrsForExport(pol, p.GetAttributes())
		}
	case *metricspb.Metric_Summary:
		for _, p := range d.Summary.GetDataPoints() {
			redactKVAttrsForExport(pol, p.GetAttributes())
		}
	}
}

// redactResourceAttrsForExport redacts resource attribute values in place,
// preserving only the authoritative tenant stamp. Mirrors resourceInfo's
// per-attribute govern call on the storage side.
func redactResourceAttrsForExport(pol govern.Policy, kvs []*commonpb.KeyValue) {
	for _, kv := range kvs {
		if kv == nil || kv.GetKey() == otel.AttrTenantID {
			continue
		}
		redactKVValue(pol, kv)
	}
}

// redactKVAttrsForExport redacts every string-valued attribute in place with the
// same per-attribute call the storage converter uses (govern.RedactTelemetry-
// Attribute). Non-string scalars cannot carry a header/secret and are left as-is;
// composite values are not scanned (the storage plane does not flatten them into
// a row either).
func redactKVAttrsForExport(pol govern.Policy, kvs []*commonpb.KeyValue) {
	for _, kv := range kvs {
		if kv == nil {
			continue
		}
		redactKVValue(pol, kv)
	}
}

func redactKVValue(pol govern.Policy, kv *commonpb.KeyValue) {
	av := kv.GetValue()
	if av == nil {
		return
	}
	sv, ok := av.GetValue().(*commonpb.AnyValue_StringValue)
	if !ok || sv.StringValue == "" {
		return
	}
	sv.StringValue = govern.RedactTelemetryAttribute(pol, kv.GetKey(), sv.StringValue)
}

// redactStringValueText masks a free-text AnyValue (a log body / span field) in
// place with govern.RedactTelemetryText, the same call the storage path applies
// to a log body. Only string values are rewritten.
func redactStringValueText(pol govern.Policy, av *commonpb.AnyValue) {
	if av == nil {
		return
	}
	sv, ok := av.GetValue().(*commonpb.AnyValue_StringValue)
	if !ok || sv.StringValue == "" {
		return
	}
	sv.StringValue = govern.RedactTelemetryText(pol, sv.StringValue)
}
