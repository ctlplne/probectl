package otlp

import (
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/otel"
)

const scopeName = "probectl"

// ResultResourceMetrics converts a probe Result to OTLP ResourceMetrics, using
// the canonical S6 resource attributes.
func ResultResourceMetrics(r *resultv1.Result) *metricspb.ResourceMetrics {
	ts := uint64(r.GetStartTimeUnixNano())
	ms := []*metricspb.Metric{
		gauge("probectl.probe.duration", "ns", ts, float64(r.GetDurationNano())),
		gauge("probectl.probe.success", "1", ts, b2f(r.GetSuccess())),
	}
	for name, v := range r.GetMetrics() {
		ms = append(ms, gauge("probectl.metric."+name, "", ts, v))
	}
	return resourceMetrics(otel.ResultAttributes(r), ms...)
}

// FlowResourceMetrics converts an eBPF L3/L4 flow to OTLP ResourceMetrics.
func FlowResourceMetrics(f *ebpfv1.Flow) *metricspb.ResourceMetrics {
	ts := uint64(f.GetObservedAtUnixNano())
	return resourceMetrics(otel.FlowAttributes(f),
		gauge("probectl.flow.bytes", "By", ts, float64(f.GetBytes())),
		gauge("probectl.flow.packets", "1", ts, float64(f.GetPackets())),
	)
}

// L7CallResourceMetrics converts an eBPF L7 call to OTLP ResourceMetrics.
func L7CallResourceMetrics(c *ebpfv1.L7Call) *metricspb.ResourceMetrics {
	ts := uint64(c.GetStartUnixNano())
	return resourceMetrics(otel.L7CallAttributes(c),
		gauge("probectl.l7.duration", "ns", ts, float64(c.GetLatencyNano())),
		gauge("probectl.l7.error", "1", ts, b2f(c.GetError())),
	)
}

// BGPEventResourceMetrics converts a BGP routing-security event to OTLP
// ResourceMetrics (the event surfaces as a unit-valued gauge with its attrs).
func BGPEventResourceMetrics(e *bgpv1.BGPEvent) *metricspb.ResourceMetrics {
	ts := uint64(e.GetDetectedAtUnixNano())
	return resourceMetrics(otel.BGPEventAttributes(e),
		gauge("probectl.bgp.event", "1", ts, 1),
	)
}

// MetricsRequest wraps ResourceMetrics into an OTLP export request.
func MetricsRequest(rms ...*metricspb.ResourceMetrics) *colmetricspb.ExportMetricsServiceRequest {
	return &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: rms}
}

// ResourceTenant returns the probectl.tenant.id resource attribute, if present.
// The receiver uses it to enforce that a push matches its authenticated tenant.
func ResourceTenant(rm *metricspb.ResourceMetrics) string {
	for _, kv := range rm.GetResource().GetAttributes() {
		if kv.GetKey() == otel.AttrTenantID {
			return kv.GetValue().GetStringValue()
		}
	}
	return ""
}

// --- builders -------------------------------------------------------------

func resourceMetrics(attrs map[string]string, metrics ...*metricspb.Metric) *metricspb.ResourceMetrics {
	return &metricspb.ResourceMetrics{
		Resource: &resourcepb.Resource{Attributes: kvAttrs(attrs)},
		ScopeMetrics: []*metricspb.ScopeMetrics{{
			Scope:   &commonpb.InstrumentationScope{Name: scopeName},
			Metrics: metrics,
		}},
	}
}

func gauge(name, unit string, ts uint64, value float64) *metricspb.Metric {
	return &metricspb.Metric{
		Name: name,
		Unit: unit,
		Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
			DataPoints: []*metricspb.NumberDataPoint{{
				TimeUnixNano: ts,
				Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: value},
			}},
		}},
	}
}

func kvAttrs(m map[string]string) []*commonpb.KeyValue {
	kvs := make([]*commonpb.KeyValue, 0, len(m))
	for k, v := range m {
		kvs = append(kvs, &commonpb.KeyValue{
			Key:   k,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}},
		})
	}
	return kvs
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
