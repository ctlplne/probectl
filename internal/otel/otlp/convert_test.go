package otlp

import (
	"testing"

	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"

	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/otel"
)

func resourceAttrs(rm *metricspb.ResourceMetrics) map[string]string {
	out := map[string]string{}
	for _, kv := range rm.GetResource().GetAttributes() {
		out[kv.GetKey()] = kv.GetValue().GetStringValue()
	}
	return out
}

func metricNames(rm *metricspb.ResourceMetrics) map[string]bool {
	out := map[string]bool{}
	for _, sm := range rm.GetScopeMetrics() {
		for _, m := range sm.GetMetrics() {
			out[m.GetName()] = true
		}
	}
	return out
}

func TestResultResourceMetricsConform(t *testing.T) {
	r := &resultv1.Result{
		TenantId: "t1", AgentId: "a1", CanaryType: "icmp", ServerAddress: "ex", ServerPort: 443,
		NetworkTransport: "tcp", Success: true, DurationNano: 1500, StartTimeUnixNano: 100,
		Metrics: map[string]float64{"rtt.avg.ms": 12.5},
	}
	rm := ResultResourceMetrics(r)

	attrs := resourceAttrs(rm)
	if attrs[otel.AttrTenantID] != "t1" {
		t.Errorf("tenant resource attr = %q", attrs[otel.AttrTenantID])
	}
	for k := range attrs {
		if !otel.KnownAttributes[k] {
			t.Errorf("non-convention resource attribute %q", k)
		}
	}
	if names := metricNames(rm); !names["probectl.probe.duration"] || !names["probectl.metric.rtt.avg.ms"] {
		t.Errorf("metrics = %v", names)
	}
	if ResourceTenant(rm) != "t1" {
		t.Errorf("ResourceTenant = %q", ResourceTenant(rm))
	}
}

func TestEveryConverterCarriesTenantAndConforms(t *testing.T) {
	rms := []*metricspb.ResourceMetrics{
		ResultResourceMetrics(&resultv1.Result{TenantId: "t", AgentId: "a", CanaryType: "icmp"}),
		FlowResourceMetrics(&ebpfv1.Flow{TenantId: "t", AgentId: "a", SourceAddress: "1.1.1.1", DestinationAddress: "2.2.2.2", DestinationPort: 443, NetworkTransport: "tcp", Bytes: 10, Packets: 1}),
		L7CallResourceMetrics(&ebpfv1.L7Call{TenantId: "t", AgentId: "a", Protocol: "http1", Method: "GET", Resource: "/x", Status: "200"}),
		BGPEventResourceMetrics(&bgpv1.BGPEvent{TenantId: "t", EventType: bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE, Severity: bgpv1.Severity_SEVERITY_INFO, Prefix: "192.0.2.0/24"}),
	}
	for i, rm := range rms {
		if ResourceTenant(rm) != "t" {
			t.Errorf("converter %d: tenant = %q, want t", i, ResourceTenant(rm))
		}
		for k := range resourceAttrs(rm) {
			if !otel.KnownAttributes[k] {
				t.Errorf("converter %d: non-convention attribute %q", i, k)
			}
		}
		if len(rm.GetScopeMetrics()) == 0 || len(rm.GetScopeMetrics()[0].GetMetrics()) == 0 {
			t.Errorf("converter %d: no metrics emitted", i)
		}
	}
}

func TestMetricsRequest(t *testing.T) {
	req := MetricsRequest(ResultResourceMetrics(&resultv1.Result{TenantId: "t"}))
	if len(req.GetResourceMetrics()) != 1 {
		t.Fatalf("resource metrics = %d, want 1", len(req.GetResourceMetrics()))
	}
}
