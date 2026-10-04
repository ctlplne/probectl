// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"errors"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/ctlplne/probectl/internal/otel"
)

func tenantKVPipe(value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   otel.AttrTenantID,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}},
	}
}

// resourceWithTenantAttrs builds a resource carrying one probectl.tenant.id
// attribute per value (so ("", "victim") produces the ING-39 duplicate shape),
// plus a non-tenant attribute to prove the stamp preserves other attrs.
func resourceWithTenantAttrs(values ...string) *resourcepb.Resource {
	res := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
		Key:   "service.name",
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "checkout"}},
	}}}
	for _, v := range values {
		res.Attributes = append(res.Attributes, tenantKVPipe(v))
	}
	return res
}

func countTenantAttrs(res *resourcepb.Resource) (count int, foreign bool) {
	for _, kv := range res.GetAttributes() {
		if kv.GetKey() != otel.AttrTenantID {
			continue
		}
		count++
		if kv.GetValue().GetStringValue() == "victim" {
			foreign = true
		}
	}
	return count, foreign
}

// TestStampOTLPResourceTenantRejectsDuplicateTenantAttr is the ING-39 regression
// on the OTLP EXPORT stamping boundary (docs/guardrails.md G7-1). A resource
// carrying duplicate tenant attributes ["", "victim"] re-stamped for bus tenant
// "attacker" used to pass the first-match check (the empty first value is not a
// mismatch), leaving the foreign "victim" value on the resource — forwarded
// unchanged to the external collector, where a last-wins reader attributes the
// batch to "victim". Stamping must now fail closed on the foreign duplicate,
// and in every accepted case emit exactly one tenant attribute equal to the
// verified tenant.
func TestStampOTLPResourceTenantRejectsDuplicateTenantAttr(t *testing.T) {
	const attacker = "attacker"

	// --- the attack: ["", "victim"] stamped for attacker must be REJECTED ---
	traceReq := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: resourceWithTenantAttrs("", "victim"),
	}}}
	if err := scopeOTLPTracesToBusTenant(traceReq, attacker); err == nil {
		// Explicit non-nil check so the red run names the surviving foreign value.
		_, foreign := countTenantAttrs(traceReq.ResourceSpans[0].Resource)
		t.Fatalf("ING-39: duplicate tenant attrs [\"\", \"victim\"] stamped for %q were ACCEPTED (want reject); foreign \"victim\" still present=%t and would be exported", attacker, foreign)
	} else if !errors.Is(err, errOTLPResourceTenantMismatch) {
		t.Errorf("duplicate-tenant trace export error = %v, want errOTLPResourceTenantMismatch", err)
	}

	logReq := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: resourceWithTenantAttrs("", "victim"),
	}}}
	if err := scopeOTLPLogsToBusTenant(logReq, attacker); err == nil {
		t.Fatalf("ING-39: duplicate tenant attrs on logs stamped for %q were ACCEPTED (want reject)", attacker)
	}

	metricReq := &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: resourceWithTenantAttrs("", "victim"),
	}}}
	if err := scopeOTLPMetricsToBusTenant(metricReq, attacker); err == nil {
		t.Fatalf("ING-39: duplicate tenant attrs on metrics stamped for %q were ACCEPTED (want reject)", attacker)
	}

	// --- normalization: a duplicate whose values are empty/matching collapses
	// to exactly one verified-tenant attribute; export never emits a second key.
	norm := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: resourceWithTenantAttrs("", attacker),
	}}}
	if err := scopeOTLPTracesToBusTenant(norm, attacker); err != nil {
		t.Fatalf("empty+matching duplicate rejected: %v", err)
	}
	if n, foreign := countTenantAttrs(norm.ResourceSpans[0].Resource); n != 1 || foreign {
		t.Errorf("normalized resource has %d tenant attrs (foreign=%t), want exactly 1 and no foreign value", n, foreign)
	}

	// --- non-vacuity: an ordinary single-tenant resource is accepted, scoped,
	// and keeps its other attributes.
	ok := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: resourceWithTenantAttrs(attacker),
	}}}
	if err := scopeOTLPTracesToBusTenant(ok, attacker); err != nil {
		t.Fatalf("single-tenant resource rejected: %v", err)
	}
	res := ok.ResourceSpans[0].Resource
	if n, _ := countTenantAttrs(res); n != 1 {
		t.Errorf("single-tenant resource has %d tenant attrs, want 1", n)
	}
	var keptService bool
	for _, kv := range res.GetAttributes() {
		if kv.GetKey() == "service.name" && kv.GetValue().GetStringValue() == "checkout" {
			keptService = true
		}
		if kv.GetKey() == otel.AttrTenantID && kv.GetValue().GetStringValue() != attacker {
			t.Errorf("tenant attr = %q, want %q", kv.GetValue().GetStringValue(), attacker)
		}
	}
	if !keptService {
		t.Error("stamping dropped the non-tenant service.name attribute")
	}
}
