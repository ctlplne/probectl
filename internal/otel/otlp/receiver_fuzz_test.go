// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/otel"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// FuzzOTLPPayload (U-082): the OTLP ingest body is authenticated but
// UNTRUSTED (guardrail 12). Whatever bytes arrive, unmarshal + the tenant
// scoping pass must never panic — and scoping must hold: after a successful
// scopeToTenant, every resource carries the authenticated tenant.
func FuzzOTLPPayload(f *testing.F) {
	// Seed: a well-formed request (no tenant, foreign tenant, matching tenant).
	mk := func(tenant string) []byte {
		rm := &metricspb.ResourceMetrics{Resource: &resourcepb.Resource{}}
		if tenant != "" {
			rm.Resource.Attributes = append(rm.Resource.Attributes, &commonpb.KeyValue{
				Key:   otel.AttrTenantID,
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}},
			})
		}
		b, _ := proto.Marshal(&colmetricspb.ExportMetricsServiceRequest{
			ResourceMetrics: []*metricspb.ResourceMetrics{rm},
		})
		return b
	}
	f.Add(mk(""))
	f.Add(mk("tenant-a"))
	f.Add(mk("tenant-evil"))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, body []byte) {
		var req colmetricspb.ExportMetricsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			return // rejected at parse — fine
		}
		err := scopeToTenant(&req, "tenant-a")
		if err != nil {
			return // foreign tenant refused — fine
		}
		// Accepted: every resource must now read as the caller's tenant via
		// the SAME first-match reader the pipeline uses downstream.
		for _, rm := range req.ResourceMetrics {
			if rm == nil {
				continue
			}
			if got := ResourceTenant(rm); got != "tenant-a" {
				t.Fatalf("scoped resource reads tenant %q, want tenant-a", got)
			}
		}
	})
}

func FuzzOTLPTracePayload(f *testing.F) {
	for _, seed := range tracePayloadSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		var req coltracepb.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			return
		}
		err := scopeTracesToTenant(&req, "tenant-a")
		if err != nil {
			return
		}
		for _, rs := range req.GetResourceSpans() {
			if rs == nil {
				continue
			}
			if got := resourceTenantOf(rs.GetResource()); got != "tenant-a" {
				t.Fatalf("scoped trace resource reads tenant %q, want tenant-a", got)
			}
		}
	})
}

func FuzzOTLPLogPayload(f *testing.F) {
	for _, seed := range logPayloadSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		var req collogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			return
		}
		err := scopeLogsToTenant(&req, "tenant-a")
		if err != nil {
			return
		}
		for _, rl := range req.GetResourceLogs() {
			if rl == nil {
				continue
			}
			if got := resourceTenantOf(rl.GetResource()); got != "tenant-a" {
				t.Fatalf("scoped log resource reads tenant %q, want tenant-a", got)
			}
		}
	})
}

func tracePayloadSeeds() [][]byte {
	return [][]byte{
		mustFuzzMarshal(&coltracepb.ExportTraceServiceRequest{}),
		mustFuzzMarshal(&coltracepb.ExportTraceServiceRequest{
			ResourceSpans: []*tracepb.ResourceSpans{{}},
		}),
		mustFuzzMarshal(&coltracepb.ExportTraceServiceRequest{
			ResourceSpans: []*tracepb.ResourceSpans{{Resource: fuzzTenantResource("tenant-a")}},
		}),
		mustFuzzMarshal(&coltracepb.ExportTraceServiceRequest{
			ResourceSpans: []*tracepb.ResourceSpans{{Resource: fuzzTenantResource("tenant-evil")}},
		}),
		mustFuzzMarshal(&coltracepb.ExportTraceServiceRequest{
			ResourceSpans: []*tracepb.ResourceSpans{{Resource: fuzzTenantResource("")}},
		}),
		mustFuzzMarshal(&coltracepb.ExportTraceServiceRequest{
			ResourceSpans: []*tracepb.ResourceSpans{{Resource: fuzzNilTenantValueResource()}},
		}),
		{},
		{0xff, 0xff, 0xff},
		{0x82, 0x06, 0x00}, // unknown field 100, length-delimited, empty
	}
}

func logPayloadSeeds() [][]byte {
	return [][]byte{
		mustFuzzMarshal(&collogspb.ExportLogsServiceRequest{}),
		mustFuzzMarshal(&collogspb.ExportLogsServiceRequest{
			ResourceLogs: []*logspb.ResourceLogs{{}},
		}),
		mustFuzzMarshal(&collogspb.ExportLogsServiceRequest{
			ResourceLogs: []*logspb.ResourceLogs{{Resource: fuzzTenantResource("tenant-a")}},
		}),
		mustFuzzMarshal(&collogspb.ExportLogsServiceRequest{
			ResourceLogs: []*logspb.ResourceLogs{{Resource: fuzzTenantResource("tenant-evil")}},
		}),
		mustFuzzMarshal(&collogspb.ExportLogsServiceRequest{
			ResourceLogs: []*logspb.ResourceLogs{{Resource: fuzzTenantResource("")}},
		}),
		mustFuzzMarshal(&collogspb.ExportLogsServiceRequest{
			ResourceLogs: []*logspb.ResourceLogs{{Resource: fuzzNilTenantValueResource()}},
		}),
		{},
		{0xff, 0xff, 0xff},
		{0x82, 0x06, 0x00}, // unknown field 100, length-delimited, empty
	}
}

func fuzzTenantResource(tenant string) *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
		Key:   otel.AttrTenantID,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}},
	}}}
}

func fuzzNilTenantValueResource() *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
		Key: otel.AttrTenantID,
	}}}
}

func mustFuzzMarshal(m proto.Message) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}
