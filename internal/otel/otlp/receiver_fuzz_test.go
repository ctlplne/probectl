package otlp

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/otel"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
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
