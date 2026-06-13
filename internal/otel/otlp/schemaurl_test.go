// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"testing"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/otel"
)

// TestExportedOTLPCarriesSchemaURL is the SCHEMA-004 acceptance test: an
// exported OTLP message must carry a non-empty schema_url equal to the pinned
// semantic-convention constant, on BOTH the ResourceMetrics and the
// ScopeMetrics, plus a non-empty scope Version. It round-trips through the wire
// (marshal → unmarshal) so it asserts what a downstream collector actually
// receives, not just the in-memory struct. The test goes red if the emitted URL
// drifts from otel.SchemaURL (the "constant and emitted URL drift" guard).
func TestExportedOTLPCarriesSchemaURL(t *testing.T) {
	r := &resultv1.Result{
		TenantId: "t1", AgentId: "a1", CanaryType: "icmp",
		Success: true, DurationNano: 100, StartTimeUnixNano: 1,
	}
	req := MetricsRequest(ResultResourceMetrics(r))

	// Round-trip through the OTLP wire form.
	wire, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got colmetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rms := got.GetResourceMetrics()
	if len(rms) != 1 {
		t.Fatalf("expected 1 ResourceMetrics, got %d", len(rms))
	}
	rm := rms[0]

	if rm.GetSchemaUrl() == "" {
		t.Fatal("ResourceMetrics.schema_url is empty — downstream cannot detect the semconv version")
	}
	if rm.GetSchemaUrl() != otel.SchemaURL {
		t.Fatalf("ResourceMetrics.schema_url = %q, want pinned %q (constant/emitted drift)", rm.GetSchemaUrl(), otel.SchemaURL)
	}

	sms := rm.GetScopeMetrics()
	if len(sms) != 1 {
		t.Fatalf("expected 1 ScopeMetrics, got %d", len(sms))
	}
	sm := sms[0]
	if sm.GetSchemaUrl() != otel.SchemaURL {
		t.Fatalf("ScopeMetrics.schema_url = %q, want pinned %q", sm.GetSchemaUrl(), otel.SchemaURL)
	}
	if sm.GetScope().GetVersion() == "" {
		t.Fatal("InstrumentationScope.version is empty — no convention version recorded")
	}
	if sm.GetScope().GetVersion() != otel.ScopeVersion {
		t.Fatalf("scope.version = %q, want %q", sm.GetScope().GetVersion(), otel.ScopeVersion)
	}
}

// TestSchemaURLPinnedToSemConvVersion guards the URL/version derivation so a
// hand-edit that decouples SchemaURL from SemConvVersion fails CI.
func TestSchemaURLPinnedToSemConvVersion(t *testing.T) {
	want := "https://opentelemetry.io/schemas/" + otel.SemConvVersion
	if otel.SchemaURL != want {
		t.Fatalf("otel.SchemaURL = %q, want %q", otel.SchemaURL, want)
	}
	if otel.ScopeVersion != otel.SemConvVersion {
		t.Fatalf("otel.ScopeVersion = %q, want SemConvVersion %q", otel.ScopeVersion, otel.SemConvVersion)
	}
}
