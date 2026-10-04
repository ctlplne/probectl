// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/ctlplne/probectl/internal/otel"
)

func tenantAttr(v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: otel.AttrTenantID,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func metricsReqWithResource(attrs ...*commonpb.KeyValue) *colmetricspb.ExportMetricsServiceRequest {
	return &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: attrs},
		}},
	}
}

// TestScopeToTenantRejectsDuplicateTenantAttr proves the metrics-ingest lane of
// ING-39 (G7-1, fail closed): a ResourceMetrics carrying DUPLICATE tenant
// attributes — e.g. ["", "victim"] authenticated as "attacker" — must be
// rejected, not stamped-first-key-only (which left "victim" riding along for a
// last-wins reader). A single valid/empty tenant is still accepted.
func TestScopeToTenantRejectsDuplicateTenantAttr(t *testing.T) {
	// Duplicate tenant attrs, first empty: the first-match read returned "" and
	// slipped the foreign "victim" past scoping. Must now reject.
	dup := metricsReqWithResource(tenantAttr(""), tenantAttr("victim"))
	if err := scopeToTenant(dup, "attacker"); err == nil {
		t.Fatal("ING-39: duplicate tenant attrs [\"\",\"victim\"] authed as attacker were ACCEPTED; want reject (fail closed)")
	}

	// A non-string tenant attribute is also rejected.
	nonStr := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key:   otel.AttrTenantID,
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 7}},
			}}},
		}},
	}
	if err := scopeToTenant(nonStr, "attacker"); err == nil {
		t.Fatal("non-string tenant attribute was accepted; want reject")
	}

	// Non-vacuity: a single matching tenant is accepted and stamped exactly once.
	ok := metricsReqWithResource(tenantAttr("attacker"))
	if err := scopeToTenant(ok, "attacker"); err != nil {
		t.Fatalf("a single valid tenant must be accepted, got %v", err)
	}
	// And an unscoped resource is stamped with the authenticated tenant.
	empty := metricsReqWithResource()
	if err := scopeToTenant(empty, "attacker"); err != nil {
		t.Fatalf("an unscoped resource must be accepted and stamped, got %v", err)
	}
	if got := ResourceTenant(empty.GetResourceMetrics()[0]); got != "attacker" {
		t.Fatalf("unscoped resource should be stamped attacker, got %q", got)
	}
}
