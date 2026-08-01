// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package otlp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/otel"
)

// TestMetricPointTypeConformance pins every OTLP metric data oneof to an
// explicit receiver outcome. A new protobuf point type cannot become an
// accidental success followed by a downstream drop: the default is reject.
func TestMetricPointTypeConformance(t *testing.T) {
	tests := []struct {
		name    string
		metric  *metricspb.Metric
		wantErr string
	}{
		{name: "gauge", metric: &metricspb.Metric{Name: "fixture.gauge", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{}}}},
		{name: "sum", metric: &metricspb.Metric{Name: "fixture.sum", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{}}}},
		{name: "explicit histogram", metric: &metricspb.Metric{Name: "fixture.histogram", Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{}}}},
		{name: "summary", metric: &metricspb.Metric{Name: "fixture.summary", Data: &metricspb.Metric_Summary{Summary: &metricspb.Summary{}}}, wantErr: `unsupported metric point type "summary"`},
		{name: "exponential histogram", metric: &metricspb.Metric{Name: "fixture.exponential", Data: &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{}}}, wantErr: `unsupported metric point type "exponential_histogram"`},
		{name: "unset data", metric: &metricspb.Metric{Name: "fixture.unset"}, wantErr: `unsupported metric point type "unspecified"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMetricPointTypes(metricPointTypeRequest("tenant-a", tt.metric))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("supported point type rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestMetricPointTypeRejectionIsProtocolVisibleAndTenantFirst(t *testing.T) {
	var grpcSinkCalls int
	grpcService := newMetricsService(SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error {
		grpcSinkCalls++
		return nil
	}))
	summary := func(tenant string) *colmetricspb.ExportMetricsServiceRequest {
		return metricPointTypeRequest(tenant, &metricspb.Metric{
			Name: "request.duration",
			Data: &metricspb.Metric_Summary{Summary: &metricspb.Summary{
				DataPoints: []*metricspb.SummaryDataPoint{{Count: 1, Sum: 4.2}},
			}},
		})
	}

	_, err := grpcService.Export(withTenant(context.Background(), "tenant-a"), summary("tenant-a"))
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(status.Convert(err).Message(), "summary") {
		t.Fatalf("gRPC summary error = %v, want InvalidArgument with summary detail", err)
	}
	// Tenant isolation is the outer boundary: a foreign-tenant payload must not
	// reveal its later point-type error or reach the sink.
	_, err = grpcService.Export(withTenant(context.Background(), "tenant-a"), summary("tenant-b"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("gRPC foreign-tenant summary code = %v, want PermissionDenied", status.Code(err))
	}
	if grpcSinkCalls != 0 {
		t.Fatalf("gRPC sink called %d times for rejected point types", grpcSinkCalls)
	}

	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	var httpSinkCalls int
	handler := MetricsHTTPHandler(auth, SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error {
		httpSinkCalls++
		return nil
	}), 1<<20)

	post := func(req *colmetricspb.ExportMetricsServiceRequest) *httptest.ResponseRecorder {
		body, marshalErr := proto.Marshal(req)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer tok")
		r.Header.Set("Content-Type", "application/x-protobuf")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	if w := post(summary("tenant-a")); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "summary") {
		t.Fatalf("HTTP summary response = %d %q, want 400 with summary detail", w.Code, w.Body.String())
	}
	if w := post(summary("tenant-b")); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "summary") {
		t.Fatalf("HTTP foreign-tenant summary response = %d %q, want tenant-first 403", w.Code, w.Body.String())
	}
	if httpSinkCalls != 0 {
		t.Fatalf("HTTP sink called %d times for rejected point types", httpSinkCalls)
	}
}

func metricPointTypeRequest(tenant string, metric *metricspb.Metric) *colmetricspb.ExportMetricsServiceRequest {
	resource := &resourcepb.Resource{}
	if tenant != "" {
		resource.Attributes = append(resource.Attributes, &commonpb.KeyValue{
			Key: otel.AttrTenantID,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{
				StringValue: tenant,
			}},
		})
	}
	return &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: resource,
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{metric},
			}},
		}},
	}
}
