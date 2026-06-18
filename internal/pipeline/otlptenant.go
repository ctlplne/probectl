// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"errors"
	"fmt"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/imfeelingtheagi/probectl/internal/otel"
)

var errOTLPResourceTenantMismatch = errors.New("pipeline: OTLP resource tenant does not match bus tenant")

func scopeOTLPMetricsToBusTenant(req *colmetricspb.ExportMetricsServiceRequest, tenant string) error {
	for _, rm := range req.GetResourceMetrics() {
		if err := stampOTLPResourceTenant(&rm.Resource, tenant); err != nil {
			return err
		}
	}
	return nil
}

func scopeOTLPTracesToBusTenant(req *coltracepb.ExportTraceServiceRequest, tenant string) error {
	for _, rs := range req.GetResourceSpans() {
		if err := stampOTLPResourceTenant(&rs.Resource, tenant); err != nil {
			return err
		}
	}
	return nil
}

func scopeOTLPLogsToBusTenant(req *collogspb.ExportLogsServiceRequest, tenant string) error {
	for _, rl := range req.GetResourceLogs() {
		if err := stampOTLPResourceTenant(&rl.Resource, tenant); err != nil {
			return err
		}
	}
	return nil
}

func stampOTLPResourceTenant(res **resourcepb.Resource, tenant string) error {
	if tenant == "" {
		return ErrNoTenant
	}
	if *res == nil {
		*res = &resourcepb.Resource{}
	}
	for _, kv := range (*res).GetAttributes() {
		if kv.GetKey() != otel.AttrTenantID {
			continue
		}
		got := kv.GetValue().GetStringValue()
		if got != "" && got != tenant {
			return fmt.Errorf("%w: bus tenant %q payload tenant %q", errOTLPResourceTenantMismatch, tenant, got)
		}
		kv.Value = otlpTenantValue(tenant)
		return nil
	}
	(*res).Attributes = append((*res).Attributes, &commonpb.KeyValue{
		Key:   otel.AttrTenantID,
		Value: otlpTenantValue(tenant),
	})
	return nil
}

func otlpTenantValue(tenant string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}}
}
