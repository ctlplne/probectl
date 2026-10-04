// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"errors"
	"fmt"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/ctlplne/probectl/internal/otel"
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
	// Scan EVERY probectl.tenant.id attribute, not just the first. A resource
	// carrying duplicates — e.g. ["", "victim"] — would otherwise pass a
	// first-match check (the empty first value is not a mismatch) and let the
	// foreign second value ride through to the external collector, where a
	// last-wins reader attributes the batch to the foreign tenant (ING-39).
	// Reject any foreign value and strip every tenant attribute, then re-stamp
	// exactly one holding the verified tenant so export can never emit a second
	// tenant key — fail closed (docs/guardrails.md G7-1).
	kept := make([]*commonpb.KeyValue, 0, len((*res).GetAttributes()))
	for _, kv := range (*res).GetAttributes() {
		if kv.GetKey() != otel.AttrTenantID {
			kept = append(kept, kv)
			continue
		}
		if got := kv.GetValue().GetStringValue(); got != "" && got != tenant {
			return fmt.Errorf("%w: bus tenant %q payload tenant %q", errOTLPResourceTenantMismatch, tenant, got)
		}
	}
	kept = append(kept, &commonpb.KeyValue{
		Key:   otel.AttrTenantID,
		Value: otlpTenantValue(tenant),
	})
	(*res).Attributes = kept
	return nil
}

func otlpTenantValue(tenant string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}}
}
