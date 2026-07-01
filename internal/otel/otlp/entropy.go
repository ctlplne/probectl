// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/imfeelingtheagi/probectl/internal/otel"
)

var otlpShardResourceAttributes = []string{
	"service.name",
	"service.instance.id",
	"service.namespace",
	otel.AttrHostName,
	otel.AttrContainerID,
	"k8s.pod.uid",
	"k8s.pod.name",
}

func metricsBusEntropy(req *colmetricspb.ExportMetricsServiceRequest) string {
	for _, rm := range req.GetResourceMetrics() {
		if entropy := resourceBusEntropy(rm.GetResource()); entropy != "" {
			return entropy
		}
	}
	return ""
}

func traceBusEntropy(req *coltracepb.ExportTraceServiceRequest) string {
	for _, rs := range req.GetResourceSpans() {
		if entropy := resourceBusEntropy(rs.GetResource()); entropy != "" {
			return entropy
		}
		for _, ss := range rs.GetScopeSpans() {
			for _, span := range ss.GetSpans() {
				if traceID := span.GetTraceId(); len(traceID) >= 8 {
					return "trace:" + hex.EncodeToString(traceID[:8])
				}
			}
		}
	}
	return ""
}

func logBusEntropy(req *collogspb.ExportLogsServiceRequest) string {
	for _, rl := range req.GetResourceLogs() {
		if entropy := resourceBusEntropy(rl.GetResource()); entropy != "" {
			return entropy
		}
		for _, sl := range rl.GetScopeLogs() {
			for _, record := range sl.GetLogRecords() {
				if traceID := record.GetTraceId(); len(traceID) >= 8 {
					return "trace:" + hex.EncodeToString(traceID[:8])
				}
				if ts := record.GetTimeUnixNano(); ts != 0 {
					return "log-time:" + strconv.FormatUint(ts, 10)
				}
				if ts := record.GetObservedTimeUnixNano(); ts != 0 {
					return "log-observed:" + strconv.FormatUint(ts, 10)
				}
				if body := anyValueString(record.GetBody()); body != "" {
					return "log-body:" + fnv32Hex(body)
				}
			}
		}
	}
	return ""
}

func resourceBusEntropy(res *resourcepb.Resource) string {
	attrs := map[string]string{}
	for _, kv := range res.GetAttributes() {
		if kv.GetKey() == otel.AttrTenantID {
			continue
		}
		if value := anyValueString(kv.GetValue()); value != "" {
			attrs[kv.GetKey()] = value
		}
	}
	for _, key := range otlpShardResourceAttributes {
		if value := attrs[key]; value != "" {
			return key + "=" + value
		}
	}
	if len(attrs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h := fnv.New32a()
	for _, key := range keys {
		_, _ = h.Write([]byte(key))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(attrs[key]))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("resource:%08x", h.Sum32())
}

func anyValueString(value *commonpb.AnyValue) string {
	switch v := value.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return v.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(v.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(v.DoubleValue, 'g', -1, 64)
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(v.BoolValue)
	default:
		return ""
	}
}

func fnv32Hex(value string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(value))
	return fmt.Sprintf("%08x", h.Sum32())
}
