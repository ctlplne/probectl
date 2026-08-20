// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// completeness-store-probe is audit-only glue. It uses the same hardened TLS
// client and tenant-labeled Prometheus writer as the product, while keeping
// runtime credentials in Authorization headers (never URL userinfo/query).
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	probcrypto "github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

var (
	uuidRE        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	markerRE      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	spanIDRE      = regexp.MustCompile(`^[0-9a-f]{16}$`)
	kafkaBucketRE = regexp.MustCompile(`^[0-9a-f-]{36}\|b[a-p]$`)
)

const (
	productMetricName       = "completeness_product_marker"
	productStoredMetricName = "probectl_otlp_completeness_product_marker"
	productSpanName         = "completeness-product-marker"
	productMetricValueA     = int64(84001)
	productMetricValueB     = int64(84002)
	maxProductResponseBytes = 4 << 20
)

type result struct {
	Service                string `json:"service"`
	Passed                 bool   `json:"passed"`
	TenantA                string `json:"tenant_a"`
	TenantB                string `json:"tenant_b"`
	SeededA                int64  `json:"seeded_tenant_a_rows"`
	SeededB                int64  `json:"seeded_tenant_b_rows"`
	OwnVisibleA            int64  `json:"tenant_a_own_visible_rows"`
	OwnVisibleB            int64  `json:"tenant_b_own_visible_rows"`
	MissingTenantLabels    *int64 `json:"missing_tenant_label_series,omitempty"`
	MismatchedTenantLabels *int64 `json:"mismatched_tenant_label_series,omitempty"`
	TotalObservedSeries    *int64 `json:"total_observed_series,omitempty"`
	ExpectedLabeledSeries  *int64 `json:"expected_tenant_labeled_series,omitempty"`
	Detail                 string `json:"detail"`
}

type effectiveIdentity struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

func currentEffectiveIdentity() effectiveIdentity {
	return effectiveIdentity{UID: os.Geteuid(), GID: os.Getegid()}
}

func main() {
	if len(os.Args) != 2 {
		fatal(errors.New("usage: completeness-store-probe identity|prometheus|product-ingest|product-kafka|product-stores"))
	}
	if os.Args[1] == "identity" {
		if err := json.NewEncoder(os.Stdout).Encode(currentEffectiveIdentity()); err != nil {
			fatal(err)
		}
		return
	}
	a, b := must("AUDIT_TENANT_A"), must("AUDIT_TENANT_B")
	if !uuidRE.MatchString(a) || !uuidRE.MatchString(b) || a == b {
		fatal(errors.New("distinct lowercase UUID tenant ids are required"))
	}
	if os.Args[1] == "product-ingest" {
		fatalIf(productIngest(a, b))
		return
	}
	if os.Args[1] == "product-kafka" {
		fatalIf(productKafka(a, b))
		return
	}
	if os.Args[1] == "product-stores" {
		fatalIf(productStores(a, b))
		return
	}
	var out result
	var err error
	switch os.Args[1] {
	case "prometheus":
		out, err = probePrometheus(a, b)
	default:
		err = fmt.Errorf("unknown probe %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fatal(err)
	}
}

func fatalIf(err error) {
	if err != nil {
		fatal(err)
	}
}

func must(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		fatal(fmt.Errorf("%s is required", name))
	}
	return value
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "store probe:", err)
	os.Exit(1)
}

type productMarkers struct {
	MetricA string
	MetricB string
	TraceA  string
	TraceB  string
	SpanA   string
	SpanB   string
}

func loadProductMarkers() (productMarkers, error) {
	out := productMarkers{
		MetricA: must("AUDIT_METRIC_MARKER_A"),
		MetricB: must("AUDIT_METRIC_MARKER_B"),
		TraceA:  must("AUDIT_TRACE_MARKER_A"),
		TraceB:  must("AUDIT_TRACE_MARKER_B"),
		SpanA:   must("AUDIT_TRACE_SPAN_ID_A"),
		SpanB:   must("AUDIT_TRACE_SPAN_ID_B"),
	}
	seen := make(map[string]bool, 4)
	for name, value := range map[string]string{
		"AUDIT_METRIC_MARKER_A": out.MetricA,
		"AUDIT_METRIC_MARKER_B": out.MetricB,
		"AUDIT_TRACE_MARKER_A":  out.TraceA,
		"AUDIT_TRACE_MARKER_B":  out.TraceB,
	} {
		if !markerRE.MatchString(value) || seen[value] {
			return productMarkers{}, fmt.Errorf("%s must be a unique lowercase 128-bit hex marker", name)
		}
		seen[value] = true
	}
	if !spanIDRE.MatchString(out.SpanA) || !spanIDRE.MatchString(out.SpanB) {
		return productMarkers{}, errors.New("trace span ids must be lowercase 64-bit hex values")
	}
	return out, nil
}

func productService(marker string) string { return "completeness-" + marker }

func stringAttribute(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{
			StringValue: value,
		}},
	}
}

func productResource(tenant, marker string) *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		stringAttribute(otel.AttrTenantID, tenant),
		stringAttribute("service.name", productService(marker)),
	}}
}

func productMetricRequest(tenant, marker string, value int64) *colmetricspb.ExportMetricsServiceRequest {
	return &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: productResource(tenant, marker),
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: productMetricName,
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
				Attributes:   []*commonpb.KeyValue{stringAttribute("marker", marker)},
				TimeUnixNano: uint64(time.Now().UTC().UnixNano()),
				Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: float64(value)},
			}}}},
		}}}},
	}}}
}

func productTraceRequest(tenant, marker, spanID string) (*coltracepb.ExportTraceServiceRequest, error) {
	traceBytes, err := hex.DecodeString(marker)
	if err != nil {
		return nil, err
	}
	spanBytes, err := hex.DecodeString(spanID)
	if err != nil {
		return nil, err
	}
	end := time.Now().UTC()
	start := end.Add(-time.Millisecond)
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: productResource(tenant, marker),
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
			TraceId:           traceBytes,
			SpanId:            spanBytes,
			Name:              productSpanName,
			Kind:              tracepb.Span_SPAN_KIND_SERVER,
			StartTimeUnixNano: uint64(start.UnixNano()),
			EndTimeUnixNano:   uint64(end.UnixNano()),
		}}}},
	}}}, nil
}

func verifiedHTTPClient(caFile string) (*http.Client, error) {
	tlsConfig, err := probcrypto.HardenedClientTLSConfigWithCAFile(caFile)
	if err != nil {
		return nil, err
	}
	client := probcrypto.HardenedHTTPClient(20 * time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("hardened HTTP client returned an unexpected transport")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = tlsConfig
	client.Transport = transport
	return client, nil
}

func productArtifactParent(root, relative string) (*os.Root, string, error) {
	root = filepath.Clean(root)
	relative = filepath.Clean(relative)
	if root == "." || !filepath.IsAbs(root) || relative == "." || filepath.IsAbs(relative) ||
		relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, "", errors.New("product artifact path is not a safe absolute-root/relative-path pair")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("product artifact root must be a real directory")
	}
	current, err := os.OpenRoot(root)
	if err != nil {
		return nil, "", err
	}
	currentInfo, err := current.Stat(".")
	if err != nil || !os.SameFile(info, currentInfo) {
		current.Close()
		return nil, "", errors.New("product artifact root changed while opening")
	}
	parent := filepath.Dir(relative)
	if parent != "." {
		for _, component := range strings.Split(parent, string(filepath.Separator)) {
			componentInfo, statErr := current.Lstat(component)
			if errors.Is(statErr, os.ErrNotExist) {
				if mkdirErr := current.Mkdir(component, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
					current.Close()
					return nil, "", mkdirErr
				}
				componentInfo, statErr = current.Lstat(component)
			}
			if statErr != nil || componentInfo.Mode()&os.ModeSymlink != 0 || !componentInfo.IsDir() {
				current.Close()
				return nil, "", fmt.Errorf("product artifact parent %q is not a real directory", component)
			}
			next, openErr := current.OpenRoot(component)
			if openErr != nil {
				current.Close()
				return nil, "", openErr
			}
			nextInfo, statErr := next.Stat(".")
			if statErr != nil || !os.SameFile(componentInfo, nextInfo) {
				next.Close()
				current.Close()
				return nil, "", fmt.Errorf("product artifact parent %q changed while opening", component)
			}
			current.Close()
			current = next
		}
	}
	return current, filepath.Base(relative), nil
}

func writeProductArtifact(root, relative string, data []byte) error {
	parent, base, err := productArtifactParent(root, relative)
	if err != nil {
		return err
	}
	defer parent.Close()
	file, err := parent.OpenFile(base, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create new product artifact %s: %w", relative, err)
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			_ = parent.Remove(base)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write product artifact %s: %w", relative, err)
	}
	if err := file.Chmod(0o644); err != nil {
		return fmt.Errorf("chmod product artifact %s: %w", relative, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close product artifact %s: %w", relative, err)
	}
	complete = true
	return nil
}

func postProductOTLP(client *http.Client, root, endpoint, token, requestPath, responsePath string, request, response proto.Message) (int, error) {
	payload, err := proto.Marshal(request)
	if err != nil {
		return 0, err
	}
	if err := writeProductArtifact(root, requestPath, payload); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProductResponseBytes+1))
	if err != nil {
		return 0, err
	}
	if len(body) > maxProductResponseBytes {
		return 0, errors.New("OTLP response exceeds audit bound")
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("OTLP endpoint returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := proto.Unmarshal(body, response); err != nil {
		return resp.StatusCode, fmt.Errorf("decode OTLP response: %w", err)
	}
	if err := writeProductArtifact(root, responsePath, body); err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

type productIngestSignal struct {
	CorrelationID     string    `json:"correlation_id"`
	SpanID            string    `json:"span_id,omitempty"`
	ServiceName       string    `json:"service_name"`
	Value             float64   `json:"value,omitempty"`
	TimeUnixNano      uint64    `json:"time_unix_nano,omitempty"`
	StartTimeUnixNano uint64    `json:"start_time_unix_nano,omitempty"`
	EndTimeUnixNano   uint64    `json:"end_time_unix_nano,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
	RequestPath       string    `json:"request_path"`
	ResponsePath      string    `json:"response_path"`
	Status            int       `json:"status"`
}

type productIngestTenant struct {
	Tenant  string              `json:"tenant"`
	Metrics productIngestSignal `json:"metrics"`
	Traces  productIngestSignal `json:"traces"`
}

func productIngest(a, b string) error {
	markers, err := loadProductMarkers()
	if err != nil {
		return err
	}
	root := must("AUDIT_ARTIFACT_DIR")
	client, err := verifiedHTTPClient(must("AUDIT_CA_FILE"))
	if err != nil {
		return err
	}
	type input struct {
		tenant, token, metric, trace, span string
		value                              int64
	}
	inputs := []input{
		{tenant: a, token: must("AUDIT_OTLP_TOKEN_A"), metric: markers.MetricA, trace: markers.TraceA, span: markers.SpanA, value: productMetricValueA},
		{tenant: b, token: must("AUDIT_OTLP_TOKEN_B"), metric: markers.MetricB, trace: markers.TraceB, span: markers.SpanB, value: productMetricValueB},
	}
	out := struct {
		Tenants []productIngestTenant `json:"tenants"`
	}{Tenants: make([]productIngestTenant, 0, 2)}
	for _, in := range inputs {
		prefix := filepath.ToSlash(filepath.Join("product", in.tenant))
		metricRequestPath := prefix + "/metrics-ingest-request.pb"
		metricResponsePath := prefix + "/metrics-ingest-response.pb"
		metricRequest := productMetricRequest(in.tenant, in.metric, in.value)
		metricStatus, err := postProductOTLP(client, root, "https://control:4318/v1/metrics", in.token,
			metricRequestPath, metricResponsePath, metricRequest,
			&colmetricspb.ExportMetricsServiceResponse{})
		if err != nil {
			return fmt.Errorf("tenant %s metrics ingest: %w", in.tenant, err)
		}
		metricObservedAt := time.Now().UTC()
		traceRequest, err := productTraceRequest(in.tenant, in.trace, in.span)
		if err != nil {
			return err
		}
		traceRequestPath := prefix + "/traces-ingest-request.pb"
		traceResponsePath := prefix + "/traces-ingest-response.pb"
		traceStatus, err := postProductOTLP(client, root, "https://control:4318/v1/traces", in.token,
			traceRequestPath, traceResponsePath, traceRequest, &coltracepb.ExportTraceServiceResponse{})
		if err != nil {
			return fmt.Errorf("tenant %s traces ingest: %w", in.tenant, err)
		}
		traceObservedAt := time.Now().UTC()
		metricPoint := metricRequest.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].GetGauge().DataPoints[0]
		traceSpan := traceRequest.ResourceSpans[0].ScopeSpans[0].Spans[0]
		out.Tenants = append(out.Tenants, productIngestTenant{
			Tenant: in.tenant,
			Metrics: productIngestSignal{CorrelationID: in.metric, ServiceName: productService(in.metric), Value: float64(in.value),
				TimeUnixNano: metricPoint.TimeUnixNano, ObservedAt: metricObservedAt,
				RequestPath: metricRequestPath, ResponsePath: metricResponsePath, Status: metricStatus},
			Traces: productIngestSignal{CorrelationID: in.trace, SpanID: in.span, ServiceName: productService(in.trace),
				StartTimeUnixNano: traceSpan.StartTimeUnixNano, EndTimeUnixNano: traceSpan.EndTimeUnixNano, ObservedAt: traceObservedAt,
				RequestPath: traceRequestPath, ResponsePath: traceResponsePath, Status: traceStatus},
		})
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

type kafkaRecordObservation struct {
	Tenant      string `json:"tenant"`
	Topic       string `json:"topic"`
	Partition   int32  `json:"partition"`
	Offset      int64  `json:"offset"`
	KeyPath     string `json:"key_path"`
	PayloadPath string `json:"payload_path"`
}

type expectedProductRecord struct {
	tenant, marker, span string
	value                int64
}

func attributeValue(attributes []*commonpb.KeyValue, key string) string {
	value := ""
	for _, attribute := range attributes {
		if attribute.GetKey() != key {
			continue
		}
		if value != "" {
			return ""
		}
		value = attribute.GetValue().GetStringValue()
	}
	return value
}

func validProductMetricPayload(payload []byte, expected expectedProductRecord) bool {
	var request colmetricspb.ExportMetricsServiceRequest
	if proto.Unmarshal(payload, &request) != nil || len(request.ResourceMetrics) != 1 {
		return false
	}
	resourceMetrics := request.ResourceMetrics[0]
	if attributeValue(resourceMetrics.GetResource().GetAttributes(), otel.AttrTenantID) != expected.tenant ||
		attributeValue(resourceMetrics.GetResource().GetAttributes(), "service.name") != productService(expected.marker) ||
		len(resourceMetrics.ScopeMetrics) != 1 || len(resourceMetrics.ScopeMetrics[0].Metrics) != 1 {
		return false
	}
	metric := resourceMetrics.ScopeMetrics[0].Metrics[0]
	gauge := metric.GetGauge()
	if metric.Name != productMetricName || gauge == nil || len(gauge.DataPoints) != 1 {
		return false
	}
	point := gauge.DataPoints[0]
	return attributeValue(point.Attributes, "marker") == expected.marker && point.GetAsDouble() == float64(expected.value)
}

func validProductTracePayload(payload []byte, expected expectedProductRecord) bool {
	var request coltracepb.ExportTraceServiceRequest
	if proto.Unmarshal(payload, &request) != nil || len(request.ResourceSpans) != 1 {
		return false
	}
	resourceSpans := request.ResourceSpans[0]
	if attributeValue(resourceSpans.GetResource().GetAttributes(), otel.AttrTenantID) != expected.tenant ||
		attributeValue(resourceSpans.GetResource().GetAttributes(), "service.name") != productService(expected.marker) ||
		len(resourceSpans.ScopeSpans) != 1 || len(resourceSpans.ScopeSpans[0].Spans) != 1 {
		return false
	}
	span := resourceSpans.ScopeSpans[0].Spans[0]
	return hex.EncodeToString(span.TraceId) == expected.marker && hex.EncodeToString(span.SpanId) == expected.span &&
		span.Name == productSpanName && span.Kind == tracepb.Span_SPAN_KIND_SERVER
}

func captureKafkaRecord(root string, record *kgo.Record, expected expectedProductRecord, signal string) (kafkaRecordObservation, error) {
	if !kafkaBucketRE.Match(record.Key) || bus.TenantFromKey(record.Key) != expected.tenant {
		return kafkaRecordObservation{}, fmt.Errorf("%s Kafka key is not the expected tenant-bucketed key", signal)
	}
	valid := false
	switch signal {
	case "metrics":
		valid = validProductMetricPayload(record.Value, expected)
	case "traces":
		valid = validProductTracePayload(record.Value, expected)
	}
	if !valid {
		return kafkaRecordObservation{}, fmt.Errorf("%s Kafka payload does not contain the exact expected tenant marker", signal)
	}
	prefix := filepath.ToSlash(filepath.Join("product", expected.tenant))
	keyPath := prefix + "/" + signal + "-kafka-key.bin"
	payloadPath := prefix + "/" + signal + "-kafka-payload.pb"
	if err := writeProductArtifact(root, keyPath, record.Key); err != nil {
		return kafkaRecordObservation{}, err
	}
	if err := writeProductArtifact(root, payloadPath, record.Value); err != nil {
		return kafkaRecordObservation{}, err
	}
	return kafkaRecordObservation{Tenant: expected.tenant, Topic: record.Topic, Partition: record.Partition,
		Offset: record.Offset, KeyPath: keyPath, PayloadPath: payloadPath}, nil
}

func productKafka(a, b string) error {
	markers, err := loadProductMarkers()
	if err != nil {
		return err
	}
	tlsConfig, err := probcrypto.HardenedClientTLSConfigWithCAFile(must("AUDIT_CA_FILE"))
	if err != nil {
		return err
	}
	client, err := kgo.NewClient(
		kgo.SeedBrokers(must("AUDIT_KAFKA_BROKER")),
		kgo.DialTLSConfig(tlsConfig),
		kgo.SASL(plain.Auth{User: must("AUDIT_KAFKA_USER"), Pass: must("KAFKA_SASL_PASSWORD")}.AsMechanism()),
		kgo.ConsumeTopics(bus.OTLPMetricsTopic, bus.OTLPTracesTopic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		return err
	}
	defer client.Close()
	expected := map[string]map[string]expectedProductRecord{
		bus.OTLPMetricsTopic: {
			a: {tenant: a, marker: markers.MetricA, value: productMetricValueA},
			b: {tenant: b, marker: markers.MetricB, value: productMetricValueB},
		},
		bus.OTLPTracesTopic: {
			a: {tenant: a, marker: markers.TraceA, span: markers.SpanA},
			b: {tenant: b, marker: markers.TraceB, span: markers.SpanB},
		},
	}
	observed := make(map[string]kafkaRecordObservation, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for len(observed) < 4 && ctx.Err() == nil {
		fetches := client.PollFetches(ctx)
		if errs := fetches.Errors(); len(errs) > 0 {
			return fmt.Errorf("kafka observation: %s: %w", errs[0].Topic, errs[0].Err)
		}
		var captureErr error
		fetches.EachRecord(func(record *kgo.Record) {
			if captureErr != nil {
				return
			}
			tenant := bus.TenantFromKey(record.Key)
			want, ok := expected[record.Topic][tenant]
			if !ok {
				return
			}
			signal := "traces"
			if record.Topic == bus.OTLPMetricsTopic {
				signal = "metrics"
			}
			key := signal + "\x00" + tenant
			if _, duplicate := observed[key]; duplicate {
				return
			}
			var observation kafkaRecordObservation
			observation, captureErr = captureKafkaRecord(must("AUDIT_ARTIFACT_DIR"), record, want, signal)
			if captureErr == nil {
				observed[key] = observation
			}
		})
		if captureErr != nil {
			return captureErr
		}
	}
	if len(observed) != 4 {
		return fmt.Errorf("observed %d/4 exact product Kafka records before timeout", len(observed))
	}
	out := struct {
		Metrics []kafkaRecordObservation `json:"metrics"`
		Traces  []kafkaRecordObservation `json:"traces"`
	}{
		Metrics: []kafkaRecordObservation{observed["metrics\x00"+a], observed["metrics\x00"+b]},
		Traces:  []kafkaRecordObservation{observed["traces\x00"+a], observed["traces\x00"+b]},
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func boundedHTTPResponse(client *http.Client, request *http.Request) ([]byte, int, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProductResponseBytes+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if len(body) > maxProductResponseBytes {
		return nil, response.StatusCode, errors.New("store response exceeds audit bound")
	}
	if response.StatusCode/100 != 2 {
		return nil, response.StatusCode, fmt.Errorf("store status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, response.StatusCode, nil
}

func validateDirectPrometheus(body []byte, tenant, marker string, value int64) (time.Time, error) {
	var response struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Value  []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || response.Status != "success" || response.Data.ResultType != "vector" || len(response.Data.Result) != 1 {
		return time.Time{}, errors.New("direct Prometheus response is not one successful vector")
	}
	result := response.Data.Result[0]
	if len(result.Metric) != 4 || result.Metric["__name__"] != productStoredMetricName || result.Metric["tenant_id"] != tenant ||
		result.Metric["marker"] != marker || result.Metric["service_name"] != productService(marker) || len(result.Value) != 2 {
		return time.Time{}, errors.New("direct Prometheus response does not contain the exact tenant marker labels")
	}
	var rawValue string
	if json.Unmarshal(result.Value[1], &rawValue) != nil {
		return time.Time{}, errors.New("direct Prometheus response value is malformed")
	}
	parsed, err := strconv.ParseFloat(rawValue, 64)
	if err != nil || parsed != float64(value) {
		return time.Time{}, errors.New("direct Prometheus response value does not match")
	}
	var sampleSeconds float64
	if json.Unmarshal(result.Value[0], &sampleSeconds) != nil || sampleSeconds <= 0 || math.IsNaN(sampleSeconds) || math.IsInf(sampleSeconds, 0) {
		return time.Time{}, errors.New("direct Prometheus response timestamp is malformed")
	}
	seconds, fraction := math.Modf(sampleSeconds)
	return time.Unix(int64(seconds), int64(math.Round(fraction*float64(time.Second)))).UTC(), nil
}

func queryDirectPrometheus(client *http.Client, base, tenant, marker string, value int64) ([]byte, time.Time, error) {
	selector := productStoredMetricName + `{marker="` + marker + `",tenant_id="` + tenant + `"}`
	query := url.Values{}
	query.Set("query", selector)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		strings.TrimRight(base, "/")+"/api/v1/query?"+query.Encode(), nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	body, _, err := boundedHTTPResponse(client, request)
	if err != nil {
		return nil, time.Time{}, err
	}
	observedAt, err := validateDirectPrometheus(body, tenant, marker, value)
	if err != nil {
		return nil, time.Time{}, err
	}
	return body, observedAt, nil
}

const directTraceSQL = "SELECT tenant_id, trace_id, span_id, name, service, toUnixTimestamp64Nano(start) AS start_time_unix_nano FROM default.probectl_otel_spans FINAL WHERE trace_id = {trace:String} FORMAT JSONEachRow"

const productIsolationSQL = "SELECT tenant_id, trace_id, span_id, name, service, toUnixTimestamp64Nano(start) AS start_time_unix_nano FROM default.probectl_otel_spans FINAL WHERE trace_id IN ({trace_a:String}, {trace_b:String}) ORDER BY tenant_id, trace_id FORMAT JSONEachRow"

const clickHouseJSONIntegerSetting = "output_format_json_quote_64bit_integers"

type productClickHouseRow struct {
	TenantID          string `json:"tenant_id"`
	TraceID           string `json:"trace_id"`
	SpanID            string `json:"span_id"`
	Name              string `json:"name"`
	Service           string `json:"service"`
	StartTimeUnixNano uint64 `json:"start_time_unix_nano"`
}

func queryClickHouseRaw(client *http.Client, base, sql, tenantSetting string, parameters url.Values) ([]byte, error) {
	query := url.Values{}
	for name, values := range parameters {
		for _, value := range values {
			query.Add(name, value)
		}
	}
	if tenantSetting != "" {
		query.Set("SQL_probectl_tenant", tenantSetting)
	}
	// ClickHouse quotes Int64 values in JSON formats by default. The signed
	// evidence contract intentionally models Unix nanoseconds as JSON numbers,
	// so pin the authenticated HTTP query's serialization instead of depending
	// on a mutable server/user default. The exact helper bytes are source-bound
	// by the receipt, and the raw response bytes are hashed into the manifest.
	query.Set(clickHouseJSONIntegerSetting, "0")
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		strings.TrimRight(base, "/")+"/?"+query.Encode(), strings.NewReader(sql))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	body, _, err := boundedHTTPResponse(client, request)
	return body, err
}

func queryDirectClickHouse(client *http.Client, base, tenant, marker, spanID string) ([]byte, error) {
	params := url.Values{}
	params.Set("param_trace", marker)
	body, err := queryClickHouseRaw(client, base, directTraceSQL, tenant, params)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(bytes.TrimSpace(body), []byte("\n"))
	if len(lines) != 1 || len(lines[0]) == 0 {
		return nil, errors.New("direct ClickHouse query did not return exactly one span row")
	}
	var span productClickHouseRow
	decoder := json.NewDecoder(bytes.NewReader(lines[0]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&span); err != nil || span.TenantID != tenant || span.TraceID != marker || span.SpanID != spanID ||
		span.Service != productService(marker) || span.Name != productSpanName || span.StartTimeUnixNano == 0 {
		return nil, errors.New("direct ClickHouse query did not return the exact tenant trace marker")
	}
	return body, nil
}

type productClickHouseIsolation struct {
	Database              string    `json:"database"`
	Table                 string    `json:"table"`
	ReaderUser            string    `json:"reader_user"`
	TenantSetting         string    `json:"tenant_setting"`
	SQL                   string    `json:"sql"`
	TenantA               string    `json:"tenant_a"`
	TenantB               string    `json:"tenant_b"`
	TenantAResponse       string    `json:"tenant_a_response"`
	TenantBResponse       string    `json:"tenant_b_response"`
	UnsetResponse         string    `json:"unset_response"`
	TenantAObservedAt     time.Time `json:"tenant_a_observed_at"`
	TenantBObservedAt     time.Time `json:"tenant_b_observed_at"`
	UnsetObservedAt       time.Time `json:"unset_observed_at"`
	SeededTenantARows     int64     `json:"seeded_tenant_a_rows"`
	SeededTenantBRows     int64     `json:"seeded_tenant_b_rows"`
	TenantAOwnVisibleRows int64     `json:"tenant_a_own_visible_rows"`
	TenantBOwnVisibleRows int64     `json:"tenant_b_own_visible_rows"`
	TenantAToBVisibleRows int64     `json:"tenant_a_to_b_visible_rows"`
	TenantBToAVisibleRows int64     `json:"tenant_b_to_a_visible_rows"`
	UnsetVisibleRows      int64     `json:"unset_visible_rows"`
	ReaderPolicyObserved  bool      `json:"reader_policy_observed"`
}

func productIsolationRows(client *http.Client, base, setting, traceA, traceB string) ([]byte, []productClickHouseRow, error) {
	parameters := url.Values{}
	parameters.Set("param_trace_a", traceA)
	parameters.Set("param_trace_b", traceB)
	body, err := queryClickHouseRaw(client, base, productIsolationSQL, setting, parameters)
	if err != nil {
		return nil, nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return body, []productClickHouseRow{}, nil
	}
	lines := bytes.Split(bytes.TrimSpace(body), []byte("\n"))
	rows := make([]productClickHouseRow, 0, len(lines))
	for _, line := range lines {
		var row productClickHouseRow
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&row); err != nil || row.TenantID == "" || !markerRE.MatchString(row.TraceID) || row.StartTimeUnixNano == 0 {
			return nil, nil, errors.New("product isolation query returned a malformed row")
		}
		rows = append(rows, row)
	}
	return body, rows, nil
}

func countTenant(rows []productClickHouseRow, tenant string) int64 {
	var count int64
	for _, row := range rows {
		if row.TenantID == tenant {
			count++
		}
	}
	return count
}

func observeProductClickHouseIsolation(client *http.Client, base, root, a, b string, markers productMarkers) (productClickHouseIsolation, error) {
	bodyA, rowsA, err := productIsolationRows(client, base, a, markers.TraceA, markers.TraceB)
	if err != nil {
		return productClickHouseIsolation{}, fmt.Errorf("tenant A setting-scoped product read: %w", err)
	}
	observedA := time.Now().UTC()
	bodyB, rowsB, err := productIsolationRows(client, base, b, markers.TraceA, markers.TraceB)
	if err != nil {
		return productClickHouseIsolation{}, fmt.Errorf("tenant B setting-scoped product read: %w", err)
	}
	observedB := time.Now().UTC()
	bodyUnset, rowsUnset, err := productIsolationRows(client, base, "", markers.TraceA, markers.TraceB)
	if err != nil {
		return productClickHouseIsolation{}, fmt.Errorf("unset setting-scoped product read: %w", err)
	}
	observedUnset := time.Now().UTC()
	if len(rowsA) != 1 || rowsA[0].TenantID != a || rowsA[0].TraceID != markers.TraceA || rowsA[0].SpanID != markers.SpanA ||
		rowsA[0].Name != productSpanName || rowsA[0].Service != productService(markers.TraceA) ||
		len(rowsB) != 1 || rowsB[0].TenantID != b || rowsB[0].TraceID != markers.TraceB || rowsB[0].SpanID != markers.SpanB ||
		rowsB[0].Name != productSpanName || rowsB[0].Service != productService(markers.TraceB) || len(rowsUnset) != 0 {
		return productClickHouseIsolation{}, errors.New("product isolation query did not return exact A-only, B-only, unset-zero marker rows")
	}
	aPath := "product/clickhouse-isolation-tenant-a.jsonl"
	bPath := "product/clickhouse-isolation-tenant-b.jsonl"
	unsetPath := "product/clickhouse-isolation-unset.jsonl"
	for path, body := range map[string][]byte{aPath: bodyA, bPath: bodyB, unsetPath: bodyUnset} {
		if err := writeProductArtifact(root, path, body); err != nil {
			return productClickHouseIsolation{}, err
		}
	}
	out := productClickHouseIsolation{
		Database:              "default",
		Table:                 "probectl_otel_spans",
		ReaderUser:            "probectl",
		TenantSetting:         "SQL_probectl_tenant",
		SQL:                   productIsolationSQL,
		TenantA:               a,
		TenantB:               b,
		TenantAResponse:       aPath,
		TenantBResponse:       bPath,
		UnsetResponse:         unsetPath,
		TenantAObservedAt:     observedA,
		TenantBObservedAt:     observedB,
		UnsetObservedAt:       observedUnset,
		SeededTenantARows:     countTenant(rowsA, a),
		SeededTenantBRows:     countTenant(rowsB, b),
		TenantAOwnVisibleRows: countTenant(rowsA, a),
		TenantBOwnVisibleRows: countTenant(rowsB, b),
		TenantAToBVisibleRows: countTenant(rowsA, b),
		TenantBToAVisibleRows: countTenant(rowsB, a),
		UnsetVisibleRows:      int64(len(rowsUnset)),
	}
	out.ReaderPolicyObserved = out.SeededTenantARows == 1 && out.SeededTenantBRows == 1 &&
		out.TenantAToBVisibleRows == 0 && out.TenantBToAVisibleRows == 0 && out.UnsetVisibleRows == 0 &&
		int64(len(rowsA)) == out.TenantAOwnVisibleRows && int64(len(rowsB)) == out.TenantBOwnVisibleRows
	if !out.ReaderPolicyObserved {
		return productClickHouseIsolation{}, fmt.Errorf("actual product table reader policy failed closed-directional proof: %+v", out)
	}
	return out, nil
}

type productStoreTenant struct {
	Tenant               string    `json:"tenant"`
	PrometheusResponse   string    `json:"prometheus_response"`
	ClickHouseResponse   string    `json:"clickhouse_response"`
	PrometheusObservedAt time.Time `json:"prometheus_observed_at"`
	ClickHouseObservedAt time.Time `json:"clickhouse_observed_at"`
	PrometheusHTTPStatus int       `json:"prometheus_http_status"`
	ClickHouseHTTPStatus int       `json:"clickhouse_http_status"`
}

func productStores(a, b string) error {
	markers, err := loadProductMarkers()
	if err != nil {
		return err
	}
	promBase := must("AUDIT_PROMETHEUS_URL")
	clickHouseBase := must("AUDIT_CLICKHOUSE_URL")
	promClient, err := probcrypto.BasicAuthHTTPClient(20*time.Second, promBase, must("AUDIT_PROMETHEUS_CREDENTIAL_FILE"))
	if err != nil {
		return err
	}
	clickHouseClient, err := probcrypto.BasicAuthHTTPClient(20*time.Second, clickHouseBase, must("AUDIT_CLICKHOUSE_CREDENTIAL_FILE"))
	if err != nil {
		return err
	}
	type input struct {
		tenant, metric, trace, span string
		value                       int64
	}
	inputs := []input{
		{tenant: a, metric: markers.MetricA, trace: markers.TraceA, span: markers.SpanA, value: productMetricValueA},
		{tenant: b, metric: markers.MetricB, trace: markers.TraceB, span: markers.SpanB, value: productMetricValueB},
	}
	root := must("AUDIT_ARTIFACT_DIR")
	out := struct {
		Tenants    []productStoreTenant       `json:"tenants"`
		ClickHouse productClickHouseIsolation `json:"clickhouse_isolation"`
	}{Tenants: make([]productStoreTenant, 0, 2)}
	for _, in := range inputs {
		prometheusBody, prometheusObservedAt, err := queryDirectPrometheus(promClient, promBase, in.tenant, in.metric, in.value)
		if err != nil {
			return fmt.Errorf("tenant %s direct Prometheus query: %w", in.tenant, err)
		}
		clickHouseBody, err := queryDirectClickHouse(clickHouseClient, clickHouseBase, in.tenant, in.trace, in.span)
		if err != nil {
			return fmt.Errorf("tenant %s direct ClickHouse query: %w", in.tenant, err)
		}
		clickHouseObservedAt := time.Now().UTC()
		prefix := filepath.ToSlash(filepath.Join("product", in.tenant))
		prometheusPath := prefix + "/metrics-prometheus-direct.json"
		clickHousePath := prefix + "/traces-clickhouse-direct.json"
		if err := writeProductArtifact(root, prometheusPath, prometheusBody); err != nil {
			return err
		}
		if err := writeProductArtifact(root, clickHousePath, clickHouseBody); err != nil {
			return err
		}
		out.Tenants = append(out.Tenants, productStoreTenant{Tenant: in.tenant,
			PrometheusResponse: prometheusPath, ClickHouseResponse: clickHousePath,
			PrometheusObservedAt: prometheusObservedAt, ClickHouseObservedAt: clickHouseObservedAt,
			PrometheusHTTPStatus: http.StatusOK, ClickHouseHTTPStatus: http.StatusOK})
	}
	out.ClickHouse, err = observeProductClickHouseIsolation(clickHouseClient, clickHouseBase, root, a, b, markers)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func probePrometheus(a, b string) (result, error) {
	endpoint := must("AUDIT_PROMETHEUS_URL")
	client, err := probcrypto.BasicAuthHTTPClient(20*time.Second, endpoint, must("AUDIT_PROMETHEUS_CREDENTIAL_FILE"))
	if err != nil {
		return result{}, err
	}
	writer := tsdb.NewPrometheusWithClient(endpoint, client)
	defer writer.Close()
	now := time.Now().UnixMilli()
	if err := writer.Write(context.Background(), []tsdb.Series{
		{Metric: "probectl_completeness_probe", Labels: map[string]string{tsdb.TenantLabel: a}, Value: 1, TimeMillis: now},
		{Metric: "probectl_completeness_probe", Labels: map[string]string{tsdb.TenantLabel: b}, Value: 1, TimeMillis: now},
	}); err != nil {
		return result{}, err
	}

	var rows []tsdb.LabeledSample
	err = nil
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		// Query the whole freshly written metric. Tenant-filtered queries cannot
		// discover an unlabeled or unexpectedly labeled series, so they are not
		// sufficient evidence for label integrity.
		rows, err = writer.InstantVector(context.Background(), `probectl_completeness_probe`)
		if err == nil && len(rows) == 2 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return result{}, err
	}
	var ownA, ownB, missing, mismatched int
	for _, row := range rows {
		tenant, ok := row.Labels[tsdb.TenantLabel]
		if !ok || strings.TrimSpace(tenant) == "" {
			missing++
			continue
		}
		switch tenant {
		case a:
			ownA++
		case b:
			ownB++
		default:
			mismatched++
		}
	}
	passed := len(rows) == 2 && ownA == 1 && ownB == 1 && missing == 0 && mismatched == 0
	if !passed {
		return result{}, fmt.Errorf("prometheus unfiltered tenant-label query failed: total=%d a=%d b=%d missing=%d mismatched=%d", len(rows), ownA, ownB, missing, mismatched)
	}
	return result{Service: "prometheus", Passed: true, TenantA: a, TenantB: b,
		SeededA: 1, SeededB: 1, OwnVisibleA: int64(ownA), OwnVisibleB: int64(ownB),
		MissingTenantLabels: int64Ptr(int64(missing)), MismatchedTenantLabels: int64Ptr(int64(mismatched)),
		TotalObservedSeries: int64Ptr(int64(len(rows))), ExpectedLabeledSeries: int64Ptr(2),
		Detail: "authenticated HTTPS remote-write plus an unfiltered PromQL query observed exactly the two freshly written series, one for each mandatory tenant label and none missing or foreign"}, nil
}

func int64Ptr(value int64) *int64 { return &value }
