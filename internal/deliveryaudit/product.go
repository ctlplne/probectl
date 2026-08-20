// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package deliveryaudit

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/promapi"
	"github.com/ctlplne/probectl/internal/store/otelstore"
)

const (
	productOTLPAuthMode           = "tenant_otlp_bearer"
	productMetricName             = "completeness_product_marker"
	productStoredMetric           = "probectl_otlp_completeness_product_marker"
	productSpanName               = "completeness-product-marker"
	productMetricsTopic           = "probectl.otlp.metrics"
	productTracesTopic            = "probectl.otlp.traces"
	productMetricsGroup           = "otlp-metrics"
	productTracesGroup            = "otlp-traces"
	productMetricsPath            = "/v1/metrics"
	productTracesIngestPath       = "/v1/traces"
	productClickHouseSQL          = "SELECT tenant_id, trace_id, span_id, name, service, toUnixTimestamp64Nano(start) AS start_time_unix_nano FROM default.probectl_otel_spans FINAL WHERE trace_id = {trace:String} FORMAT JSONEachRow"
	productClickHouseIsolationSQL = "SELECT tenant_id, trace_id, span_id, name, service, toUnixTimestamp64Nano(start) AS start_time_unix_nano FROM default.probectl_otel_spans FINAL WHERE trace_id IN ({trace_a:String}, {trace_b:String}) ORDER BY tenant_id, trace_id FORMAT JSONEachRow"
	productTimeTolerance          = time.Millisecond
)

var (
	productCorrelationRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	productSpanIDRe      = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

type productLintContext struct {
	receipt        Receipt
	loader         *semanticArtifactLoader
	kinds          map[string]ArtifactKind
	transcript     CLITranscriptArtifact
	used           map[string]string
	offsets        map[string]bool
	product        ProductPipelineArtifact
	earliestEvent  time.Time
	latestReadback time.Time
	out            []Diagnostic
}

func lintProductPipelineArtifact(receipt Receipt, loader *semanticArtifactLoader) []Diagnostic {
	if receipt.HarnessScope.Mode != HarnessModeTenantPlane {
		return nil
	}
	if indexArtifactKinds(receipt.Artifacts)[receipt.Stores.ProductPipelineArtifact] != ArtifactProductPipeline {
		return nil
	}
	var artifact ProductPipelineArtifact
	if diagnostic := decodeSemanticJSON(loader, receipt.Stores.ProductPipelineArtifact, ProductPipelineArtifactSchema, &artifact); diagnostic != nil {
		return []Diagnostic{*diagnostic}
	}
	var transcript CLITranscriptArtifact
	if diagnostic := decodeSemanticJSON(loader, receipt.CLI.Transcript, CLITranscriptArtifactSchema, &transcript); diagnostic != nil {
		return []Diagnostic{{Code: "product-pipeline-invalid", Field: "stores.product_pipeline_artifact", Problem: "product pipeline cannot be cross-bound because the release CLI transcript is invalid"}}
	}
	ctx := &productLintContext{
		receipt: receipt, loader: loader, kinds: indexArtifactKinds(receipt.Artifacts), transcript: transcript,
		used: make(map[string]string), offsets: make(map[string]bool), product: artifact,
	}
	if !validProductReceiptBinding(receipt, artifact) {
		ctx.problem("product-pipeline-invalid", "product_pipeline", "product evidence must bind the exact receipt source/build identity and a non-empty window contained by the signed receipt")
	}
	if len(artifact.Tenants) != 2 || strings.TrimSpace(artifact.Tenants[0].Tenant) == "" ||
		strings.TrimSpace(artifact.Tenants[1].Tenant) == "" || artifact.Tenants[0].Tenant == artifact.Tenants[1].Tenant {
		ctx.problem("product-pipeline-invalid", "product_pipeline.tenants", "product pipeline must contain exactly two distinct non-empty tenants")
		return ctx.out
	}
	if !canonicalStoreTenantPair(receipt.Stores, artifact.Tenants[0].Tenant, artifact.Tenants[1].Tenant) {
		ctx.problem("product-pipeline-cross-tenant", "product_pipeline.tenants", "the same canonical unordered tenant pair must be used by the product pipeline and every Postgres/ClickHouse/Kafka/Prometheus probe")
	}

	markers := make(map[string]bool)
	values := make(map[float64]bool)
	for i := range artifact.Tenants {
		tenant := artifact.Tenants[i]
		ctx.lintMetricFlow(i, tenant.Tenant, tenant.Metrics, markers, values)
		ctx.lintTraceFlow(i, tenant.Tenant, tenant.Traces, markers)
	}
	for i := range artifact.Tenants {
		other := artifact.Tenants[1-i]
		ctx.lintForeignMetricQuery(i, artifact.Tenants[i].Tenant, other.Metrics, artifact.Tenants[i].ForeignQueries.Metrics)
		ctx.lintForeignTraceQuery(i, artifact.Tenants[i].Tenant, other.Traces, artifact.Tenants[i].ForeignQueries.Traces)
	}
	ctx.lintKafkaSummary()
	ctx.lintClickHouseIsolation(artifact.ClickHouseIsolation, artifact.Tenants)
	ctx.lintIntegrity(artifact.Integrity)
	ctx.rejectOrphanProductArtifacts(receipt.Stores.ProductPipelineArtifact)
	return ctx.out
}

func (c *productLintContext) lintKafkaSummary() {
	probe := c.receipt.Stores.Kafka
	if !truePointer(probe.ProductMessagesObserved) || !int64PointerEquals(probe.ObservedProductMessages, 4) {
		c.problem("product-pipeline-invalid", "stores.kafka", "Kafka store summary must cross-bind the four exact typed product records proved by the two-tenant metrics/traces manifest")
	}
}

func validProductReceiptBinding(receipt Receipt, artifact ProductPipelineArtifact) bool {
	return artifact.ReceiptID == receipt.ReceiptID && artifact.SourceGitSHA == receipt.Source.GitSHA &&
		artifact.SourceTreeSHA == receipt.Source.TreeSHA && artifact.ControlImageID == receipt.Build.ControlImageID &&
		artifact.CLISHA256 == receipt.Build.CLISHA256 && !artifact.StartedAt.IsZero() && !artifact.CompletedAt.IsZero() &&
		artifact.CompletedAt.After(artifact.StartedAt) && !artifact.StartedAt.Before(receipt.StartedAt) &&
		!artifact.CompletedAt.After(receipt.CompletedAt)
}

func (c *productLintContext) eventTime(field string, raw uint64) time.Time {
	if raw == 0 || raw > uint64(math.MaxInt64) {
		c.problem("product-pipeline-invalid", field, "product event timestamp must be a positive signed Unix nanosecond inside the product window")
		return time.Time{}
	}
	observed := time.Unix(0, int64(raw)).UTC()
	if !c.withinWindow(observed) {
		c.problem("product-pipeline-invalid", field, "product event timestamp must be inside the source-bound product window")
	}
	if c.earliestEvent.IsZero() || observed.Before(c.earliestEvent) {
		c.earliestEvent = observed
	}
	return observed
}

func (c *productLintContext) observationTime(field string, observed, event time.Time) bool {
	valid := c.withinWindow(observed) && (event.IsZero() || !observed.Add(productTimeTolerance).Before(event))
	if !valid {
		c.problem("product-pipeline-invalid", field, "observation timestamp must be inside the product window and no earlier than its emitted event")
	}
	if !observed.IsZero() && (c.latestReadback.IsZero() || observed.After(c.latestReadback)) {
		c.latestReadback = observed
	}
	return valid
}

func (c *productLintContext) withinWindow(observed time.Time) bool {
	return !observed.IsZero() && !c.product.StartedAt.IsZero() && !c.product.CompletedAt.IsZero() &&
		!observed.Add(productTimeTolerance).Before(c.product.StartedAt) &&
		!observed.Add(-productTimeTolerance).After(c.product.CompletedAt)
}

func (c *productLintContext) problem(code, field, problem string) {
	c.out = append(c.out, Diagnostic{Code: code, Field: field, Problem: problem})
}

func (c *productLintContext) ref(field string, ref ProductArtifactRef, want ArtifactKind) ([]byte, bool) {
	if strings.TrimSpace(ref.Path) == "" || !digestRe.MatchString(ref.SHA256) || c.kinds[ref.Path] != want {
		c.problem("product-pipeline-ref-invalid", field, fmt.Sprintf("product reference must name one declared %s artifact and exact SHA-256", want))
		return nil, false
	}
	if previous := c.used[ref.Path]; previous != "" {
		c.problem("product-pipeline-ref-invalid", field, "product artifacts must be one-use; path is already referenced by "+previous)
		return nil, false
	}
	c.used[ref.Path] = field
	data, err := c.loader.read(ref.Path)
	if err != nil || digestBytes(data) != ref.SHA256 {
		c.problem("product-pipeline-ref-invalid", field, "product reference digest does not match the exact verified artifact bytes")
		return nil, false
	}
	return data, true
}

func (c *productLintContext) lintMetricFlow(index int, tenant string, flow ProductMetricPipelineFlow, markers map[string]bool, values map[float64]bool) {
	field := fmt.Sprintf("product_pipeline.tenants.%d.metrics", index)
	event := c.eventTime(field+".time_unix_nano", flow.TimeUnixNano)
	if !productCorrelationRe.MatchString(flow.CorrelationID) || markers[flow.CorrelationID] ||
		flow.ServiceName != "completeness-"+flow.CorrelationID || flow.MetricName != productMetricName ||
		flow.StoredMetricName != productStoredMetric || math.IsNaN(flow.Value) || math.IsInf(flow.Value, 0) || flow.Value == 0 || values[flow.Value] {
		c.problem("product-pipeline-invalid", field, "metric flow needs a unique 128-bit marker, exact service/metric names, and a unique finite non-zero value")
	}
	markers[flow.CorrelationID] = true
	values[flow.Value] = true

	request, response, ok := c.lintIngest(field+".ingest", tenant, flow.Ingest, productMetricsPath, event)
	var requestMessage colmetricspb.ExportMetricsServiceRequest
	var responseMessage colmetricspb.ExportMetricsServiceResponse
	if !ok || proto.Unmarshal(request, &requestMessage) != nil || proto.Unmarshal(response, &responseMessage) != nil ||
		!validProductMetricRequest(&requestMessage, tenant, flow) || !proto.Equal(&responseMessage, &colmetricspb.ExportMetricsServiceResponse{}) {
		c.problem("product-pipeline-invalid", field+".ingest", "metrics ingest must bind an uncompressed, already tenant-stamped OTLP protobuf containing exactly the signed marker/value")
	}
	payload, kafkaOK := c.lintKafka(field+".kafka", tenant, flow.ServiceName, flow.Kafka, productMetricsTopic, productMetricsGroup, event)
	var kafkaMessage colmetricspb.ExportMetricsServiceRequest
	if !kafkaOK || proto.Unmarshal(payload, &kafkaMessage) != nil || !validProductMetricRequest(&kafkaMessage, tenant, flow) ||
		!bytes.Equal(request, payload) || !proto.Equal(&requestMessage, &kafkaMessage) {
		c.problem("product-pipeline-invalid", field+".kafka", "Kafka payload must decode to the same tenant-stamped OTLP metrics message as the authenticated ingest request")
	}
	body, controlOK := c.lintControlQuery(field+".control_query", tenant, flow.ControlQuery, event)
	if !controlOK || !validProductMetricQuery(flow.ControlQuery.Path, flow) ||
		!validPrometheusMarkerResponse(body, tenant, flow, flow.ControlQuery.ObservedAt, false) {
		c.problem("product-pipeline-invalid", field+".control_query", "tenant-authenticated release CLI/API query must return exactly the signed Prometheus marker/value")
	}
	directProof := flow.PrometheusDirect
	direct, directOK := c.ref(field+".prometheus_direct.response", directProof.Response, ArtifactStoreObservation)
	timeOK := c.observationTime(field+".prometheus_direct.observed_at", directProof.ObservedAt, event)
	if !directOK || !timeOK || directProof.User != "audit" || !validDirectPrometheusQuery(directProof, tenant, flow) ||
		!validPrometheusMarkerResponse(direct, tenant, flow, directProof.ObservedAt, false) {
		c.problem("product-pipeline-invalid", field+".prometheus_direct", "direct Prometheus proof must bind the real authenticated service URL, exact tenant/marker selector, and matching response")
	}
}

func (c *productLintContext) lintTraceFlow(index int, tenant string, flow ProductTracePipelineFlow, markers map[string]bool) {
	field := fmt.Sprintf("product_pipeline.tenants.%d.traces", index)
	start := c.eventTime(field+".start_time_unix_nano", flow.StartTimeUnixNano)
	end := c.eventTime(field+".end_time_unix_nano", flow.EndTimeUnixNano)
	if !productCorrelationRe.MatchString(flow.CorrelationID) || markers[flow.CorrelationID] ||
		flow.TraceID != flow.CorrelationID || !productSpanIDRe.MatchString(flow.SpanID) ||
		flow.ServiceName != "completeness-"+flow.CorrelationID || flow.SpanName != productSpanName ||
		start.IsZero() || end.IsZero() || !end.After(start) {
		c.problem("product-pipeline-invalid", field, "trace flow needs unique exact correlation/trace/span IDs and canonical marker service/span names")
	}
	markers[flow.CorrelationID] = true
	request, response, ok := c.lintIngest(field+".ingest", tenant, flow.Ingest, productTracesIngestPath, end)
	var requestMessage coltracepb.ExportTraceServiceRequest
	var responseMessage coltracepb.ExportTraceServiceResponse
	if !ok || proto.Unmarshal(request, &requestMessage) != nil || proto.Unmarshal(response, &responseMessage) != nil ||
		!validProductTraceRequest(&requestMessage, tenant, flow) || !proto.Equal(&responseMessage, &coltracepb.ExportTraceServiceResponse{}) {
		c.problem("product-pipeline-invalid", field+".ingest", "trace ingest must bind an uncompressed, already tenant-stamped OTLP protobuf containing exactly the signed trace/span marker")
	}
	payload, kafkaOK := c.lintKafka(field+".kafka", tenant, flow.ServiceName, flow.Kafka, productTracesTopic, productTracesGroup, end)
	var kafkaMessage coltracepb.ExportTraceServiceRequest
	if !kafkaOK || proto.Unmarshal(payload, &kafkaMessage) != nil || !validProductTraceRequest(&kafkaMessage, tenant, flow) ||
		!bytes.Equal(request, payload) || !proto.Equal(&requestMessage, &kafkaMessage) {
		c.problem("product-pipeline-invalid", field+".kafka", "Kafka payload must decode to the same tenant-stamped OTLP trace message as the authenticated ingest request")
	}
	body, controlOK := c.lintControlQuery(field+".control_query", tenant, flow.ControlQuery, end)
	if !controlOK || !validProductTraceQuery(flow.ControlQuery.Path, flow.TraceID) || !validTraceMarkerResponse(body, tenant, flow, false) {
		c.problem("product-pipeline-invalid", field+".control_query", "tenant-authenticated release CLI/API query must return exactly the signed ClickHouse-backed trace")
	}
	directProof := flow.ClickHouseDirect
	direct, directOK := c.ref(field+".clickhouse_direct.response", directProof.Response, ArtifactStoreObservation)
	timeOK := c.observationTime(field+".clickhouse_direct.observed_at", directProof.ObservedAt, end)
	if !directOK || !timeOK || directProof.User != "probectl" || directProof.Database != "default" ||
		directProof.Table != "probectl_otel_spans" || directProof.TenantSetting != "SQL_probectl_tenant" ||
		directProof.TenantSettingValue != tenant || directProof.SQL != productClickHouseSQL ||
		len(directProof.Parameters) != 1 || directProof.Parameters["trace"] != flow.TraceID ||
		!validClickHouseMarkerResponse(direct, tenant, flow) {
		c.problem("product-pipeline-invalid", field+".clickhouse_direct", "direct ClickHouse proof must use the release reader, actual product table, exact tenant setting, tenant-predicate-free canonical query, and matching trace row")
	}
}

func (c *productLintContext) lintIngest(field, tenant string, exchange ProductIngestExchange, wantPath string, event time.Time) ([]byte, []byte, bool) {
	u, err := url.Parse(exchange.URL)
	valid := err == nil && u.Scheme == "https" && u.Host == "control:4318" && u.User == nil && u.Fragment == "" &&
		u.Opaque == "" && u.Path == wantPath && u.RawQuery == "" &&
		exchange.AuthMode == productOTLPAuthMode && exchange.Method == "POST" && exchange.Status == 200
	timeOK := c.observationTime(field+".observed_at", exchange.ObservedAt, event)
	if !valid || !timeOK {
		c.problem("product-pipeline-invalid", field, "OTLP ingest must be a successful authenticated HTTPS POST to the exact signal endpoint")
	}
	request, requestOK := c.ref(field+".request", exchange.Request, ArtifactOTLPRequest)
	response, responseOK := c.ref(field+".response", exchange.Response, ArtifactOTLPResponse)
	_ = tenant // tenant is verified from the protobuf, not an echoed exchange field.
	return request, response, valid && timeOK && requestOK && responseOK
}

func (c *productLintContext) lintKafka(field, tenant, service string, observation ProductKafkaObservation, topic, group string, event time.Time) ([]byte, bool) {
	key, keyOK := c.ref(field+".key", observation.Key, ArtifactKafkaKey)
	payload, payloadOK := c.ref(field+".payload", observation.Payload, ArtifactKafkaPayload)
	groupData, groupRefOK := c.ref(field+".group_offset", observation.GroupOffset, ArtifactKafkaGroupOffset)
	var groupProof KafkaGroupOffsetArtifact
	groupOK := groupRefOK && decodeStrict(groupData, &groupProof) == nil && groupProof.Schema == KafkaGroupOffsetArtifactSchema
	raw, rawOK := c.ref(field+".group_offset.raw_observation", groupProof.RawObservation, ArtifactKafkaGroupRaw)
	offsetKey := fmt.Sprintf("%s/%d/%d", observation.Topic, observation.Partition, observation.Offset)
	valid := observation.Topic == topic && observation.Partition >= 0 && observation.Offset >= 0 &&
		!c.offsets[offsetKey] && bytes.Equal(key, bus.TenantKey(tenant, "service.name="+service)) && groupOK && rawOK &&
		groupProof.BrokerAuthority == "kafka:9093" && groupProof.Source == "kafka_consumer_groups_describe" &&
		groupProof.SecurityProtocol == "SASL_SSL" && groupProof.TLSVerified != nil && *groupProof.TLSVerified &&
		groupProof.SASLAuthenticated != nil && *groupProof.SASLAuthenticated && groupProof.Topic == topic &&
		groupProof.Partition == observation.Partition && groupProof.ConsumerGroup == group &&
		groupProof.CommittedOffset > observation.Offset && validKafkaGroupOffsetRaw(raw, groupProof)
	valid = c.observationTime(field+".group_offset.observed_at", groupProof.ObservedAt, event) && valid
	c.offsets[offsetKey] = true
	if !valid {
		c.problem("product-pipeline-invalid", field, "Kafka proof must bind a unique tenant-bucketed record and a release consumer-group committed offset beyond that record")
	}
	return payload, valid && keyOK && payloadOK
}

func (c *productLintContext) lintControlQuery(field, tenant string, query ProductControlQuery, event time.Time) ([]byte, bool) {
	data, refOK := c.ref(field+".api_observation", query.APIObservation, ArtifactAPIObservation)
	var artifact APIObservationArtifact
	valid := refOK && decodeStrict(data, &artifact) == nil && artifact.Schema == APIObservationArtifactSchema &&
		artifact.Redacted != nil && *artifact.Redacted && artifact.AuthMode == c.receipt.HarnessScope.CLIAuthMode &&
		artifact.Tenant == tenant && artifact.TargetTenant == "" && artifact.ProviderActor == "" &&
		artifact.Command == query.Command && strings.EqualFold(artifact.Method, query.Method) && artifact.Path == query.Path &&
		artifact.Status == 200 && artifact.ErrorCode == "" && query.Method == "GET" && strings.HasPrefix(query.Command, "probectl ")
	matches := 0
	for _, observation := range c.transcript.Observations {
		if observation.ResponseArtifact == query.APIObservation.Path && observation.ResponseSHA256 == query.APIObservation.SHA256 &&
			observation.Command == query.Command && observation.Tenant == tenant && observation.Path == query.Path &&
			strings.EqualFold(observation.Method, query.Method) && validSuccessfulCLIObservation(observation, c.receipt.HarnessScope) {
			matches++
		}
	}
	valid = valid && matches == 1 && c.observationTime(field+".observed_at", query.ObservedAt, event)
	if !valid {
		c.problem("product-pipeline-invalid", field, "product readback must be one successful tenant-authenticated release CLI observation cross-bound to its strict API response")
	}
	return artifact.Body, valid
}

func (c *productLintContext) lintForeignMetricQuery(index int, tenant string, foreign ProductMetricPipelineFlow, query ProductControlQuery) {
	field := fmt.Sprintf("product_pipeline.tenants.%d.foreign_queries.metrics", index)
	event := time.Unix(0, int64(foreign.TimeUnixNano)).UTC()
	body, ok := c.lintControlQuery(field, tenant, query, event)
	if !ok || !validProductMetricQuery(query.Path, foreign) ||
		!validPrometheusMarkerResponse(body, "", foreign, query.ObservedAt, true) {
		c.problem("product-pipeline-cross-tenant", field, "tenant query for the other tenant's exact metric marker must succeed with an empty vector")
	}
}

func (c *productLintContext) lintForeignTraceQuery(index int, tenant string, foreign ProductTracePipelineFlow, query ProductControlQuery) {
	field := fmt.Sprintf("product_pipeline.tenants.%d.foreign_queries.traces", index)
	event := time.Unix(0, int64(foreign.EndTimeUnixNano)).UTC()
	body, ok := c.lintControlQuery(field, tenant, query, event)
	if !ok || !validProductTraceQuery(query.Path, foreign.TraceID) || !validTraceMarkerResponse(body, "", foreign, true) {
		c.problem("product-pipeline-cross-tenant", field, "tenant query for the other tenant's exact trace ID must succeed with an empty span set")
	}
}

func (c *productLintContext) lintClickHouseIsolation(ref ProductArtifactRef, tenants []ProductTenantPipeline) {
	field := "product_pipeline.clickhouse_isolation"
	data, refOK := c.ref(field, ref, ArtifactClickHouseIsolation)
	var proof ClickHouseIsolationArtifact
	proofOK := refOK && decodeStrict(data, &proof) == nil && proof.Schema == ClickHouseIsolationArtifactSchema
	if len(tenants) != 2 {
		proofOK = false
	}
	var tenantA, tenantB ProductTenantPipeline
	if len(tenants) == 2 {
		tenantA, tenantB = tenants[0], tenants[1]
	}
	aRaw, aOK := c.ref(field+".tenant_a_response", proof.TenantAResponse, ArtifactClickHouseIsolationRaw)
	bRaw, bOK := c.ref(field+".tenant_b_response", proof.TenantBResponse, ArtifactClickHouseIsolationRaw)
	unsetRaw, unsetOK := c.ref(field+".unset_response", proof.UnsetResponse, ArtifactClickHouseIsolationRaw)
	parametersOK := len(proof.Parameters) == 2 && proof.Parameters["trace_a"] == tenantA.Traces.TraceID &&
		proof.Parameters["trace_b"] == tenantB.Traces.TraceID
	timeA := c.observationTime(field+".tenant_a_observed_at", proof.TenantAObservedAt, unixNanoTime(tenantA.Traces.EndTimeUnixNano))
	timeB := c.observationTime(field+".tenant_b_observed_at", proof.TenantBObservedAt, unixNanoTime(tenantB.Traces.EndTimeUnixNano))
	timeUnset := c.observationTime(field+".unset_observed_at", proof.UnsetObservedAt, latestTime(
		unixNanoTime(tenantA.Traces.EndTimeUnixNano), unixNanoTime(tenantB.Traces.EndTimeUnixNano),
	))
	storeOK := clickHouseProofMatchesReceipt(c.receipt.Stores.ClickHouse, proof)
	valid := proofOK && aOK && bOK && unsetOK && proof.User == "probectl" && proof.Database == "default" &&
		proof.Table == "probectl_otel_spans" && proof.TenantSetting == "SQL_probectl_tenant" &&
		proof.SQL == productClickHouseIsolationSQL && proof.TenantA == tenantA.Tenant && proof.TenantB == tenantB.Tenant &&
		parametersOK && timeA && timeB && timeUnset && storeOK && validClickHouseMarkerResponse(aRaw, tenantA.Tenant, tenantA.Traces) &&
		validClickHouseMarkerResponse(bRaw, tenantB.Tenant, tenantB.Traces) && len(bytes.TrimSpace(unsetRaw)) == 0
	if !valid {
		c.problem("product-pipeline-cross-tenant", field, "typed release-reader proof must run the exact predicate-free two-trace query under tenant A, tenant B, and no tenant setting, exposing only each own row and no unset rows")
	}
}

func clickHouseProofMatchesReceipt(probe ClickHouseIsolationProbe, proof ClickHouseIsolationArtifact) bool {
	return probe.ProofKind == ClickHouseProofKind && truePointer(probe.ProductPathConfigured) &&
		truePointer(probe.ControlRoundTripObserved) && truePointer(probe.ReaderPolicyObserved) &&
		probe.Database == proof.Database && probe.Table == proof.Table && probe.ReaderUser == proof.User &&
		probe.TenantSetting == proof.TenantSetting && canonicalPair(probe.TenantA, probe.TenantB, proof.TenantA, proof.TenantB) &&
		int64PointerEquals(probe.SeededTenantARows, 1) && int64PointerEquals(probe.SeededTenantBRows, 1) &&
		int64PointerEquals(probe.TenantAOwnVisibleRows, 1) && int64PointerEquals(probe.TenantBOwnVisibleRows, 1) &&
		int64PointerEquals(probe.TenantAToBVisibleRows, 0) && int64PointerEquals(probe.TenantBToAVisibleRows, 0) &&
		int64PointerEquals(probe.UnsetVisibleRows, 0)
}

func truePointer(value *bool) bool {
	return value != nil && *value
}

func int64PointerEquals(value *int64, want int64) bool {
	return value != nil && *value == want
}

func canonicalPair(a, b, wantA, wantB string) bool {
	return (a == wantA && b == wantB) || (a == wantB && b == wantA)
}

func unixNanoTime(raw uint64) time.Time {
	if raw == 0 || raw > uint64(math.MaxInt64) {
		return time.Time{}
	}
	return time.Unix(0, int64(raw)).UTC()
}

func latestTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func (c *productLintContext) lintIntegrity(integrity ProductPipelineIntegrity) {
	beforeRaw, beforeOK := c.ref("product_pipeline.integrity.before", integrity.Before, ArtifactPipelineCounters)
	afterRaw, afterOK := c.ref("product_pipeline.integrity.after", integrity.After, ArtifactPipelineCounters)
	before, errBefore := parseProductCounterSnapshot(beforeRaw)
	after, errAfter := parseProductCounterSnapshot(afterRaw)
	if !beforeOK || !afterOK || errBefore != nil || errAfter != nil {
		c.problem("product-pipeline-integrity-failed", "product_pipeline.integrity", "before/after artifacts must be raw bounded control /metrics snapshots containing every OTLP integrity counter")
		return
	}
	timesOK := c.withinWindow(integrity.BeforeObservedAt) && c.withinWindow(integrity.AfterObservedAt) &&
		!integrity.AfterObservedAt.Before(integrity.BeforeObservedAt) &&
		(c.earliestEvent.IsZero() || !integrity.BeforeObservedAt.After(c.earliestEvent.Add(productTimeTolerance))) &&
		(c.latestReadback.IsZero() || !integrity.AfterObservedAt.Add(productTimeTolerance).Before(c.latestReadback))
	if !timesOK {
		c.problem("product-pipeline-integrity-failed", "product_pipeline.integrity", "counter snapshots must bracket every fresh product event and readback inside the product window")
	}
	for _, signal := range []string{"otlp_metrics", "otlp_traces"} {
		prefix := "probectl_pipeline_" + signal + "_"
		for _, name := range []string{"received_total", "stored_total"} {
			if after[prefix+name]-before[prefix+name] < 2 {
				c.problem("product-pipeline-integrity-failed", "product_pipeline.integrity", signal+" "+name+" must increase by at least the two tenant product messages")
			}
		}
		for _, name := range []string{"malformed_total", "tenant_rejected_total", "fairness_shed_total", "cardinality_dropped_total", "label_truncated_total", "unsupported_total", "dead_lettered_total", "dropped_total"} {
			if after[prefix+name] != before[prefix+name] {
				c.problem("product-pipeline-integrity-failed", "product_pipeline.integrity", signal+" "+name+" must remain unchanged during the correlated product round trip")
			}
		}
	}
}

func (c *productLintContext) rejectOrphanProductArtifacts(manifestPath string) {
	productKinds := map[ArtifactKind]bool{
		ArtifactOTLPRequest: true, ArtifactOTLPResponse: true, ArtifactKafkaKey: true,
		ArtifactKafkaPayload: true, ArtifactStoreObservation: true, ArtifactPipelineCounters: true,
		ArtifactKafkaGroupOffset: true, ArtifactKafkaGroupRaw: true,
		ArtifactClickHouseIsolation: true, ArtifactClickHouseIsolationRaw: true,
	}
	manifestCount := 0
	for _, artifact := range c.receipt.Artifacts {
		if artifact.Kind == ArtifactProductPipeline {
			manifestCount++
			if artifact.Path != manifestPath {
				c.problem("product-pipeline-ref-invalid", "artifacts", "orphan product-pipeline manifest contradicts the receipt authority path: "+artifact.Path)
			}
		}
		if productKinds[artifact.Kind] && c.used[artifact.Path] == "" {
			c.problem("product-pipeline-ref-invalid", "artifacts", "orphan product-path artifact is not referenced exactly once by "+manifestPath+": "+artifact.Path)
		}
	}
	if manifestCount != 1 {
		c.problem("product-pipeline-ref-invalid", "stores.product_pipeline_artifact", "receipt must declare exactly one product-pipeline manifest")
	}
}

func validKafkaGroupOffsetRaw(raw []byte, proof KafkaGroupOffsetArtifact) bool {
	matches := 0
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[0] != proof.ConsumerGroup || fields[1] != proof.Topic {
			continue
		}
		partition, partitionErr := strconv.ParseInt(fields[2], 10, 32)
		committed, committedErr := strconv.ParseInt(fields[3], 10, 64)
		if partitionErr == nil && committedErr == nil && int32(partition) == proof.Partition && committed == proof.CommittedOffset {
			matches++
		}
	}
	return scanner.Err() == nil && matches == 1
}

func validProductMetricRequest(req *colmetricspb.ExportMetricsServiceRequest, tenant string, flow ProductMetricPipelineFlow) bool {
	if req == nil || protoMessageHasUnknown(req) || len(req.ResourceMetrics) != 1 {
		return false
	}
	rm := req.ResourceMetrics[0]
	if rm == nil || rm.SchemaUrl != "" || rm.Resource == nil || rm.Resource.DroppedAttributesCount != 0 || len(rm.Resource.EntityRefs) != 0 ||
		!exactStringAttributes(rm.Resource.Attributes, map[string]string{otel.AttrTenantID: tenant, "service.name": flow.ServiceName}) ||
		len(rm.ScopeMetrics) != 1 || rm.ScopeMetrics[0] == nil || rm.ScopeMetrics[0].SchemaUrl != "" || rm.ScopeMetrics[0].Scope != nil ||
		len(rm.ScopeMetrics[0].Metrics) != 1 {
		return false
	}
	metric := rm.ScopeMetrics[0].Metrics[0]
	if metric == nil {
		return false
	}
	gauge, ok := metric.Data.(*metricspb.Metric_Gauge)
	if !ok || gauge.Gauge == nil || metric.Name != flow.MetricName || metric.Description != "" || metric.Unit != "" || len(metric.Metadata) != 0 ||
		len(gauge.Gauge.DataPoints) != 1 || gauge.Gauge.DataPoints[0] == nil {
		return false
	}
	point := gauge.Gauge.DataPoints[0]
	if point.StartTimeUnixNano != 0 || point.TimeUnixNano != flow.TimeUnixNano || point.Flags != 0 || len(point.Exemplars) != 0 ||
		!exactStringAttributes(point.Attributes, map[string]string{"marker": flow.CorrelationID}) {
		return false
	}
	switch value := point.Value.(type) {
	case *metricspb.NumberDataPoint_AsDouble:
		return value.AsDouble == flow.Value
	default:
		return false
	}
}

func validProductTraceRequest(req *coltracepb.ExportTraceServiceRequest, tenant string, flow ProductTracePipelineFlow) bool {
	if req == nil || protoMessageHasUnknown(req) || len(req.ResourceSpans) != 1 {
		return false
	}
	rs := req.ResourceSpans[0]
	if rs == nil || rs.SchemaUrl != "" || rs.Resource == nil || rs.Resource.DroppedAttributesCount != 0 || len(rs.Resource.EntityRefs) != 0 ||
		!exactStringAttributes(rs.Resource.Attributes, map[string]string{otel.AttrTenantID: tenant, "service.name": flow.ServiceName}) ||
		len(rs.ScopeSpans) != 1 || rs.ScopeSpans[0] == nil || rs.ScopeSpans[0].SchemaUrl != "" || rs.ScopeSpans[0].Scope != nil ||
		len(rs.ScopeSpans[0].Spans) != 1 {
		return false
	}
	span := rs.ScopeSpans[0].Spans[0]
	return span != nil && hex.EncodeToString(span.TraceId) == flow.TraceID && hex.EncodeToString(span.SpanId) == flow.SpanID &&
		len(span.ParentSpanId) == 0 && span.TraceState == "" && span.Flags == 0 && span.Name == flow.SpanName &&
		span.Kind == tracepb.Span_SPAN_KIND_SERVER && span.StartTimeUnixNano == flow.StartTimeUnixNano &&
		span.EndTimeUnixNano == flow.EndTimeUnixNano && len(span.Attributes) == 0 && span.DroppedAttributesCount == 0 &&
		len(span.Events) == 0 && span.DroppedEventsCount == 0 && len(span.Links) == 0 && span.DroppedLinksCount == 0 && span.Status == nil
}

func exactStringAttributes(attributes []*commonpb.KeyValue, expected map[string]string) bool {
	if len(attributes) != len(expected) {
		return false
	}
	seen := make(map[string]bool, len(expected))
	for _, attribute := range attributes {
		if attribute == nil || seen[attribute.Key] {
			return false
		}
		want, ok := expected[attribute.Key]
		stringValue, stringOK := attribute.GetValue().GetValue().(*commonpb.AnyValue_StringValue)
		if !ok || !stringOK || want == "" || stringValue.StringValue != want {
			return false
		}
		seen[attribute.Key] = true
	}
	return len(seen) == len(expected)
}

func protoMessageHasUnknown(message proto.Message) bool {
	if message == nil {
		return false
	}
	return protoReflectionHasUnknown(message.ProtoReflect())
}

func protoReflectionHasUnknown(message protoreflect.Message) bool {
	if !message.IsValid() {
		return false
	}
	if len(message.GetUnknown()) != 0 {
		return true
	}
	hasUnknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsList() && field.Kind() == protoreflect.MessageKind:
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if protoReflectionHasUnknown(list.Get(i).Message()) {
					hasUnknown = true
					return false
				}
			}
		case field.IsMap() && field.MapValue().Kind() == protoreflect.MessageKind:
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				hasUnknown = protoReflectionHasUnknown(item.Message())
				return !hasUnknown
			})
		case field.Kind() == protoreflect.MessageKind:
			hasUnknown = protoReflectionHasUnknown(value.Message())
		}
		return !hasUnknown
	})
	return hasUnknown
}

func canonicalStoreTenantPair(stores StoreEvidence, tenantA, tenantB string) bool {
	pair := func(a, b string) bool {
		return (a == tenantA && b == tenantB) || (a == tenantB && b == tenantA)
	}
	return pair(stores.Postgres.TenantA, stores.Postgres.TenantB) &&
		pair(stores.ClickHouse.TenantA, stores.ClickHouse.TenantB) &&
		pair(stores.Kafka.TenantA, stores.Kafka.TenantB) &&
		pair(stores.Prometheus.TenantA, stores.Prometheus.TenantB)
}

func validProductMetricQuery(rawPath string, flow ProductMetricPipelineFlow) bool {
	u, err := url.ParseRequestURI(rawPath)
	if err != nil || u.Path != "/v1/grafana/api/v1/query" || len(u.Query()) != 1 || len(u.Query()["query"]) != 1 {
		return false
	}
	selector, err := promapi.ParseSelector(u.Query().Get("query"))
	if err != nil || selector.Metric != flow.StoredMetricName || len(selector.Matchers) != 1 {
		return false
	}
	matcher := selector.Matchers[0]
	return matcher.Name == "marker" && matcher.Op == "=" && matcher.Value == flow.CorrelationID
}

func validDirectPrometheusQuery(query ProductPrometheusDirectQuery, tenant string, flow ProductMetricPipelineFlow) bool {
	u, err := url.Parse(query.URL)
	if err != nil || u.Scheme != "https" || u.Host != "prometheus:9090" || u.User != nil || u.Fragment != "" ||
		u.Path != "/api/v1/query" || len(u.Query()) != 1 || len(u.Query()["query"]) != 1 || u.Query().Get("query") != query.Query {
		return false
	}
	selector, err := promapi.ParseSelector(query.Query)
	if err != nil || selector.Metric != flow.StoredMetricName || len(selector.Matchers) != 2 {
		return false
	}
	marker, tenantMatcher := selector.Matchers[0], selector.Matchers[1]
	return marker.Name == "marker" && marker.Op == "=" && marker.Value == flow.CorrelationID &&
		tenantMatcher.Name == "tenant_id" && tenantMatcher.Op == "=" && tenantMatcher.Value == tenant
}

type productPrometheusResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  []json.RawMessage `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

func validPrometheusMarkerResponse(raw []byte, tenant string, flow ProductMetricPipelineFlow, observedAt time.Time, wantEmpty bool) bool {
	var response productPrometheusResponse
	if decodeStrict(raw, &response) != nil || response.Status != "success" || response.Data.ResultType != "vector" {
		return false
	}
	if wantEmpty {
		return len(response.Data.Result) == 0
	}
	if len(response.Data.Result) != 1 || len(response.Data.Result[0].Value) != 2 {
		return false
	}
	labels := response.Data.Result[0].Metric
	if len(labels) != 4 || labels["__name__"] != flow.StoredMetricName || labels["tenant_id"] != tenant ||
		labels["marker"] != flow.CorrelationID || labels["service_name"] != flow.ServiceName {
		return false
	}
	var value string
	if json.Unmarshal(response.Data.Result[0].Value[1], &value) != nil {
		return false
	}
	var sampleSeconds float64
	if json.Unmarshal(response.Data.Result[0].Value[0], &sampleSeconds) != nil || observedAt.IsZero() || math.IsNaN(sampleSeconds) ||
		math.IsInf(sampleSeconds, 0) || math.Abs(sampleSeconds*float64(time.Second)-float64(observedAt.UnixNano())) > float64(productTimeTolerance) {
		return false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	return err == nil && parsed == flow.Value
}

func validProductTraceQuery(rawPath, traceID string) bool {
	u, err := url.ParseRequestURI(rawPath)
	return err == nil && u.Path == "/v1/otlp/traces" && len(u.Query()) == 1 && len(u.Query()["trace_id"]) == 1 && u.Query().Get("trace_id") == traceID
}

func validTraceMarkerResponse(raw []byte, tenant string, flow ProductTracePipelineFlow, wantEmpty bool) bool {
	var response struct {
		Spans []otelstore.Span `json:"spans"`
	}
	if decodeStrict(raw, &response) != nil {
		return false
	}
	if wantEmpty {
		return len(response.Spans) == 0
	}
	return len(response.Spans) == 1 && validTraceRow(response.Spans[0], tenant, flow)
}

func validClickHouseMarkerResponse(raw []byte, tenant string, flow ProductTracePipelineFlow) bool {
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 1 || len(lines[0]) == 0 {
		return false
	}
	var row productClickHouseRow
	return decodeStrict(lines[0], &row) == nil && row.TenantID == tenant && row.TraceID == flow.TraceID &&
		row.SpanID == flow.SpanID && row.Service == flow.ServiceName && row.Name == flow.SpanName &&
		row.StartTimeUnixNano > 0 && nanoDifference(row.StartTimeUnixNano, flow.StartTimeUnixNano) <= uint64(productTimeTolerance)
}

type productClickHouseRow struct {
	TenantID          string `json:"tenant_id"`
	TraceID           string `json:"trace_id"`
	SpanID            string `json:"span_id"`
	Name              string `json:"name"`
	Service           string `json:"service"`
	StartTimeUnixNano uint64 `json:"start_time_unix_nano"`
}

func nanoDifference(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

func validTraceRow(row otelstore.Span, tenant string, flow ProductTracePipelineFlow) bool {
	if flow.EndTimeUnixNano <= flow.StartTimeUnixNano {
		return false
	}
	expectedStart := unixNanoTime(flow.StartTimeUnixNano)
	expectedDuration := time.Duration(flow.EndTimeUnixNano - flow.StartTimeUnixNano)
	return !expectedStart.IsZero() && row.TenantID == tenant && row.TraceID == flow.TraceID && row.SpanID == flow.SpanID &&
		row.ParentSpanID == "" && row.Service == flow.ServiceName && row.Name == flow.SpanName && row.Kind == "server" &&
		row.StatusCode == "unset" && len(row.Attrs) == 1 && row.Attrs["service.name"] == flow.ServiceName &&
		durationAbs(row.Start.Sub(expectedStart)) <= productTimeTolerance &&
		durationAbs(row.Duration-expectedDuration) <= productTimeTolerance
}

func durationAbs(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func parseProductCounterSnapshot(raw []byte) (map[string]float64, error) {
	wanted := make(map[string]bool)
	for _, signal := range []string{"otlp_metrics", "otlp_traces"} {
		for _, suffix := range []string{"received_total", "stored_total", "malformed_total", "tenant_rejected_total", "fairness_shed_total", "cardinality_dropped_total", "label_truncated_total", "unsupported_total", "dead_lettered_total", "dropped_total"} {
			wanted["probectl_pipeline_"+signal+"_"+suffix] = true
		}
	}
	values := make(map[string]float64, len(wanted))
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	buffer := make([]byte, 64<<10)
	scanner.Buffer(buffer, maxSemanticArtifactBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !wanted[fields[0]] {
			continue
		}
		if _, duplicate := values[fields[0]]; duplicate {
			return nil, fmt.Errorf("duplicate counter %s", fields[0])
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return nil, fmt.Errorf("invalid counter %s", fields[0])
		}
		values[fields[0]] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(values) != len(wanted) {
		return nil, fmt.Errorf("counter snapshot contains %d/%d required counters", len(values), len(wanted))
	}
	return values, nil
}
