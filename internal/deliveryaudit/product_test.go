// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package deliveryaudit

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/store/otelstore"
)

func TestProductPipelineBindsCanonicalReleaseAuthorities(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	var original ProductPipelineArtifact
	readTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), &original)
	tests := []struct {
		name   string
		mutate func(*ProductPipelineArtifact)
	}{
		{name: "fake OTLP receiver", mutate: func(p *ProductPipelineArtifact) { p.Tenants[0].Metrics.Ingest.URL = "https://fake:4318/v1/metrics" }},
		{name: "OTLP userinfo", mutate: func(p *ProductPipelineArtifact) {
			p.Tenants[0].Metrics.Ingest.URL = "https://audit@control:4318/v1/metrics"
		}},
		{name: "OTLP fragment", mutate: func(p *ProductPipelineArtifact) {
			p.Tenants[0].Metrics.Ingest.URL = "https://control:4318/v1/metrics#other"
		}},
		{name: "wrong product table", mutate: func(p *ProductPipelineArtifact) { p.Tenants[0].Traces.ClickHouseDirect.Table = "audit.tenant_probe" }},
		{name: "tenant predicate in direct SQL", mutate: func(p *ProductPipelineArtifact) {
			p.Tenants[0].Traces.ClickHouseDirect.SQL += " WHERE tenant_id = 'tenant-a'"
		}},
		{name: "wrong release reader", mutate: func(p *ProductPipelineArtifact) { p.Tenants[0].Traces.ClickHouseDirect.User = "audit_tenant_a" }},
		{name: "wrong Prometheus authority", mutate: func(p *ProductPipelineArtifact) {
			p.Tenants[0].Metrics.PrometheusDirect.URL = strings.Replace(p.Tenants[0].Metrics.PrometheusDirect.URL, "prometheus:9090", "fake:9090", 1)
		}},
		{name: "Prometheus query lacks tenant", mutate: func(p *ProductPipelineArtifact) {
			flow := &p.Tenants[0].Metrics
			flow.PrometheusDirect.Query = flow.StoredMetricName + `{marker="` + flow.CorrelationID + `"}`
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneProductArtifact(t, original)
			test.mutate(&candidate)
			rewriteTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), candidate)
			assertProductDiagnostic(t, receipt, root, "product-pipeline-invalid")
		})
	}
}

func TestProductPipelineRequiresOneCanonicalStoreTenantPair(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	receipt.Stores.Postgres.TenantA = "unrelated-a"
	receipt.Stores.Postgres.TenantB = "unrelated-b"
	assertProductDiagnostic(t, receipt, root, "product-pipeline-cross-tenant")
}

func TestProductPipelineAllowsCanonicalStorePairInSwappedOrder(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	swap := func(a, b *string) { *a, *b = *b, *a }
	swap(&receipt.Stores.Postgres.TenantA, &receipt.Stores.Postgres.TenantB)
	swap(&receipt.Stores.ClickHouse.TenantA, &receipt.Stores.ClickHouse.TenantB)
	swap(&receipt.Stores.Kafka.TenantA, &receipt.Stores.Kafka.TenantB)
	swap(&receipt.Stores.Prometheus.TenantA, &receipt.Stores.Prometheus.TenantB)
	rewriteTestJSON(t, filepath.Join(root, receipt.Stores.Artifact), StoreProbesArtifact{
		Schema: StoreProbesArtifactSchema, ProductPipelineArtifact: receipt.Stores.ProductPipelineArtifact,
		Postgres: receipt.Stores.Postgres, ClickHouse: receipt.Stores.ClickHouse,
		Kafka: receipt.Stores.Kafka, Prometheus: receipt.Stores.Prometheus,
		ProviderBoundary: receipt.Stores.ProviderBoundary,
	})
	if diagnostics := LintWithArtifactsAtSource(receipt, root, testSourceRoot(t)); len(diagnostics) != 0 {
		t.Fatalf("swapped canonical tenant pair diagnostics = %v, want none", diagnostics)
	}
}

func TestProductPipelineRejectsManualKafkaSplices(t *testing.T) {
	t.Run("forged committed offset disagrees with broker output", func(t *testing.T) {
		root := t.TempDir()
		receipt := mustSelfTestReceipt(t, root)
		manifest := readProductArtifact(t, root, receipt)
		ref := &manifest.Tenants[0].Metrics.Kafka.GroupOffset
		var proof KafkaGroupOffsetArtifact
		proofPath := filepath.Join(root, filepath.FromSlash(ref.Path))
		readTestJSON(t, proofPath, &proof)
		proof.CommittedOffset++
		rewriteTestJSON(t, proofPath, proof)
		data, err := os.ReadFile(proofPath)
		if err != nil {
			t.Fatal(err)
		}
		ref.SHA256 = digestBytes(data)
		rewriteTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), manifest)
		assertProductDiagnostic(t, receipt, root, "product-pipeline-invalid")
	})

	t.Run("wrong deterministic bucket", func(t *testing.T) {
		root := t.TempDir()
		receipt := mustSelfTestReceipt(t, root)
		manifest := readProductArtifact(t, root, receipt)
		flow := &manifest.Tenants[0].Metrics
		wrongKey := bus.TenantKey(manifest.Tenants[0].Tenant, "service.name=some-other-service")
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(flow.Kafka.Key.Path)), wrongKey, 0o600); err != nil {
			t.Fatal(err)
		}
		flow.Kafka.Key.SHA256 = digestBytes(wrongKey)
		rewriteTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), manifest)
		assertProductDiagnostic(t, receipt, root, "product-pipeline-invalid")
	})

	t.Run("semantically equal but different payload bytes", func(t *testing.T) {
		root := t.TempDir()
		receipt := mustSelfTestReceipt(t, root)
		manifest := readProductArtifact(t, root, receipt)
		ref := &manifest.Tenants[0].Metrics.Kafka.Payload
		payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ref.Path)))
		if err != nil {
			t.Fatal(err)
		}
		// Unknown field 100 (varint=1) preserves decoded OTLP semantics but
		// changes the exact bytes. The release receiver did not emit this body.
		payload = append(payload, 0xa0, 0x06, 0x01)
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(ref.Path)), payload, 0o600); err != nil {
			t.Fatal(err)
		}
		ref.SHA256 = digestBytes(payload)
		rewriteTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), manifest)
		assertProductDiagnostic(t, receipt, root, "product-pipeline-invalid")
	})
}

func TestProductPipelineRejectsPartialOTLPSuccessAndFailureCounterMovement(t *testing.T) {
	t.Run("partial success", func(t *testing.T) {
		root := t.TempDir()
		receipt := mustSelfTestReceipt(t, root)
		manifest := readProductArtifact(t, root, receipt)
		ref := &manifest.Tenants[0].Metrics.Ingest.Response
		payload, err := proto.Marshal(&colmetricspb.ExportMetricsServiceResponse{PartialSuccess: &colmetricspb.ExportMetricsPartialSuccess{
			RejectedDataPoints: 1, ErrorMessage: "rejected",
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(ref.Path)), payload, 0o600); err != nil {
			t.Fatal(err)
		}
		ref.SHA256 = digestBytes(payload)
		rewriteTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), manifest)
		assertProductDiagnostic(t, receipt, root, "product-pipeline-invalid")
	})

	t.Run("malformed counter increased", func(t *testing.T) {
		root := t.TempDir()
		receipt := mustSelfTestReceipt(t, root)
		manifest := readProductArtifact(t, root, receipt)
		ref := &manifest.Integrity.After
		path := filepath.Join(root, filepath.FromSlash(ref.Path))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.Replace(string(data), "probectl_pipeline_otlp_metrics_malformed_total 10", "probectl_pipeline_otlp_metrics_malformed_total 11", 1))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		ref.SHA256 = digestBytes(data)
		rewriteTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), manifest)
		assertProductDiagnostic(t, receipt, root, "product-pipeline-integrity-failed")
	})
}

func TestProductPipelineRejectsOrphanManifestAndWrongActualTableProbe(t *testing.T) {
	t.Run("orphan manifest", func(t *testing.T) {
		root := t.TempDir()
		receipt := mustSelfTestReceipt(t, root)
		data, err := os.ReadFile(filepath.Join(root, receipt.Stores.ProductPipelineArtifact))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "contradictory-product-pipeline.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		receipt.Artifacts = append(receipt.Artifacts, Artifact{Path: "contradictory-product-pipeline.json", Kind: ArtifactProductPipeline})
		assertProductDiagnostic(t, receipt, root, "product-pipeline-ref-invalid")
	})

	t.Run("audit-only ClickHouse table", func(t *testing.T) {
		root := t.TempDir()
		receipt := mustSelfTestReceipt(t, root)
		receipt.Stores.ClickHouse.Table = "audit.tenant_probe"
		if codes := diagnosticCodes(Lint(receipt)); !slices.Contains(codes, "store-probe-failed") {
			t.Fatalf("codes = %v, want store-probe-failed", codes)
		}
	})
}

func TestProductPipelineRejectsCrossRevisionAndStaleEvidence(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(Receipt, *ProductPipelineArtifact)
	}{
		{name: "other receipt", want: "product-pipeline-invalid", edit: func(_ Receipt, p *ProductPipelineArtifact) { p.ReceiptID = "other-receipt" }},
		{name: "other source commit", want: "product-pipeline-invalid", edit: func(_ Receipt, p *ProductPipelineArtifact) { p.SourceGitSHA = strings.Repeat("e", 40) }},
		{name: "other source tree", want: "product-pipeline-invalid", edit: func(_ Receipt, p *ProductPipelineArtifact) { p.SourceTreeSHA = strings.Repeat("e", 40) }},
		{name: "other control image", want: "product-pipeline-invalid", edit: func(_ Receipt, p *ProductPipelineArtifact) { p.ControlImageID = "sha256:" + strings.Repeat("e", 64) }},
		{name: "other CLI", want: "product-pipeline-invalid", edit: func(_ Receipt, p *ProductPipelineArtifact) { p.CLISHA256 = "sha256:" + strings.Repeat("e", 64) }},
		{name: "window starts before receipt", want: "product-pipeline-invalid", edit: func(r Receipt, p *ProductPipelineArtifact) { p.StartedAt = r.StartedAt.Add(-time.Second) }},
		{name: "window ends after receipt", want: "product-pipeline-invalid", edit: func(r Receipt, p *ProductPipelineArtifact) { p.CompletedAt = r.CompletedAt.Add(time.Second) }},
		{name: "stale ingest observation", want: "product-pipeline-invalid", edit: func(_ Receipt, p *ProductPipelineArtifact) {
			p.Tenants[0].Metrics.Ingest.ObservedAt = p.StartedAt.Add(-time.Second)
		}},
		{name: "readback predates event", want: "product-pipeline-invalid", edit: func(_ Receipt, p *ProductPipelineArtifact) {
			p.Tenants[0].Metrics.ControlQuery.ObservedAt = p.StartedAt
		}},
		{name: "counters do not bracket readbacks", want: "product-pipeline-integrity-failed", edit: func(_ Receipt, p *ProductPipelineArtifact) {
			p.Integrity.AfterObservedAt = p.StartedAt.Add(time.Second)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			receipt := mustSelfTestReceipt(t, root)
			manifest := readProductArtifact(t, root, receipt)
			test.edit(receipt, &manifest)
			rewriteTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), manifest)
			assertProductDiagnostic(t, receipt, root, test.want)
		})
	}
}

func TestProductMetricSelectorsAreExact(t *testing.T) {
	flow := ProductMetricPipelineFlow{CorrelationID: strings.Repeat("1", 32), StoredMetricName: productStoredMetric}
	control := productStoredMetric + `{marker="` + flow.CorrelationID + `"}`
	if !validProductMetricQuery("/v1/grafana/api/v1/query?query="+url.QueryEscape(control), flow) {
		t.Fatal("canonical control selector rejected")
	}
	for _, selector := range []string{
		productStoredMetric + `{marker="` + flow.CorrelationID + `",impossible="yes"}`,
		productStoredMetric + `{marker="` + flow.CorrelationID + `",marker="` + flow.CorrelationID + `"}`,
	} {
		if validProductMetricQuery("/v1/grafana/api/v1/query?query="+url.QueryEscape(selector), flow) {
			t.Fatalf("non-canonical control selector accepted: %s", selector)
		}
	}
	direct := productStoredMetric + `{marker="` + flow.CorrelationID + `",tenant_id="tenant-a"}`
	proof := ProductPrometheusDirectQuery{Query: direct, URL: "https://prometheus:9090/api/v1/query?query=" + url.QueryEscape(direct)}
	if !validDirectPrometheusQuery(proof, "tenant-a", flow) {
		t.Fatal("canonical direct selector rejected")
	}
	for _, selector := range []string{
		productStoredMetric + `{marker="` + flow.CorrelationID + `",tenant_id="tenant-a",impossible="yes"}`,
		productStoredMetric + `{tenant_id="tenant-a",marker="` + flow.CorrelationID + `"}`,
	} {
		proof.Query = selector
		proof.URL = "https://prometheus:9090/api/v1/query?query=" + url.QueryEscape(selector)
		if validDirectPrometheusQuery(proof, "tenant-a", flow) {
			t.Fatalf("non-canonical direct selector accepted: %s", selector)
		}
	}
}

func TestProductPrometheusResponseIsExactAndFresh(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	manifest := readProductArtifact(t, root, receipt)
	flow := manifest.Tenants[0].Metrics
	raw, err := selfTestPrometheusBody(manifest.Tenants[0].Tenant, flow, flow.ControlQuery.ObservedAt, false)
	if err != nil {
		t.Fatal(err)
	}
	var response productPrometheusResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	queryTimestamp, err := json.Marshal(float64(flow.ControlQuery.ObservedAt.UnixNano()) / float64(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	response.Data.Result[0].Value[0] = queryTimestamp
	raw, err = json.Marshal(response)
	if err != nil || !validPrometheusMarkerResponse(raw, manifest.Tenants[0].Tenant, flow, flow.ControlQuery.ObservedAt, false) {
		t.Fatal("canonical Prometheus instant-query marker response rejected")
	}
	if validPrometheusMarkerResponse(raw, manifest.Tenants[0].Tenant, flow, flow.ControlQuery.ObservedAt.Add(-time.Second), false) {
		t.Fatal("Prometheus response accepted against a different query observation time")
	}
	response.Data.Result[0].Metric["impossible"] = "splice"
	extraLabel, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if validPrometheusMarkerResponse(extraLabel, manifest.Tenants[0].Tenant, flow, flow.ControlQuery.ObservedAt, false) {
		t.Fatal("Prometheus response with an extra label accepted")
	}
	delete(response.Data.Result[0].Metric, "impossible")
	response.Data.Result[0].Value[0] = json.RawMessage("1")
	stale, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if validPrometheusMarkerResponse(stale, manifest.Tenants[0].Tenant, flow, flow.ControlQuery.ObservedAt, false) {
		t.Fatal("Prometheus response with a stale sample timestamp accepted")
	}
}

func TestProductTraceResponseRequiresCanonicalServiceAttribute(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	manifest := readProductArtifact(t, root, receipt)
	tenant := manifest.Tenants[0]
	flow := tenant.Traces
	row := otelstore.Span{
		TenantID: tenant.Tenant, TraceID: flow.TraceID, SpanID: flow.SpanID,
		Name: flow.SpanName, Kind: "server", Service: flow.ServiceName,
		Start:      unixNanoTime(flow.StartTimeUnixNano),
		Duration:   time.Duration(flow.EndTimeUnixNano - flow.StartTimeUnixNano),
		StatusCode: "unset", Attrs: map[string]string{"service.name": flow.ServiceName},
	}
	if !validTraceRow(row, tenant.Tenant, flow) {
		t.Fatal("canonical retained service.name trace attribute rejected")
	}
	row.Attrs["impossible"] = "splice"
	if validTraceRow(row, tenant.Tenant, flow) {
		t.Fatal("trace response with an extra attribute accepted")
	}
	delete(row.Attrs, "impossible")
	row.Attrs["service.name"] = "some-other-service"
	if validTraceRow(row, tenant.Tenant, flow) {
		t.Fatal("trace response with a mismatched service.name attribute accepted")
	}
}

func TestProductProtobufsRejectUnknownAndExtraFields(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	manifest := readProductArtifact(t, root, receipt)
	tenant := manifest.Tenants[0]

	metricRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(tenant.Metrics.Ingest.Request.Path)))
	if err != nil {
		t.Fatal(err)
	}
	var metric colmetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(metricRaw, &metric); err != nil || !validProductMetricRequest(&metric, tenant.Tenant, tenant.Metrics) {
		t.Fatal("canonical metric protobuf rejected")
	}
	metric.ResourceMetrics[0].Resource.Attributes = append(metric.ResourceMetrics[0].Resource.Attributes,
		&commonpb.KeyValue{Key: "fixture", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "splice"}}})
	if validProductMetricRequest(&metric, tenant.Tenant, tenant.Metrics) {
		t.Fatal("metric protobuf with an extra resource attribute accepted")
	}
	if err := proto.Unmarshal(metricRaw, &metric); err != nil {
		t.Fatal(err)
	}
	metric.ResourceMetrics[0].Resource.EntityRefs = []*commonpb.EntityRef{{Type: "service", IdKeys: []string{"service.name"}}}
	if validProductMetricRequest(&metric, tenant.Tenant, tenant.Metrics) {
		t.Fatal("metric protobuf with a resource entity reference accepted")
	}
	if err := proto.Unmarshal(metricRaw, &metric); err != nil {
		t.Fatal(err)
	}
	metric.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].Metadata = []*commonpb.KeyValue{{
		Key: "splice", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "extra"}},
	}}
	if validProductMetricRequest(&metric, tenant.Tenant, tenant.Metrics) {
		t.Fatal("metric protobuf with metadata accepted")
	}
	if err := proto.Unmarshal(append(metricRaw, 0xa0, 0x06, 0x01), &metric); err != nil {
		t.Fatal(err)
	}
	if validProductMetricRequest(&metric, tenant.Tenant, tenant.Metrics) {
		t.Fatal("metric protobuf with an unknown wire field accepted")
	}

	traceRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(tenant.Traces.Ingest.Request.Path)))
	if err != nil {
		t.Fatal(err)
	}
	var trace coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(traceRaw, &trace); err != nil || !validProductTraceRequest(&trace, tenant.Tenant, tenant.Traces) {
		t.Fatal("canonical trace protobuf rejected")
	}
	trace.ResourceSpans[0].ScopeSpans[0].Spans[0].Attributes = append(trace.ResourceSpans[0].ScopeSpans[0].Spans[0].Attributes,
		&commonpb.KeyValue{Key: "fixture", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "splice"}}})
	if validProductTraceRequest(&trace, tenant.Tenant, tenant.Traces) {
		t.Fatal("trace protobuf with an extra span attribute accepted")
	}
	if err := proto.Unmarshal(traceRaw, &trace); err != nil {
		t.Fatal(err)
	}
	trace.ResourceSpans[0].Resource.EntityRefs = []*commonpb.EntityRef{{Type: "service", IdKeys: []string{"service.name"}}}
	if validProductTraceRequest(&trace, tenant.Tenant, tenant.Traces) {
		t.Fatal("trace protobuf with a resource entity reference accepted")
	}
	if err := proto.Unmarshal(append(traceRaw, 0xa0, 0x06, 0x01), &trace); err != nil {
		t.Fatal(err)
	}
	if validProductTraceRequest(&trace, tenant.Tenant, tenant.Traces) {
		t.Fatal("trace protobuf with an unknown wire field accepted")
	}
}

func TestProductPipelineRejectsUnknownFieldsInIngestAndKafka(t *testing.T) {
	for _, signal := range []string{"metrics", "traces"} {
		t.Run(signal, func(t *testing.T) {
			root := t.TempDir()
			receipt := mustSelfTestReceipt(t, root)
			manifest := readProductArtifact(t, root, receipt)
			var requestRef, payloadRef *ProductArtifactRef
			if signal == "metrics" {
				requestRef = &manifest.Tenants[0].Metrics.Ingest.Request
				payloadRef = &manifest.Tenants[0].Metrics.Kafka.Payload
			} else {
				requestRef = &manifest.Tenants[0].Traces.Ingest.Request
				payloadRef = &manifest.Tenants[0].Traces.Kafka.Payload
			}
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(requestRef.Path)))
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, 0xa0, 0x06, 0x01)
			for _, ref := range []*ProductArtifactRef{requestRef, payloadRef} {
				if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(ref.Path)), data, 0o600); err != nil {
					t.Fatal(err)
				}
				ref.SHA256 = digestBytes(data)
			}
			rewriteTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), manifest)
			assertProductDiagnostic(t, receipt, root, "product-pipeline-invalid")
		})
	}
}

func TestProductPipelineRequiresTypedClickHouseIsolation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ClickHouseIsolationArtifact)
	}{
		{name: "tenant predicate", edit: func(p *ClickHouseIsolationArtifact) { p.SQL += " WHERE tenant_id = 'tenant-a'" }},
		{name: "privileged reader", edit: func(p *ClickHouseIsolationArtifact) { p.User = "default" }},
		{name: "stale observation", edit: func(p *ClickHouseIsolationArtifact) { p.TenantAObservedAt = time.Unix(1, 0).UTC() }},
		{name: "swapped raw response", edit: func(p *ClickHouseIsolationArtifact) { p.TenantAResponse = p.TenantBResponse }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			receipt := mustSelfTestReceipt(t, root)
			manifest := readProductArtifact(t, root, receipt)
			proofPath := filepath.Join(root, filepath.FromSlash(manifest.ClickHouseIsolation.Path))
			var proof ClickHouseIsolationArtifact
			readTestJSON(t, proofPath, &proof)
			test.edit(&proof)
			rewriteTestJSON(t, proofPath, proof)
			data, err := os.ReadFile(proofPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest.ClickHouseIsolation.SHA256 = digestBytes(data)
			rewriteTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), manifest)
			assertProductDiagnostic(t, receipt, root, "product-pipeline-cross-tenant")
		})
	}
}

func TestProductPipelineCrossBindsTypedStoreSummaries(t *testing.T) {
	t.Run("Kafka exact product record count", func(t *testing.T) {
		root := t.TempDir()
		receipt := mustSelfTestReceipt(t, root)
		three := int64(3)
		receipt.Stores.Kafka.ObservedProductMessages = &three
		assertProductDiagnostic(t, receipt, root, "product-pipeline-invalid")
	})
	t.Run("ClickHouse exact directional counts", func(t *testing.T) {
		root := t.TempDir()
		receipt := mustSelfTestReceipt(t, root)
		two := int64(2)
		receipt.Stores.ClickHouse.SeededTenantARows = &two
		assertProductDiagnostic(t, receipt, root, "product-pipeline-cross-tenant")
	})
}

func readProductArtifact(t *testing.T, root string, receipt Receipt) ProductPipelineArtifact {
	t.Helper()
	var artifact ProductPipelineArtifact
	readTestJSON(t, filepath.Join(root, receipt.Stores.ProductPipelineArtifact), &artifact)
	return artifact
}

func cloneProductArtifact(t *testing.T, artifact ProductPipelineArtifact) ProductPipelineArtifact {
	t.Helper()
	data, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var clone ProductPipelineArtifact
	if err := decodeStrict(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func assertProductDiagnostic(t *testing.T, receipt Receipt, root, want string) {
	t.Helper()
	codes := diagnosticCodes(LintWithArtifactsAtSource(receipt, root, testSourceRoot(t)))
	if !slices.Contains(codes, want) {
		t.Fatalf("codes = %v, want %q", codes, want)
	}
}
