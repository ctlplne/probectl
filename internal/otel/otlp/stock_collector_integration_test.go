// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package otlp_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestStockCollectorDeliversAllSignalsToShippedTenants(t *testing.T) {
	binary := os.Getenv("PROBECTL_TEST_STOCK_OTEL_COLLECTOR")
	if binary == "" {
		if os.Getenv("PROBECTL_TEST_REQUIRE_STOCK_OTEL_COLLECTOR") == "1" {
			t.Fatal("the stock OpenTelemetry Collector executable is required")
		}
		testsupport.SkipOptIn(t, "PROBECTL_TEST_REQUIRE_STOCK_OTEL_COLLECTOR", "set PROBECTL_TEST_STOCK_OTEL_COLLECTOR to the stock Collector executable")
	}
	stack := shipped.Start(t, shipped.Options{Name: "stockotlp", TenantBand: 3})
	operator := stack.OnboardOperator(t, "root@msp-stock-otlp.example")
	service := "stock-otlp-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := [2]struct {
		tenant wireTenant
		signal wireSignalPair
		metric string
		value  string
	}{}
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		lane := &lanes[i]
		slug := service + "-" + strconv.Itoa(i)
		var result struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &result, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, slug, slug))
		lane.tenant.id, lane.tenant.cookie = result.ID, stack.SignIn(t, result.ID, email, slug)
		code, body := stack.Do(t, lane.tenant.cookie, http.MethodPost, "/v1/otlp-tokens", map[string]string{"name": "stock-collector"})
		if code != http.StatusCreated || json.Unmarshal(body, &lane.tenant.token) != nil || lane.tenant.token.Token == "" {
			t.Fatalf("the tenant could not mint its Collector export credential: HTTP %d", code)
		}
		lane.signal = newWireSignalPair(t, service, slug, "")
		lane.metric = "stock_otel_" + strconv.Itoa(i)
		value := []float64{11.25, 97.5}[i]
		lane.value = strconv.FormatFloat(value, 'f', -1, 64)
		client, collector := startStockOTelCollector(t, binary, stack, slug, lane.tenant.token.Token)
		sendStockCollectorSignal(t, client, collector, "traces", lane.signal.traces)
		sendStockCollectorSignal(t, client, collector, "logs", lane.signal.logs)
		sendStockCollectorSignal(t, client, collector, "metrics", &colmetricspb.ExportMetricsServiceRequest{
			ResourceMetrics: []*metricspb.ResourceMetrics{{
				Resource: lane.signal.traces.ResourceSpans[0].Resource,
				ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
					Name: lane.metric,
					Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
						TimeUnixNano: uint64(time.Now().UnixNano()), Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: value},
					}}}},
				}}}},
			}},
		})
	}
	for i, lane := range lanes {
		other := lanes[1-i]
		shipped.Await(t, "Collector persisted all three signals", 45*time.Second, func() bool {
			spans, logs := readWireSignalPair(t, stack, lane.tenant.cookie, service, lane.signal.traceID)
			if len(spans) == 0 || len(logs) == 0 {
				return false
			}
			checkWireSignalPair(t, lane.tenant.id, lane.signal, spans, logs)
			values := stockCollectorMetricValues(t, stack, lane.tenant.cookie, lane.metric)
			return len(values) == 1 && values[0] == lane.value
		})
		spans, logs := readWireSignalPair(t, stack, other.tenant.cookie, service, lane.signal.traceID)
		if len(spans) != 0 || len(logs) != 0 || len(stockCollectorMetricValues(t, stack, other.tenant.cookie, lane.metric)) != 0 {
			t.Fatal("a sibling tenant read a Collector signal it did not own")
		}
	}
}

func startStockOTelCollector(t *testing.T, binary string, stack *shipped.Stack, name, token string) (*http.Client, string) {
	t.Helper()
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := held.Addr().String()
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(dir, "receiver.crt"), filepath.Join(dir, "receiver.key"), filepath.Join(dir, "receiver-ca.crt")
	clientCertFile, clientKeyFile := filepath.Join(dir, "sender.crt"), filepath.Join(dir, "sender.key")
	ca, err := crypto.GenerateCA(name, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServerCert(name, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, clientKey, err := ca.IssueClientCert(name, "spiffe://probectl.test/otlp/"+name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{
		certFile: cert, keyFile: key, caFile: ca.CertPEM(), clientCertFile: clientCert, clientKeyFile: clientKey,
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(dir, "collector.yaml")
	body := fmt.Sprintf(`receivers:
  otlp:
    protocols:
      http:
        endpoint: %q
        tls:
          cert_file: %q
          key_file: %q
          client_ca_file: %q
processors:
  batch:
    timeout: 100ms
exporters:
  otlphttp/probectl:
    endpoint: %q
    headers:
      Authorization: 'Bearer ${env:PROBECTL_TEST_COLLECTOR_EXPORT_TOKEN}'
    tls:
      ca_file: %q
    compression: gzip
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp/probectl]
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp/probectl]
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp/probectl]
`, addr, certFile, keyFile, caFile, stack.OTLPURL, stack.CAFile)
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "--config", config)
	cmd.Dir = dir
	cmd.Env = []string{"PROBECTL_TEST_COLLECTOR_EXPORT_TOKEN=" + token}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	tls, err := crypto.ClientMTLSConfig(clientCertFile, clientKeyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: tls}
	client := &http.Client{Timeout: 2 * time.Second, Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)
	base := "https://" + addr
	shipped.Await(t, "stock Collector TLS receiver", 15*time.Second, func() bool {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/v1/traces", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			return false
		}
		_ = res.Body.Close()
		return res.StatusCode == http.StatusMethodNotAllowed
	})
	unauthenticated, err := crypto.HardenedHTTPClientWithCAFile(2*time.Second, caFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unauthenticated.CloseIdleConnections)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/v1/traces", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := unauthenticated.Do(req); err == nil {
		_ = res.Body.Close()
		t.Fatal("the Collector receiver accepted a caller without its lane certificate")
	}
	return client, base
}

func sendStockCollectorSignal(t *testing.T, client *http.Client, base, kind string, signal proto.Message) {
	t.Helper()
	body, err := proto.Marshal(signal)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/v1/"+kind, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("stock Collector %s receiver returned HTTP %d", kind, res.StatusCode)
	}
}

func stockCollectorMetricValues(t *testing.T, stack *shipped.Stack, cookie, metric string) []string {
	t.Helper()
	path := "/v1/grafana/api/v1/query?query=" + url.QueryEscape("probectl_otlp_"+metric)
	code, body := stack.Do(t, cookie, http.MethodGet, path, nil)
	var vector struct {
		Status string
		Data   struct {
			Result []struct{ Value []json.RawMessage }
		}
	}
	if code != http.StatusOK || json.Unmarshal(body, &vector) != nil || vector.Status != "success" {
		t.Fatalf("the Prometheus query returned HTTP %d", code)
	}
	var values []string
	for _, sample := range vector.Data.Result {
		var value string
		if len(sample.Value) != 2 || json.Unmarshal(sample.Value[1], &value) != nil {
			t.Fatal("the Prometheus response did not contain a complete sample")
		}
		values = append(values, value)
	}
	return values
}
