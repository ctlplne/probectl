// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agentmetrics

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
)

func TestMetricsEveryAgentComponentExposesCoreSeries(t *testing.T) {
	for _, component := range Components {
		component := component
		t.Run(component, func(t *testing.T) {
			r, err := New(component, "v-test", "abc123", Config{Addr: "127.0.0.1:0"})
			if err != nil {
				t.Fatal(err)
			}
			r.Collection(2)
			r.Publish(1, 25*time.Millisecond, nil)
			r.Error()
			r.SetBufferDepth(3)
			r.SessionTimeout()
			r.SessionAdmissionRejected()
			r.SetActiveSessions(2)

			ctx, cancel := context.WithCancel(context.Background())
			errCh := make(chan error, 1)
			go func() { errCh <- r.Serve(ctx) }()
			waitReady(t, r)
			resp, err := http.Get("http://" + r.boundAddr() + "/metrics") // #nosec G107 -- loopback-only test listener
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			for _, want := range []string{
				"probectl_agent_collections_total 2",
				"probectl_agent_published_total 1",
				"probectl_agent_errors_total 1",
				"probectl_agent_buffer_depth 3",
				"probectl_agent_publish_latency_seconds 0.025",
				"probectl_agent_session_timeouts_total 1",
				"probectl_agent_session_rejections_total 1",
				"probectl_agent_active_sessions 2",
				"probectl_agent_metrics_tls 0",
			} {
				if !strings.Contains(string(body), want) {
					t.Errorf("/metrics missing %q:\n%s", want, body)
				}
			}
			cancel()
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMetricsNonLoopbackRequiresTLS(t *testing.T) {
	for _, addr := range []string{":9464", "0.0.0.0:9464", "192.0.2.1:9464"} {
		if _, err := New("probectl-agent", "test", "test", Config{Addr: addr}); err == nil || !strings.Contains(err.Error(), "requires TLS") {
			t.Fatalf("New(%q) error = %v, want non-loopback TLS refusal", addr, err)
		}
	}
	if _, err := New("probectl-agent", "test", "test", Config{Addr: "127.0.0.1:9464", TLSCertFile: "cert-only"}); err == nil {
		t.Fatal("one-sided TLS configuration must fail closed")
	}
}

func TestMetricsTLS13Listener(t *testing.T) {
	ca, err := crypto.GenerateCA("agent-metrics-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("agent-metrics", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := New("probectl-agent", "test", "test", Config{
		Addr: "127.0.0.1:0", TLSCertFile: certFile, TLSKeyFile: keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- r.Serve(ctx) }()
	waitReady(t, r)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("append test CA")
	}
	tlsCfg := crypto.InternalClientTLSConfig()
	tlsCfg.RootCAs = pool
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	resp, err := client.Get("https://" + r.boundAddr() + "/metrics")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "probectl_agent_metrics_tls 1") {
		t.Fatalf("TLS metric missing:\n%s", body)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestMetricsWiredIntoEveryAgentBinary(t *testing.T) {
	root := filepath.Join("..", "..", "..", "cmd")
	for _, component := range Components {
		path := filepath.Join(root, component, "main.go")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, want := range []string{"internal/agent/metrics", "agentmetrics.New(", "RunTogether("} {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s missing metrics wiring %q", component, want)
			}
		}
	}
}

func waitReady(t *testing.T, r *Runtime) {
	t.Helper()
	select {
	case <-r.readyChan():
	case <-time.After(3 * time.Second):
		t.Fatal("metrics listener did not become ready")
	}
}

type failureReportingBus struct {
	bus.Bus
}

func (failureReportingBus) PublishFailures() (uint64, uint64, error) {
	return 3, 1, errors.New("last produce failure on t: MESSAGE_TOO_LARGE")
}

// plainBus hides the wrapped bus's optional capabilities, so a transport that
// genuinely cannot report undelivered records can be tested (DPR-140).
type plainBus struct{ inner bus.Bus }

func (p plainBus) Publish(ctx context.Context, topic string, key, value []byte) error {
	return p.inner.Publish(ctx, topic, key, value)
}
func (p plainBus) Subscribe(ctx context.Context, topic, group string, h bus.Handler) error {
	return p.inner.Subscribe(ctx, topic, group, h)
}
func (p plainBus) Close() error { return p.inner.Close() }

// DPR-071: the metrics wrapper must not hide the wrapped bus's asynchronous
// failure counters from the agent that reads them after each flush.
func TestObservedBusForwardsPublishFailures(t *testing.T) {
	rt, err := New("probectl-ebpf-agent", "test", "test", Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	observed := ObserveBus(failureReportingBus{Bus: bus.NewMemory()}, rt)
	r, ok := observed.(bus.PublishFailureReporter)
	if !ok {
		t.Fatal("observed bus does not forward PublishFailureReporter")
	}
	f, s, last := r.PublishFailures()
	if f != 3 || s != 1 || last == nil {
		t.Errorf("forwarded failed=%d shed=%d last=%v", f, s, last)
	}
	plain := ObserveBus(bus.NewMemory(), rt).(bus.PublishFailureReporter)
	if f, s, last := plain.PublishFailures(); f != 0 || s != 0 || last != nil {
		t.Errorf("a bus without the capability must report nothing, got %d/%d/%v", f, s, last)
	}
}

// DPR-140: published_total counts what the transport accepted, which for an
// async producer is intent. Every agent whose transport can report undelivered
// records must expose that on its own endpoint, or "delivering nothing" is
// indistinguishable from "idle".
func TestObservedBusExposesUndeliveredOnTheEndpoint(t *testing.T) {
	rt, err := New("probectl-flow-agent", "v-test", "abc123", Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	_ = ObserveBus(failureReportingBus{Bus: bus.NewMemory()}, rt)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- rt.Serve(ctx) }()
	waitReady(t, rt)
	resp, err := http.Get("http://" + rt.boundAddr() + "/metrics") // #nosec G107 -- loopback-only test listener
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	text := string(body)
	for _, want := range []string{
		"probectl_agent_bus_publish_failed_total 3",
		"probectl_agent_bus_publish_shed_total 1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics endpoint missing %q", want)
		}
	}
	// The counters describe records ALREADY counted as published, so the help
	// text has to say that or an operator reads them as ordinary errors.
	if !strings.Contains(text, "never reached the broker") {
		t.Error("the failed counter must explain that these records were counted as published first")
	}
}

// A transport that cannot report undelivered records must not grow empty series
// that look like a healthy zero.
func TestObservedBusOmitsUndeliveredSeriesWithoutTheCapability(t *testing.T) {
	rt, err := New("probectl-device-agent", "v-test", "abc123", Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	_ = ObserveBus(plainBus{inner: bus.NewMemory()}, rt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = rt.Serve(ctx) }()
	waitReady(t, rt)
	resp, err := http.Get("http://" + rt.boundAddr() + "/metrics") // #nosec G107 -- loopback-only test listener
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), "probectl_agent_bus_publish_failed_total") {
		t.Error("a transport that cannot report undelivered records must expose no such series")
	}
}
