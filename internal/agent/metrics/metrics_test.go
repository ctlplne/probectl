// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package agentmetrics

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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

			ctx, cancel := context.WithCancel(context.Background())
			errCh := make(chan error, 1)
			go func() { errCh <- r.Serve(ctx) }()
			waitReady(t, r)
			resp, err := http.Get("http://" + r.Addr() + "/metrics") // #nosec G107 -- loopback-only test listener
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
	resp, err := client.Get("https://" + r.Addr() + "/metrics")
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
	case <-r.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("metrics listener did not become ready")
	}
}
