// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"net"
	"testing"

	agentmetrics "github.com/ctlplne/probectl/internal/agent/metrics"
)

func TestEnrolledEndpointMetricsRequireTLSAndAllowConcurrentSessions(t *testing.T) {
	const (
		addressKey = "PROBECTL_ENDPOINT_METRICS_ADDR"
		certKey    = "PROBECTL_ENDPOINT_METRICS_TLS_CERT_FILE"
		privateKey = "PROBECTL_ENDPOINT_METRICS_TLS_KEY_FILE"
	)
	t.Setenv(addressKey, "")
	t.Setenv(certKey, "")
	t.Setenv(privateKey, "")
	if cfg, err := endpointMetricsConfig(true); err != nil || cfg.Addr != "" {
		t.Fatalf("an enrolled endpoint opened metrics by default: %+v, %v", cfg, err)
	}
	if cfg, err := endpointMetricsConfig(false); err != nil || cfg.Addr != agentmetrics.DefaultEndpointAddr {
		t.Fatalf("standalone endpoint metrics configuration = %+v, %v", cfg, err)
	}
	t.Setenv(addressKey, "127.0.0.1:19468")
	if cfg, err := endpointMetricsConfig(true); err == nil || cfg.Addr != "" {
		t.Fatal("enrolled endpoint accepted a plaintext metrics address")
	}
	t.Setenv(certKey, "metrics-cert.pem")
	if cfg, err := endpointMetricsConfig(true); err == nil || cfg.Addr != "" {
		t.Fatal("enrolled endpoint accepted only a metrics certificate")
	}
	t.Setenv(privateKey, "metrics-key.pem")
	if cfg, err := endpointMetricsConfig(true); err != nil || cfg.Addr != "127.0.0.1:19468" ||
		cfg.TLSCertFile != "metrics-cert.pem" || cfg.TLSKeyFile != "metrics-key.pem" {
		t.Fatalf("explicit TLS metrics configuration = %+v, %v", cfg, err)
	}
	t.Setenv(addressKey, "")
	cfg, err := endpointMetricsConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	addr := cfg.Addr
	if addr != "127.0.0.1:0" {
		t.Fatalf("managed endpoint metrics selected a shared address %q", addr)
	}
	var listener net.ListenConfig
	first, err := listener.Listen(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := listener.Listen(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if first.Addr().String() == second.Addr().String() {
		t.Fatalf("two sessions shared one metrics socket %s", first.Addr())
	}
}
