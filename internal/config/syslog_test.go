// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strings"
	"testing"
)

// TestSyslogReceiverConfig covers the RTP-09 config surface: a fully configured
// client-cert listener parses its sources and reports enabled, while each
// fail-closed guard (missing TLS, no sources, uncredentialed source, no tenant,
// client-cert without a CA bundle) is refused.
func TestSyslogReceiverConfig(t *testing.T) {
	base := map[string]string{
		"PROBECTL_SYSLOG_LISTEN_ADDR":   ":6514",
		"PROBECTL_SYSLOG_TLS_CERT_FILE": "/run/secrets/syslog.pem",
		"PROBECTL_SYSLOG_TLS_KEY_FILE":  "/run/secrets/syslog-key.pem",
		"PROBECTL_SYSLOG_TLS_CA_FILE":   "/run/secrets/syslog-ca.pem",
		"PROBECTL_SYSLOG_SOURCES":       `[{"name":"edge-fw","tenant_id":"tenant-a","tls_client_subject":"CN=edge-fw,O=probectl","rate_limit":120}]`,
	}

	cfg, err := Load(envFunc(base))
	if err != nil {
		t.Fatalf("valid syslog config: %v", err)
	}
	if !cfg.SyslogEnabled() {
		t.Fatal("SyslogEnabled() = false for a fully configured listener")
	}
	if !cfg.SyslogClientCertRequired() {
		t.Fatal("SyslogClientCertRequired() = false with a tls_client_subject source")
	}
	if len(cfg.SyslogSources) != 1 {
		t.Fatalf("sources = %+v", cfg.SyslogSources)
	}
	src := cfg.SyslogSources[0]
	if src.Name != "edge-fw" || src.TenantID != "tenant-a" ||
		src.TLSClientSubject != "CN=edge-fw,O=probectl" || src.RateLimit != 120 {
		t.Fatalf("parsed source = %+v", src)
	}

	// HMAC-only source needs no CA bundle and is not client-cert mode.
	hmac := clone(base)
	delete(hmac, "PROBECTL_SYSLOG_TLS_CA_FILE")
	hmac["PROBECTL_SYSLOG_SOURCES"] = `[{"name":"edge-fw","tenant_id":"tenant-a","hmac_secret":"shared-secret"}]`
	cfg, err = Load(envFunc(hmac))
	if err != nil {
		t.Fatalf("valid hmac syslog config: %v", err)
	}
	if cfg.SyslogClientCertRequired() {
		t.Fatal("SyslogClientCertRequired() = true for an hmac-only source")
	}

	for _, tc := range []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{"no tls cert", func(m map[string]string) { delete(m, "PROBECTL_SYSLOG_TLS_CERT_FILE") }, "TLS-only"},
		{"no sources", func(m map[string]string) { delete(m, "PROBECTL_SYSLOG_SOURCES") }, "at least one authenticated source"},
		{"uncredentialed source", func(m map[string]string) {
			m["PROBECTL_SYSLOG_SOURCES"] = `[{"name":"edge-fw","tenant_id":"tenant-a"}]`
		}, "tls_client_subject or hmac_secret"},
		{"no tenant", func(m map[string]string) {
			m["PROBECTL_SYSLOG_SOURCES"] = `[{"name":"edge-fw","tls_client_subject":"CN=edge-fw,O=probectl"}]`
		}, "needs tenant_id"},
		{"client cert without ca", func(m map[string]string) { delete(m, "PROBECTL_SYSLOG_TLS_CA_FILE") }, "PROBECTL_SYSLOG_TLS_CA_FILE is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := clone(base)
			tc.mutate(env)
			if _, err := Load(envFunc(env)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
