// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRejectsPlaintextIdentityServer(t *testing.T) {
	path := writeAgentConfig(t, `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
identity:
  server: http://127.0.0.1:8443
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "config: identity.server: enroll: plaintext http:// enrollment is refused") {
		t.Fatalf("plaintext identity.server should be refused at config load, got %v", err)
	}
}

func TestConfigRejectsPlaintextEnrollServerWithoutOverride(t *testing.T) {
	path := writeAgentConfig(t, `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
enroll:
  server: http://127.0.0.1:8443
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "config: enroll.server: enroll: plaintext http:// enrollment is refused") {
		t.Fatalf("plaintext enroll.server should be refused at config load, got %v", err)
	}
}

func TestConfigAllowsPlaintextEnrollServerOnlyForLoopbackOverride(t *testing.T) {
	path := writeAgentConfig(t, `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
enroll:
  server: http://127.0.0.1:8443
  allow_plaintext_loopback: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("loopback plaintext override should load: %v", err)
	}
	if !cfg.Enroll.AllowPlaintextLoopback {
		t.Fatal("allow_plaintext_loopback did not decode")
	}
}

func TestConfigA2ADefaultsToDisabled(t *testing.T) {
	path := writeAgentConfig(t, `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.A2A.Enabled {
		t.Fatal("a2a.enabled must default false so raw responder listeners require explicit operator opt-in")
	}
	if cfg.Buffer.MaxRecords != defaultBufferMaxRecords {
		t.Fatalf("buffer max_records = %d, want %d", cfg.Buffer.MaxRecords, defaultBufferMaxRecords)
	}
	if cfg.Buffer.DrainMaxRecords != defaultDrainMaxRecords {
		t.Fatalf("buffer drain_max_records = %d, want %d", cfg.Buffer.DrainMaxRecords, defaultDrainMaxRecords)
	}
	if cfg.Buffer.DrainMaxBytes != defaultDrainMaxBytes {
		t.Fatalf("buffer drain_max_bytes = %d, want %d", cfg.Buffer.DrainMaxBytes, defaultDrainMaxBytes)
	}
	if cfg.Buffer.DrainPace.Std() != defaultDrainPace {
		t.Fatalf("buffer drain_pace = %s, want %s", cfg.Buffer.DrainPace.Std(), defaultDrainPace)
	}
}

func writeAgentConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
