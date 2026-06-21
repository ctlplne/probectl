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

func TestConfigRequiresVersionAndRejectsUnknownKeys(t *testing.T) {
	missingVersion := filepath.Join(t.TempDir(), "agent.yml")
	if err := os.WriteFile(missingVersion, []byte(`
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(missingVersion)
	if err == nil || !strings.Contains(err.Error(), "apiVersion is required") {
		t.Fatalf("missing apiVersion should fail, got %v", err)
	}

	path := writeAgentConfig(t, `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
old_removed_key: true
`)
	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "field old_removed_key not found") {
		t.Fatalf("unknown key should fail strict YAML decode, got %v", err)
	}
}

func TestConfigAcceptsSchemaVersionAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yml")
	if err := os.WriteFile(path, []byte(`
schema_version: 1
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("schema_version alias should load: %v", err)
	}
	if cfg.APIVersion != ConfigAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", cfg.APIVersion, ConfigAPIVersion)
	}
}

func TestShippedAgentConfigsLoadStrictly(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "..", "deploy", "agent", "probectl-agent.example.yml"),
		filepath.Join("..", "..", "deploy", "packaging", "config", "agent.yaml"),
	} {
		t.Run(path, func(t *testing.T) {
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("load shipped config: %v", err)
			}
			if cfg.APIVersion != ConfigAPIVersion {
				t.Fatalf("apiVersion = %q, want %q", cfg.APIVersion, ConfigAPIVersion)
			}
		})
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
	if !strings.Contains(body, "apiVersion:") && !strings.Contains(body, "schema_version:") {
		body = "apiVersion: " + ConfigAPIVersion + "\n" + body
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
