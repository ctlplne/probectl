// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestShippedRenderedBrowserConfigLoadsStrictly(t *testing.T) {
	// The shipped file points at the paths inside the browser-agent image. For a
	// host-side schema test, replace both with this already-present test binary;
	// the release-container smoke separately proves /worker/worker.mjs + node.
	t.Setenv("PROBECTL_AGENT_BROWSER_WORKER_COMMAND", os.Args[0])
	t.Setenv("PROBECTL_AGENT_BROWSER_WORKER_PATH", os.Args[0])
	path := filepath.Join("..", "..", "deploy", "compose", "eval-browser-agent.yml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load shipped rendered-browser config: %v", err)
	}
	if cfg.Browser.Driver != "browser" || cfg.Canaries[0].Params["browser_driver"] != "browser" {
		t.Fatalf("rendered browser selection drifted: browser=%+v canary=%+v", cfg.Browser, cfg.Canaries[0])
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

func TestConfigLoadsAgentObjectStoreEnvOverride(t *testing.T) {
	t.Setenv("PROBECTL_AGENT_OBJECTSTORE_DIR", "/var/lib/probectl/objects")
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
	if cfg.ArtifactStore.Dir != "/var/lib/probectl/objects" {
		t.Fatalf("artifact_store.dir = %q", cfg.ArtifactStore.Dir)
	}
}

func TestConfigBrowserDriverDefaultsToHTTP(t *testing.T) {
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
	if cfg.Browser.Driver != "http" {
		t.Fatalf("browser.driver = %q, want http", cfg.Browser.Driver)
	}
}

func TestConfigBrowserDriverRequiresPresentWorker(t *testing.T) {
	base := `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
browser:
  driver: browser
  worker:
    command: %q
    path: %q
`
	for _, tc := range []struct {
		name    string
		command string
		path    string
		wantErr string
	}{
		{name: "missing path", command: os.Args[0], wantErr: "worker.path is required"},
		{name: "missing command", command: filepath.Join(t.TempDir(), "missing-command"), path: os.Args[0], wantErr: "command"},
		{name: "missing worker", command: os.Args[0], path: filepath.Join(t.TempDir(), "missing-worker.mjs"), wantErr: "worker path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeAgentConfig(t, fmt.Sprintf(base, tc.command, tc.path))
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
			}
		})
	}

	path := writeAgentConfig(t, fmt.Sprintf(base, os.Args[0], os.Args[0]))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("present browser worker rejected: %v", err)
	}
	if cfg.Browser.Driver != "browser" || cfg.Browser.Worker.StepTimeout.Std() != 15*time.Second {
		t.Fatalf("browser config = %+v", cfg.Browser)
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
