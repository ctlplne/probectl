// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package agent

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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

func TestConfigRejectsLegacyInsecureTLSOptIn(t *testing.T) {
	path := writeAgentConfig(t, `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
security:
  allow_insecure_skip_verify: true
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "outbound certificate verification cannot be disabled") {
		t.Fatalf("legacy insecure TLS opt-in should be refused at config load, got %v", err)
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

func TestConfigLoadsAndNormalizesLocalPlacementLabels(t *testing.T) {
	path := writeAgentConfig(t, `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
agent:
  labels:
    Region: " eu-west "
    site: dub-1
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.Labels["region"] != "eu-west" || cfg.Agent.Labels["site"] != "dub-1" {
		t.Fatalf("labels = %#v", cfg.Agent.Labels)
	}
}

func TestLoadBoundsConfigFile(t *testing.T) {
	const limit = 1 << 20
	valid := []byte("apiVersion: " + ConfigAPIVersion + "\ncontrol_plane:\n  grpc_addr: control:9443\ntls:\n  cert_file: cert.pem\n  key_file: key.pem\n  ca_file: ca.pem\n")
	pad := func(size int) []byte {
		t.Helper()
		if size < len(valid)+2 {
			t.Fatalf("fixture size %d is too small", size)
		}
		return append(append(append([]byte{}, valid...), '\n', '#'), bytes.Repeat([]byte{'x'}, size-len(valid)-2)...)
	}

	for _, tc := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "maximum", size: limit},
		{name: "one past maximum", size: limit + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.yml")
			if err := os.WriteFile(path, pad(tc.size), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "exceeds 1048576-byte limit") {
					t.Fatalf("one-past-maximum agent config error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("maximum-sized agent config rejected: %v", err)
			}
		})
	}
}

func TestJoinTokenBoundsTokenFile(t *testing.T) {
	const (
		limit  = 64 << 10
		canary = "planted-enrollment-token-canary"
	)
	t.Setenv("PROBECTL_AGENT_JOIN_TOKEN", "")

	for _, tc := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "maximum", size: limit},
		{name: "one past maximum", size: limit + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := append([]byte(canary), bytes.Repeat([]byte{'x'}, tc.size-len(canary))...)
			path := filepath.Join(t.TempDir(), "join-token")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}

			cfg := Config{Enroll: EnrollConfig{TokenFile: path}}
			got, err := cfg.JoinToken()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "enrollment token file exceeds 65536-byte limit") {
					t.Fatalf("one-past-maximum enrollment token error = %v", err)
				}
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("enrollment token error leaked token material: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("maximum-sized enrollment token rejected: %v", err)
			}
			if got != string(body) {
				t.Fatalf("maximum-sized enrollment token length = %d, want %d", len(got), len(body))
			}
		})
	}
}

func TestConfigAcceptsUniqueTestIDsAndRejectsAmbiguity(t *testing.T) {
	valid := writeAgentConfig(t, `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
canaries:
  - test_id: 018f2d5e-7b3a-7aa2-8b8a-9c21b0c6d991
    type: dns
    target: example.test
`)
	cfg, err := Load(valid)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Canaries[0].TestID; got != "018f2d5e-7b3a-7aa2-8b8a-9c21b0c6d991" {
		t.Fatalf("test_id = %q", got)
	}

	for name, body := range map[string]string{
		"duplicate": `
canaries:
  - test_id: same
    type: dns
  - test_id: same
    type: http
`,
		"unsupported": `
canaries:
  - test_id: "not a stable id"
    type: dns
`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeAgentConfig(t, `
control_plane:
  grpc_addr: control:9443
tls:
  cert_file: cert.pem
  key_file: key.pem
  ca_file: ca.pem
`+body)
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "test_id") {
				t.Fatalf("invalid test_id should fail closed, got %v", err)
			}
		})
	}
}

// DPR-137: this test existed and named two files, so the agent config the
// evaluation canary actually mounts was never loaded by it — and it shipped
// without apiVersion, which is fatal. The canary crash-looped on config parse
// with no data and nothing pointing at the config file. The cloud-init
// packaging config had the same defect, on the production path.
//
// The list is now DISCOVERED: any YAML under deploy/ whose top level has
// control_plane is an agent config and gets loaded with the real loader, so a
// new one is covered the day it is added rather than the day someone remembers
// to extend a list.
func TestShippedAgentConfigsLoadStrictly(t *testing.T) {
	// The rendered-browser config needs its worker paths faked on a host, and
	// TestShippedRenderedBrowserConfigLoadsStrictly covers it properly.
	skip := map[string]bool{"eval-browser-agent.yml": true}

	var found []string
	root := filepath.Join("..", "..", "deploy")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
			return nil
		}
		if skip[filepath.Base(path)] || strings.Contains(path, string(filepath.Separator)+"templates"+string(filepath.Separator)) {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		var top map[string]any
		if yaml.Unmarshal(b, &top) != nil {
			return nil // not a mapping (multi-doc manifests, etc.)
		}
		if _, ok := top["control_plane"]; !ok {
			return nil
		}
		found = append(found, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk deploy/: %v", err)
	}
	// A discovery that silently finds nothing is the failure mode this replaces.
	// control_plane is what a CANARY agent config has; the device, flow and eBPF
	// agents have their own shapes and their own loaders, so they are not here.
	if len(found) < 3 {
		t.Fatalf("discovered only %d shipped agent configs (%v) — discovery is broken, not the tree", len(found), found)
	}
	var sawEval bool
	for _, path := range found {
		if filepath.Base(path) == "eval-agent.yml" {
			sawEval = true
		}
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
	if !sawEval {
		t.Error("the evaluation canary's own config must be among the discovered ones — it is the config a new reader runs first")
	}
}

// The cloud-init packaging file embeds an agent config inside write_files, so
// discovery cannot see it as YAML. It is a production path and shipped without
// apiVersion too (DPR-137), so it gets loaded from its embedded content.
func TestCloudInitEmbeddedAgentConfigLoadsStrictly(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "packaging", "cloud-init", "probectl-agent.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cloud-init: %v", err)
	}
	var doc struct {
		WriteFiles []struct {
			Path    string `yaml:"path"`
			Content string `yaml:"content"`
		} `yaml:"write_files"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse cloud-init: %v", err)
	}
	var embedded string
	for _, f := range doc.WriteFiles {
		if strings.Contains(f.Path, "agent.yaml") || strings.Contains(f.Path, "agent.yml") {
			embedded = f.Content
		}
	}
	if embedded == "" {
		t.Fatal("cloud-init no longer writes an agent config; update this test with it")
	}
	out := filepath.Join(t.TempDir(), "agent.yml")
	if err := os.WriteFile(out, []byte(embedded), 0o600); err != nil {
		t.Fatalf("write embedded config: %v", err)
	}
	cfg, err := Load(out)
	if err != nil {
		t.Fatalf("the config cloud-init writes must load: %v", err)
	}
	if cfg.APIVersion != ConfigAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", cfg.APIVersion, ConfigAPIVersion)
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

func TestConfigLoadsDurableS3ArtifactStore(t *testing.T) {
	t.Setenv("PROBECTL_AGENT_OBJECTSTORE_MODE", "s3")
	t.Setenv("PROBECTL_AGENT_OBJECTSTORE_S3_ENDPOINT", "https://minio.example")
	t.Setenv("PROBECTL_AGENT_OBJECTSTORE_S3_BUCKET", "artifacts")
	t.Setenv("PROBECTL_AGENT_OBJECTSTORE_S3_ACCESS_KEY", "access")
	t.Setenv("PROBECTL_AGENT_OBJECTSTORE_S3_SECRET_KEY", "secret")
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
	if cfg.ArtifactStore.Mode != "s3" || cfg.ArtifactStore.Endpoint != "https://minio.example" || cfg.ArtifactStore.Bucket != "artifacts" {
		t.Fatalf("artifact store = %+v", cfg.ArtifactStore)
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
