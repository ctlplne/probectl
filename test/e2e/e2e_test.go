// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package e2e holds probectl's BLACK-BOX full-stack end-to-end tests
// (U-054): real binaries built from this tree, the real compose
// dependencies, and only public interfaces — process env/flags, the bus,
// and the versioned REST API. No internal packages are imported, by
// design.
//
// The happy paths + tenancy boundary:
//
//	compose up (postgres+kafka) → build probectl-control + agents →
//	boot HTTPS + agent mTLS → redeem a one-time join token for a
//	tenant-bound SVID → run a real noop canary over mTLS → assert its
//	result through /v1/results/latest → run TWO fixture-mode eBPF agents
//	(tenant A and tenant B, disjoint traffic) → flows ride Kafka → query
//	/v1/topology per tenant → assert no result or topology bleed → teardown.
//
// Gated on PROBECTL_E2E=1 (the nightly e2e workflow sets it; `go test
// ./test/...` stays a no-op skip everywhere else).
package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tenantA        = "00000000-0000-0000-0000-000000000001" // the seeded default tenant
	tenantB        = "00000000-0000-0000-0000-00000000e2e2"
	agentAID       = "a7000000-0000-4000-8000-000000000001"
	agentBID       = "a7000000-0000-4000-8000-000000000002"
	canaryAgentID  = "a7000000-0000-4000-8000-000000000003"
	expiredAgentID = "a7000000-0000-4000-8000-000000000004"
	plainAgentID   = "a7000000-0000-4000-8000-000000000005"
	canaryTarget   = "e2e-mtls-noop"
	laneA          = "t-e2e-a"
	laneB          = "t-e2e-b"
	ipOnlyA        = "10.77.1.9"  // appears only in tenant A's traffic
	ipOnlyB        = "10.88.2.10" // appears only in tenant B's traffic
	composeF       = "deploy/compose/dev.yml"
	composeIsoF    = "deploy/compose/isolated.yml"
)

func TestE2E(t *testing.T) {
	if os.Getenv("PROBECTL_E2E") != "1" {
		t.Skip("set PROBECTL_E2E=1 to run the full-stack e2e (nightly ci job; needs docker)")
	}
	root := repoRoot(t)
	work := t.TempDir()
	composeFile := filepath.Join(root, composeF)
	composeIsoFile := filepath.Join(root, composeIsoF)
	composeProject := fmt.Sprintf("probectl-e2e-%d-%d", os.Getpid(), time.Now().UnixNano())
	composeEnv := []string{"PROBECTL_ISOLATED_NETWORK=" + composeProject + "-network"}

	// ── stack up ────────────────────────────────────────────────────────
	// The black-box receipt must be repeatable on a developer workstation where
	// the shared dev stack may already have data. A unique Compose project gives
	// this run empty, disposable volumes without ever targeting the developer's
	// probectl-dev project during setup or teardown.
	runCmd(t, root, composeEnv, "docker", composeArgs(composeProject, composeFile, composeIsoFile,
		"up", "-d", "--wait", "postgres", "kafka")...)
	t.Cleanup(func() {
		cmd := exec.Command("docker", composeArgs(composeProject, composeFile, composeIsoFile,
			"down", "-v", "--remove-orphans")...)
		cmd.Env = append(os.Environ(), composeEnv...)
		_ = cmd.Run()
	})
	createKafkaTopics(t, root, composeEnv, composeProject, composeFile, composeIsoFile,
		"probectl."+laneA+".ebpf.flows",
		"probectl."+laneB+".ebpf.flows",
		"probectl."+laneA+".network.results",
		"probectl."+laneB+".network.results",
	)

	// ── build the real binaries from this tree ──────────────────────────
	control := filepath.Join(work, "probectl-control")
	ebpfAgent := filepath.Join(work, "probectl-ebpf-agent")
	canaryAgent := filepath.Join(work, "probectl-agent")
	licenseTool := filepath.Join(work, "probectl-license")
	licensePriv := filepath.Join(work, "license-signing.key")
	licensePub := filepath.Join(work, "license-signing.pub")
	licenseFile := filepath.Join(work, "probectl-license.json")

	runCmd(t, root, nil, "go", "build", "-o", licenseTool, "./cmd/probectl-license")
	runCmd(t, root, nil, licenseTool, "gen-key", "-out-priv", licensePriv, "-out-pub", licensePub)
	runCmd(t, root, nil, licenseTool, "sign",
		"-key", licensePriv,
		"-customer", "probectl e2e",
		"-tier", "msp",
		"-tenant-band", "4",
		"-expires", time.Now().UTC().AddDate(1, 0, 0).Format("2006-01-02"),
		"-out", licenseFile)
	pubPEM, err := os.ReadFile(licensePub)
	if err != nil {
		t.Fatal(err)
	}
	licenseLDFlags := "-X github.com/ctlplne/probectl/internal/license.builtinPubKeysB64=" +
		base64.StdEncoding.EncodeToString(pubPEM)

	runCmd(t, root, nil, "go", "build", "-tags", "devauth", "-ldflags", licenseLDFlags, "-o", control, "./cmd/probectl-control")
	runCmd(t, root, nil, "go", "build", "-o", ebpfAgent, "./cmd/probectl-ebpf-agent")
	runCmd(t, root, nil, "go", "build", "-o", canaryAgent, "./cmd/probectl-agent")

	serverTLSDir := filepath.Join(work, "server-tls")
	runCmd(t, root, nil, control, "gen-cert", serverTLSDir)
	serverCert := filepath.Join(serverTLSDir, "tls.crt")
	serverKey := filepath.Join(serverTLSDir, "tls.key")
	serverCA := filepath.Join(serverTLSDir, "ca.crt")
	irPublicDir := filepath.Join(work, "ir-public")
	wormDir := filepath.Join(work, "audit-worm")
	for _, dir := range []string{irPublicDir, wormDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create e2e security directory %s: %v", dir, err)
		}
	}
	wormSigningKey := filepath.Join(wormDir, "signing-key.pem")

	controlEnv := []string{
		"PROBECTL_DATABASE_URL=postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable",
		"PROBECTL_HTTP_ADDR=127.0.0.1:0", // loopback posture for offline CLI subcommands
		"PROBECTL_AUTH_MODE=dev",
		"PROBECTL_DEV_AUTH_ACK=i-understand",
		"PROBECTL_ENVELOPE_KEY_ID=e2e",
		"PROBECTL_ENVELOPE_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", // test-only 32-byte KEK
		"PROBECTL_AUDIT_WORM_DIR=" + wormDir,
		"PROBECTL_WORM_SIGNING_KEY_FILE=" + wormSigningKey,
		"PROBECTL_IR_PUBLIC_KEY_DIR=" + irPublicDir,
		"PROBECTL_LICENSE_FILE=" + licenseFile,
		"PROBECTL_PATHSTORE_TENANT_SCOPING=true",
		"PROBECTL_FLOWSTORE_TENANT_SCOPING=true",
		"PROBECTL_OTELSTORE_TENANT_SCOPING=true",
		"PROBECTL_EBPFSTORE_TENANT_SCOPING=true",
		"PROBECTL_ENDPOINTSTORE_TENANT_SCOPING=true",
		"PROBECTL_INGEST_STRICT_TENANT_LANES=true",
		"PROBECTL_BUS_MODE=kafka",
		"PROBECTL_BUS_BROKERS=localhost:9092",
		"PROBECTL_BUS_ALLOW_PLAINTEXT=true", // dev compose kafka is plaintext (U-010 dev override)
	}

	// ── schema: the serve path checks DB-level tenant isolation before listen ─
	runCmd(t, root, controlEnv, control, "migrate")
	seedE2ETenants(t, root, composeEnv, composeProject, composeFile, composeIsoFile)
	// DPR-121 hardened `agent-ca init` to refuse printing the root CA private key
	// to a non-terminal, because a Job log or a CI artifact is exactly where
	// docs/guardrails.md G7-6 says a private key must never land — and `go test`
	// stdout is a non-terminal. The key goes to a file under the test's temp dir,
	// the same way deploy/compose/eval-synthetic.yml bootstraps it. This caller was
	// missed when that landed, which is why nightly e2e had been red (DPR-270).
	agentCARootKey := filepath.Join(work, "agent-ca-root.key")
	runCmd(t, root, controlEnv, control, "agent-ca", "init", "-key-out", agentCARootKey)
	agentCABundle := filepath.Join(work, "agent-ca.crt")
	runCmd(t, root, controlEnv, control, "agent-ca", "export", agentCABundle)
	registerCollector(t, root, control, controlEnv, tenantA, agentAID, "agent-a")
	registerCollector(t, root, control, controlEnv, tenantB, agentBID, "agent-b")
	canaryToken := mintEnrollToken(t, root, control, controlEnv, tenantA, canaryAgentID, "e2e-canary")
	apiAddr := freeTCPAddr(t)
	apiBase := "https://" + apiAddr
	agentGRPCAddr := freeTCPAddr(t)

	serveEnv := append(setEnv(controlEnv, "PROBECTL_HTTP_ADDR", apiAddr),
		"PROBECTL_TLS_CERT_FILE="+serverCert,
		"PROBECTL_TLS_KEY_FILE="+serverKey,
		"PROBECTL_AGENT_GRPC_ADDR="+agentGRPCAddr,
		"PROBECTL_AGENT_TLS_CERT_FILE="+serverCert,
		"PROBECTL_AGENT_TLS_KEY_FILE="+serverKey,
		"PROBECTL_AGENT_TLS_CA_FILE="+agentCABundle,
	)
	apiClient := newAPIClient(t, serverCA)

	// ── control plane: public configuration surface only ────────────────
	controlLog, _ := startProc(t, work, "control", control, nil, serveEnv)
	waitFor(t, "control plane /readyz", 90*time.Second, func() bool {
		resp, err := apiClient.Get(apiBase + "/readyz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	if body := isolationJSON(t, apiClient, apiBase, tenantA); !strings.Contains(body, `"mode":"tenant_namespaced"`) || !strings.Contains(body, laneA) {
		t.Fatalf("tenant A isolation status did not report the expected namespaced lane %s:\n%s", laneA, body)
	}

	// First contact fails closed without trust and over plaintext. Neither
	// attempt may consume its single-use token.
	runCmdMustFail(t, root, nil, canaryAgent,
		"enroll", "--server", apiBase, "--token", canaryToken,
		"--dir", filepath.Join(work, "missing-ca-identity"), "--hostname", "missing-ca")
	plainToken := mintEnrollTokenTTL(t, root, control, controlEnv, tenantA, plainAgentID, "plaintext-refused", "10m")
	runCmdMustFail(t, root, nil, canaryAgent,
		"enroll", "--server", "http://"+apiAddr, "--token", plainToken,
		"--dir", filepath.Join(work, "plaintext-identity"), "--hostname", "plaintext-refused")
	plainEnrollOut := runCmdOutput(t, root, nil, canaryAgent,
		"enroll", "--server", apiBase, "--token", plainToken,
		"--dir", filepath.Join(work, "plaintext-identity"), "--ca-file", serverCA,
		"--hostname", "plaintext-refused")
	if !strings.Contains(plainEnrollOut, cryptoSPIFFE(tenantA, plainAgentID)) {
		t.Fatal("plaintext refusal consumed or changed the tenant-bound enrollment token")
	}
	// ── two fixture-mode agents, one per tenant, disjoint traffic ───────
	// ── real canary agent: join token → SVID → mTLS → result API ──────
	// The real canary path runs first; the fixture agents follow it.
	identityDir := filepath.Join(work, "canary-identity")
	enrollOut := runCmdOutput(t, root, nil, canaryAgent, "enroll",
		"--server", apiBase,
		"--token", canaryToken,
		"--dir", identityDir,
		"--ca-file", serverCA,
		"--hostname", "e2e-canary")
	wantSPIFFE := "spiffe://probectl/tenant/" + tenantA + "/agent/" + canaryAgentID
	if !strings.Contains(enrollOut, wantSPIFFE) {
		t.Fatalf("agent enrollment did not return the expected tenant-bound SVID %s:\n%s", wantSPIFFE, enrollOut)
	}
	canaryConfig := filepath.Join(work, "canary-agent.yaml")
	writeFile(t, canaryConfig, fmt.Sprintf(`apiVersion: probectl.io/agent/v1
control_plane:
  grpc_addr: %q
tls:
  cert_file: %q
  key_file: %q
  ca_file: %q
  server_name: "localhost"
agent:
  hostname: "e2e-canary"
  capabilities: ["noop"]
  heartbeat_interval: 1s
buffer:
  dir: %q
  max_records: 100
  drain_pace: 100ms
canaries:
  - type: noop
    target: %q
    interval: 1s
    timeout: 1s
`, agentGRPCAddr,
		filepath.Join(identityDir, "cert.pem"),
		filepath.Join(identityDir, "key.pem"),
		serverCA,
		filepath.Join(work, "canary-buffer"),
		canaryTarget))
	_, stopCanary := startProc(t, work, "canary-agent", canaryAgent, []string{"-config", canaryConfig}, nil)

	var firstObserved time.Time
	waitFor(t, "tenant A's mTLS canary in /v1/results/latest", 90*time.Second, func() bool {
		var ok bool
		firstObserved, ok = latestResultObservedAt(t, apiClient, apiBase, tenantA, canaryAgentID, "noop", canaryTarget)
		return ok
	})
	if latestResultsContains(t, apiClient, apiBase, tenantB, canaryAgentID, "noop", canaryTarget) {
		t.Fatalf("CROSS-TENANT LEAK: tenant B can read tenant A's mTLS canary result (%s/%s)", canaryAgentID, canaryTarget)
	}

	// Force a public-binary rotation, preserving the SPIFFE identity while the
	// leaf fingerprint changes, then prove the rotated credential reconnects.
	stopCanary()
	beforeSerial, beforeSPIFFE := certificateIdentity(t, filepath.Join(identityDir, "cert.pem"))
	runCmd(t, root, nil, canaryAgent, "rotate", "--server", apiBase, "--dir", identityDir, "--ca-file", serverCA)
	afterSerial, afterSPIFFE := certificateIdentity(t, filepath.Join(identityDir, "cert.pem"))
	if beforeSerial == afterSerial || beforeSPIFFE != afterSPIFFE || afterSPIFFE != wantSPIFFE {
		t.Fatalf("rotation identity mismatch: before=(%s,%s) after=(%s,%s)",
			beforeSerial, beforeSPIFFE, afterSerial, afterSPIFFE)
	}
	_, stopRotated := startProc(t, work, "canary-agent-rotated", canaryAgent, []string{"-config", canaryConfig}, nil)
	var rotatedObserved time.Time
	waitFor(t, "rotated mTLS identity to publish a newer result", 30*time.Second, func() bool {
		var ok bool
		rotatedObserved, ok = latestResultObservedAt(t, apiClient, apiBase, tenantA, canaryAgentID, "noop", canaryTarget)
		return ok && rotatedObserved.After(firstObserved)
	})

	// API revocation pushes the serial/SPIFFE deny-list into the live gRPC
	// listener. A reconnect and a further rotation both fail, and no newer
	// result is persisted for the revoked identity.
	revokeAgent(t, apiClient, apiBase, tenantA, canaryAgentID)
	stopRotated()
	runCmdMustFail(t, root, nil, canaryAgent, "rotate", "--server", apiBase, "--dir", identityDir, "--ca-file", serverCA)
	startProc(t, work, "canary-agent-revoked", canaryAgent, []string{"-config", canaryConfig}, nil)
	time.Sleep(3 * time.Second)
	revokedObserved, ok := latestResultObservedAt(t, apiClient, apiBase, tenantA, canaryAgentID, "noop", canaryTarget)
	if !ok || revokedObserved.After(rotatedObserved) {
		t.Fatalf("revoked identity persisted a newer result: before=%s after=%s", rotatedObserved, revokedObserved)
	}

	// Deliberately failing, server-reaching enrollment cases run only after
	// the valid lifecycle is complete. They still exercise the real auth
	// limiter, without allowing an expected lockout to mask rotation/revocation.
	// A redeemed token is immutable history, never a reusable credential.
	runCmdMustFail(t, root, nil, canaryAgent,
		"enroll", "--server", apiBase, "--token", canaryToken,
		"--dir", filepath.Join(work, "replay-identity"), "--ca-file", serverCA,
		"--hostname", "replay-refused")
	expiredToken := mintEnrollTokenTTL(t, root, control, controlEnv, tenantA, expiredAgentID, "expired-token", "1ms")
	time.Sleep(20 * time.Millisecond)
	runCmdMustFail(t, root, nil, canaryAgent,
		"enroll", "--server", apiBase, "--token", expiredToken,
		"--dir", filepath.Join(work, "expired-identity"), "--ca-file", serverCA,
		"--hostname", "expired-token")

	// Two fixture-mode agents now exercise tenant-namespaced flow ingestion.
	for _, a := range []struct{ tenant, ip, name, agentID, lane string }{
		{tenantA, ipOnlyA, "agent-a", agentAID, laneA},
		{tenantB, ipOnlyB, "agent-b", agentBID, laneB},
	} {
		fixture := writeFixture(t, work, a.name, a.tenant, a.agentID, a.ip)
		cfg := filepath.Join(work, a.name+".yaml")
		writeFile(t, cfg, fmt.Sprintf(
			"apiVersion: probectl.io/ebpf-agent/v1\ntenant_id: %q\nhost: %q\nfixture_path: %q\nbus:\n  mode: kafka\n  brokers: [\"localhost:9092\"]\n  namespace: %q\n",
			a.tenant, a.agentID, fixture, a.lane))
		startProc(t, work, a.name, ebpfAgent, []string{"--config", cfg}, []string{
			"PROBECTL_EBPF_BUS_ALLOW_PLAINTEXT=true",
		})
	}
	t.Cleanup(func() {
		if t.Failed() {
			dumpKafkaDiagnostics(t, root, composeEnv, composeProject, composeFile, composeIsoFile)
		}
	})

	// ── ingest lands: each tenant's edge appears via the PUBLIC API ─────
	waitFor(t, "tenant A's edge in /v1/topology", 90*time.Second, func() bool {
		return strings.Contains(topologyJSON(t, apiClient, apiBase, tenantA), ipOnlyA)
	})
	waitFor(t, "tenant B's edge in /v1/topology", 90*time.Second, func() bool {
		return strings.Contains(topologyJSON(t, apiClient, apiBase, tenantB), ipOnlyB)
	})

	// ── the tenancy boundary: no bleed in either direction ──────────────
	if body := topologyJSON(t, apiClient, apiBase, tenantA); strings.Contains(body, ipOnlyB) {
		t.Fatalf("CROSS-TENANT LEAK: tenant A's topology contains tenant B's endpoint %s:\n%s", ipOnlyB, body)
	}
	if body := topologyJSON(t, apiClient, apiBase, tenantB); strings.Contains(body, ipOnlyA) {
		t.Fatalf("CROSS-TENANT LEAK: tenant B's topology contains tenant A's endpoint %s:\n%s", ipOnlyA, body)
	}

	// And a malformed tenant override is rejected, not defaulted (dev-mode
	// fail-closed contract).
	req, _ := http.NewRequest(http.MethodGet, apiBase+"/v1/topology", nil)
	req.Header.Set("X-Probectl-Tenant", "not-a-uuid")
	resp, err := apiClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed tenant override returned %d, want 400", resp.StatusCode)
	}

	t.Logf("e2e PASS: join token -> tenant-bound SVID -> mTLS canary -> public result API; flow ingest is tenant-scoped and isolation holds both ways (control log: %s)", controlLog)
}

// ── helpers (stdlib only — this module stays dependency-free) ───────────

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, composeF)); err != nil {
		t.Fatalf("repo root not found from %s: %v", wd, err)
	}
	return root
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate loopback test port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback test port %s: %v", addr, err)
	}
	return addr
}

func setEnv(env []string, key, value string) []string {
	result := append([]string(nil), env...)
	prefix := key + "="
	for index, item := range result {
		if strings.HasPrefix(item, prefix) {
			result[index] = prefix + value
			return result
		}
	}
	return append(result, prefix+value)
}

func runCmd(t *testing.T, dir string, env []string, name string, args ...string) {
	t.Helper()
	_ = runCmdOutput(t, dir, env, name, args...)
}

func runCmdOutput(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", redactedCommand(name, args), err, redactCommandOutput(out, args))
	}
	return string(out)
}

func runCmdMustFail(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded", redactedCommand(name, args))
	}
	return string(redactCommandOutput(out, args))
}

func redactedCommand(name string, args []string) string {
	redacted := append([]string(nil), args...)
	for i := 0; i+1 < len(redacted); i++ {
		if redacted[i] == "--token" || redacted[i] == "-token" {
			redacted[i+1] = "[redacted]"
		}
	}
	return name + " " + strings.Join(redacted, " ")
}

func redactCommandOutput(out []byte, args []string) []byte {
	redacted := append([]byte(nil), out...)
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--token" || args[i] == "-token" {
			redacted = []byte(strings.ReplaceAll(string(redacted), args[i+1], "[redacted]"))
		}
	}
	return redacted
}

func composeArgs(project, file, isolatedFile string, args ...string) []string {
	base := []string{"compose", "--project-name", project, "-f", file, "-f", isolatedFile}
	return append(base, args...)
}

func TestComposeArgsScopesDisposableProject(t *testing.T) {
	t.Parallel()
	got := composeArgs("probectl-e2e-123", "/tmp/dev.yml", "/tmp/isolated.yml", "down", "-v")
	want := []string{
		"compose", "--project-name", "probectl-e2e-123", "-f", "/tmp/dev.yml", "-f", "/tmp/isolated.yml", "down", "-v",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("compose args = %q, want %q", got, want)
	}
}

func seedE2ETenants(t *testing.T, root string, composeEnv []string, composeProject, composeFile, composeIsoFile string) {
	t.Helper()
	sql := fmt.Sprintf(`INSERT INTO tenants (id, slug, name, status, isolation_model)
VALUES
  ('%s', 'e2e-a', 'E2E Tenant A', 'active', 'hybrid'),
  ('%s', 'e2e-b', 'E2E Tenant B', 'active', 'hybrid')
ON CONFLICT (id) DO UPDATE
SET slug = EXCLUDED.slug,
    name = EXCLUDED.name,
    status = EXCLUDED.status,
    isolation_model = EXCLUDED.isolation_model,
    updated_at = now()`, tenantA, tenantB)
	runCmd(t, root, composeEnv, "docker", composeArgs(composeProject, composeFile, composeIsoFile, "exec", "-T",
		"postgres", "psql", "-U", "probectl", "-d", "probectl",
		"-v", "ON_ERROR_STOP=1", "-c", sql)...)
}

func registerCollector(t *testing.T, root, control string, env []string, tenant, agentID, name string) {
	t.Helper()
	token := mintEnrollToken(t, root, control, env, tenant, agentID, name)
	regOut := runCmdOutput(t, root, env, control,
		"register-collector", "-token", token, "-plane", "ebpf", "-hostname", name)
	if !strings.Contains(regOut, agentID) || !strings.Contains(regOut, tenant) {
		t.Fatalf("collector registration did not bind expected tenant/agent (%s/%s):\n%s", tenant, agentID, regOut)
	}
}

func mintEnrollToken(t *testing.T, root, control string, env []string, tenant, agentID, name string) string {
	return mintEnrollTokenTTL(t, root, control, env, tenant, agentID, name, "10m")
}

func mintEnrollTokenTTL(t *testing.T, root, control string, env []string, tenant, agentID, name, ttl string) string {
	t.Helper()
	tokenOut := runCmdOutput(t, root, env, control,
		"enroll-token", "-tenant", tenant, "-agent", agentID, "-name", name, "-ttl", ttl)
	token := ""
	for _, line := range strings.Split(tokenOut, "\n") {
		if candidate := strings.TrimSpace(line); strings.HasPrefix(candidate, "pjt_") {
			token = candidate
			break
		}
	}
	if token == "" {
		t.Fatal("enroll-token did not print a display token")
	}
	return token
}

func createKafkaTopics(t *testing.T, root string, composeEnv []string, composeProject, composeFile, composeIsoFile string, topics ...string) {
	t.Helper()
	for _, topic := range topics {
		runCmd(t, root, composeEnv, "docker", composeArgs(composeProject, composeFile, composeIsoFile, "exec", "-T", "kafka",
			"/opt/kafka/bin/kafka-topics.sh",
			"--bootstrap-server", "localhost:9092",
			"--create",
			"--if-not-exists",
			"--topic", topic,
			"--partitions", "3",
			"--replication-factor", "1")...)
	}
}

func dumpKafkaDiagnostics(t *testing.T, root string, composeEnv []string, composeProject, composeFile, composeIsoFile string) {
	t.Helper()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "topics", args: []string{"/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", "localhost:9092", "--list"}},
		{name: "consumer-groups", args: []string{"/opt/kafka/bin/kafka-consumer-groups.sh", "--bootstrap-server", "localhost:9092", "--all-groups", "--describe"}},
		{name: "tenant-a-ebpf-offsets", args: []string{"/opt/kafka/bin/kafka-get-offsets.sh", "--bootstrap-server", "localhost:9092", "--topic", "probectl." + laneA + ".ebpf.flows"}},
		{name: "tenant-b-ebpf-offsets", args: []string{"/opt/kafka/bin/kafka-get-offsets.sh", "--bootstrap-server", "localhost:9092", "--topic", "probectl." + laneB + ".ebpf.flows"}},
		{name: "tenant-a-result-offsets", args: []string{"/opt/kafka/bin/kafka-get-offsets.sh", "--bootstrap-server", "localhost:9092", "--topic", "probectl." + laneA + ".network.results"}},
		{name: "tenant-b-result-offsets", args: []string{"/opt/kafka/bin/kafka-get-offsets.sh", "--bootstrap-server", "localhost:9092", "--topic", "probectl." + laneB + ".network.results"}},
	} {
		args := composeArgs(composeProject, composeFile, composeIsoFile, append([]string{"exec", "-T", "kafka"}, tc.args...)...)
		cmd := exec.Command("docker", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), composeEnv...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("---- kafka %s failed ----\n%v\n%s", tc.name, err, out)
			continue
		}
		t.Logf("---- kafka %s ----\n%s", tc.name, out)
	}
}

// startProc launches a long-running binary, captures its output to a log
// file, and guarantees teardown. Returns the log path for diagnostics.
func startProc(t *testing.T, work, name, bin string, args, env []string) (string, func()) {
	t.Helper()
	logPath := filepath.Join(work, name+".log")
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = append(os.Environ(), env...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			_ = logf.Close()
		})
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			if b, err := os.ReadFile(logPath); err == nil {
				logText := string(b)
				if name == "control" {
					var kept []string
					for _, line := range strings.Split(logText, "\n") {
						if !strings.Contains(line, `"msg":"request"`) {
							kept = append(kept, line)
						}
					}
					logText = strings.Join(kept, "\n")
				}
				tail := []byte(logText)
				if len(tail) > 32768 {
					tail = tail[len(tail)-32768:]
				}
				t.Logf("---- %s log tail ----\n%s", name, tail)
			}
		}
	})
	return logPath, stop
}

func waitFor(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

func newAPIClient(t *testing.T, caFile string) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("API CA file %s contains no certificates", caFile)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		}},
	}
}

// topologyJSON fetches /v1/topology as the given tenant (dev-auth header)
// and returns the raw body (valid JSON asserted).
func topologyJSON(t *testing.T, client *http.Client, apiBase, tenant string) string {
	t.Helper()
	return getTenantJSON(t, client, apiBase, tenant, "/v1/topology")
}

func isolationJSON(t *testing.T, client *http.Client, apiBase, tenant string) string {
	t.Helper()
	return getTenantJSON(t, client, apiBase, tenant, "/v1/isolation/status")
}

func getTenantJSON(t *testing.T, client *http.Client, apiBase, tenant, path string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, apiBase+path, nil)
	req.Header.Set("X-Probectl-Tenant", tenant)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s query: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s query for %s: %d: %s", path, tenant, resp.StatusCode, body)
	}
	if !json.Valid(body) {
		t.Fatalf("%s response is not JSON: %s", path, body)
	}
	return string(body)
}

func latestResultsContains(t *testing.T, client *http.Client, apiBase, tenant, agentID, canaryType, target string) bool {
	_, ok := latestResultObservedAt(t, client, apiBase, tenant, agentID, canaryType, target)
	return ok
}

func latestResultObservedAt(t *testing.T, client *http.Client, apiBase, tenant, agentID, canaryType, target string) (time.Time, bool) {
	t.Helper()
	var response struct {
		Items []struct {
			AgentID    string    `json:"agent_id"`
			Type       string    `json:"type"`
			Target     string    `json:"target"`
			Success    bool      `json:"success"`
			ObservedAt time.Time `json:"observed_at"`
		} `json:"items"`
	}
	body := getTenantJSON(t, client, apiBase, tenant, "/v1/results/latest")
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatalf("decode /v1/results/latest for %s: %v", tenant, err)
	}
	for _, item := range response.Items {
		if item.AgentID == agentID && item.Type == canaryType && item.Target == target && item.Success {
			return item.ObservedAt, true
		}
	}
	return time.Time{}, false
}

func certificateIdentity(t *testing.T, path string) (serial, spiffeID string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity certificate: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("identity certificate has no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse identity certificate: %v", err)
	}
	if len(cert.URIs) != 1 {
		t.Fatalf("identity certificate URI SANs = %d, want 1", len(cert.URIs))
	}
	return cert.SerialNumber.Text(16), cert.URIs[0].String()
}

func cryptoSPIFFE(tenant, agentID string) string {
	return "spiffe://probectl/tenant/" + tenant + "/agent/" + agentID
}

func revokeAgent(t *testing.T, client *http.Client, apiBase, tenant, agentID string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, apiBase+"/v1/agents/"+agentID+"/revoke", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Probectl-Tenant", tenant)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("revoke agent: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke agent returned %d: %s", resp.StatusCode, body)
	}
}

// writeFixture emits a small recorded-flow file whose endpoints are unique
// to the tenant — the basis of the isolation assertion.
func writeFixture(t *testing.T, work, name, tenant, agentID, ip string) string {
	t.Helper()
	type row struct {
		TenantID  string `json:"tenant_id"`
		AgentID   string `json:"agent_id"`
		Host      string `json:"host"`
		SrcAddr   string `json:"source_address"`
		SrcPort   int    `json:"source_port"`
		SrcPID    int    `json:"source_pid"`
		DstAddr   string `json:"destination_address"`
		DstPort   int    `json:"destination_port"`
		Transport string `json:"network_transport"`
		NetType   string `json:"network_type"`
		Bytes     int    `json:"bytes"`
		Packets   int    `json:"packets"`
		Direction string `json:"direction"`
		State     string `json:"state"`
	}
	rows := make([]row, 0, 6)
	for i := 0; i < 6; i++ {
		rows = append(rows, row{
			TenantID: tenant, AgentID: agentID, Host: name + "-host",
			SrcAddr: "10.50.0.5", SrcPort: 40000 + i, SrcPID: 4242,
			DstAddr: ip, DstPort: 443,
			Transport: "tcp", NetType: "ipv4",
			Bytes: 1024 * (i + 1), Packets: 8, Direction: "egress", State: "established",
		})
	}
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(work, name+"-flows.json")
	writeFile(t, path, string(b))
	return path
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
