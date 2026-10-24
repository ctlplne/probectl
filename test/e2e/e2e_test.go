// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package e2e holds probectl's BLACK-BOX full-stack end-to-end test (U-054,
// TQ-03): the control plane is the RELEASE IMAGE, built from
// deploy/docker/Dockerfile exactly as CI's build-images and image-scan jobs
// build it (core edition, no build tags) and run the way the shipped Compose
// stack runs it, in its production auth mode. Only public interfaces are used
// — container env and flags, the bus, the versioned REST API and the IdP's own
// sign-in form. No internal packages are imported, by design.
//
// The happy paths + tenancy boundary:
//
//	build the release image → certgen (localhost, postgres SANs) → compose up
//	Postgres (TLS) + Kafka → migrate as the owner login, serve as the
//	least-privilege login over sslmode=verify-full → start Dex (real OIDC) →
//	sign tenant A's and tenant B's admins in through Dex's password form and
//	mint API tokens from those sessions → each tenant writes tests and alert
//	rules over HTTPS → each sees only its own; the other tenant's object ids
//	answer 404 for read, update and delete → redeem a one-time join token for
//	a tenant-bound SVID → run a real noop canary over mTLS → assert its result
//	through /v1/results/latest → rotate, revoke → run TWO fixture-mode eBPF
//	agents (disjoint traffic) → flows ride Kafka → query /v1/topology per
//	tenant → any cross-tenant visibility fails the test → teardown.
//
// Gated on PROBECTL_E2E=1 (ci.yml's e2e job and the nightly set it; `go test
// ./test/...` stays a no-op skip everywhere else).
package e2e

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	adminA         = "ada@acme.example"   // a scripts/ci_dex.sh password user
	adminB         = "bob@globex.example" // another, in no tenant but B
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
	apiListen      = "8443" // the control container's HTTPS listener
	agentListen    = "9443" // and its agent mTLS listener
)

// tokenScopes is what each tenant admin's API token may do: exactly the
// routes this test drives, nothing more.
var tokenScopes = []string{
	"tenant.read", "test.read", "test.write", "alert.read", "alert.write",
	"agent.read", "agent.write", "topology.read",
}

func TestE2E(t *testing.T) {
	if os.Getenv("PROBECTL_E2E") != "1" {
		t.Skip("set PROBECTL_E2E=1 to run the full-stack e2e (ci + nightly job; needs docker)")
	}
	root := repoRoot(t)
	// The work directory is bind-mounted into the control containers; resolve
	// symlinks (macOS /var → /private/var) so the daemon sees a real path.
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prefix := envOr("PROBECTL_E2E_NAME_PREFIX", "probectl-e2e")
	project := fmt.Sprintf("%s-%d-%d", prefix, os.Getpid(), time.Now().UnixNano())
	network := project + "-network"

	// ── the release image, and its certgen ──────────────────────────────
	ctl := &controlImage{image: releaseImage(t, root, project), network: network, work: work, project: project}
	tlsDir := mkdir(t, work, "tls")
	ctl.oneShot(t, "none", nil, []string{"PROBECTL_CERT_HOSTS=localhost,127.0.0.1,postgres"},
		"gen-cert", ctl.path(t, tlsDir))
	serverCA := filepath.Join(tlsDir, "ca.crt")

	// ── stack up ────────────────────────────────────────────────────────
	// A unique Compose project gives this run empty, disposable volumes and its
	// own network, never the developer's probectl-dev project. Postgres serves
	// TLS with the certgen bundle, exactly as deploy/compose/probectl.yml does.
	pgPort, kafkaPort := freeTCPPort(t), freeTCPPort(t)
	stack := composeStack{project: project, env: []string{
		"PROBECTL_ISOLATED_NETWORK=" + network,
		"PROBECTL_DEV_POSTGRES_PORT=" + pgPort,
		"PROBECTL_DEV_KAFKA_PORT=" + kafkaPort,
		"PROBECTL_E2E_TLS_DIR=" + tlsDir,
	}}
	overrideFile := filepath.Join(work, "e2e-override.yml")
	writeFile(t, overrideFile, composeOverride)
	stack.files = []string{filepath.Join(root, composeF), filepath.Join(root, composeIsoF), overrideFile}
	t.Cleanup(func() {
		cmd := exec.Command("docker", stack.args("down", "-v", "--remove-orphans")...)
		cmd.Env = append(os.Environ(), stack.env...)
		_ = cmd.Run()
	})
	runCmd(t, root, stack.env, "docker", stack.args("up", "-d", "--wait", "postgres", "kafka")...)
	createKafkaTopics(t, root, stack,
		"probectl."+laneA+".ebpf.flows",
		"probectl."+laneB+".ebpf.flows",
		"probectl."+laneA+".network.results",
		"probectl."+laneB+".network.results",
	)

	// ── the real IdP, on the stack's network ────────────────────────────
	apiPort, agentPort := freeTCPPort(t), freeTCPPort(t)
	apiBase := "https://localhost:" + apiPort
	dexDir := mkdir(t, work, "dex")
	dex := startDex(t, root, dexDir, network, project+"-dex", apiBase+"/auth/callback")

	// ── control-plane configuration: the production auth mode ───────────
	// TEN-01: serve as the least-privilege login, migrate as the owner; both
	// over TLS with chain + hostname verification against the certgen CA.
	pgTLS := "@postgres:5432/probectl?sslmode=verify-full&sslrootcert=" + ctl.path(t, serverCA)
	state := mkdir(t, work, "state")
	wormDir := mkdir(t, work, "audit-worm")
	base := map[string]string{
		"PROBECTL_DATABASE_URL":               "postgres://probectl_runtime:" + e2eRuntimePassword + pgTLS,
		"PROBECTL_MIGRATE_DATABASE_URL":       "postgres://probectl:probectl" + pgTLS,
		"PROBECTL_HTTP_ADDR":                  ":" + apiListen,
		"PROBECTL_TLS_CERT_FILE":              ctl.path(t, filepath.Join(tlsDir, "tls.crt")),
		"PROBECTL_TLS_KEY_FILE":               ctl.path(t, filepath.Join(tlsDir, "tls.key")),
		"PROBECTL_HSTS_ENABLED":               "true",
		"PROBECTL_AUTH_MODE":                  "session",
		"PROBECTL_SESSION_HMAC_KEY":           randomHex(t, 32),
		"PROBECTL_OIDC_ISSUER":                dex["PROBECTL_TEST_DEX_ISSUER"],
		"PROBECTL_OIDC_CLIENT_ID":             dex["PROBECTL_TEST_DEX_CLIENT_ID"],
		"PROBECTL_OIDC_CLIENT_SECRET":         dex["PROBECTL_TEST_DEX_CLIENT_SECRET"],
		"PROBECTL_OIDC_REDIRECT_URL":          dex["PROBECTL_TEST_DEX_REDIRECT_URL"],
		"PROBECTL_OIDC_CA_FILE":               ctl.path(t, filepath.Join(dexDir, "ca.crt")),
		"PROBECTL_ENVELOPE_KEY_FILE":          ctl.path(t, filepath.Join(state, "envelope.key")),
		"PROBECTL_REQUIRE_AT_REST_ENCRYPTION": "true",
		"PROBECTL_OBJECTSTORE_DIR":            ctl.path(t, filepath.Join(state, "objects")),
		"PROBECTL_EVIDENCE_SIGNING_KEY_FILE":  ctl.path(t, filepath.Join(state, "evidence-signing-ed25519.pem")),
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE":  ctl.path(t, filepath.Join(state, "testsync-signing-ed25519.pem")),
		"PROBECTL_AUDIT_WORM_DIR":             ctl.path(t, wormDir),
		"PROBECTL_WORM_SIGNING_KEY_FILE":      ctl.path(t, filepath.Join(wormDir, "signing-key.pem")),
		"PROBECTL_IR_PUBLIC_KEY_DIR":          ctl.path(t, mkdir(t, work, "ir-public")),
		"PROBECTL_INGEST_STRICT_TENANT_LANES": "true",
		"PROBECTL_BUS_MODE":                   "kafka",
		"PROBECTL_BUS_BROKERS":                kafkaInternalBroker,
		"PROBECTL_BUS_ALLOW_PLAINTEXT":        "true", // dev compose kafka is plaintext, in-network only (U-010 dev override)
		"PROBECTL_LOG_FORMAT":                 "json",
	}
	for _, plane := range []string{"PATHSTORE", "FLOWSTORE", "OTELSTORE", "EBPFSTORE", "ENDPOINTSTORE"} {
		base["PROBECTL_"+plane+"_TENANT_SCOPING"] = "true"
	}
	baseEnv := writeEnvFile(t, filepath.Join(work, "control.env"), base)
	cli := func(args ...string) string {
		t.Helper()
		return ctl.oneShot(t, network, []string{baseEnv}, nil, args...)
	}

	// ── schema, logins, tenants, people, agent CA ───────────────────────
	cli("migrate")
	provisionRuntimeLogin(t, root, stack)
	seedE2ETenants(t, root, stack)
	for _, admin := range []struct{ tenant, email string }{{tenantA, adminA}, {tenantB, adminB}} {
		if out := cli("bootstrap-admin", "-tenant", admin.tenant, "-email", admin.email); !strings.Contains(out, admin.email) {
			t.Fatalf("bootstrap-admin %s in %s:\n%s", admin.email, admin.tenant, out)
		}
	}
	// DPR-121: the agent CA root key goes to a file, never to stdout.
	cli("agent-ca", "init", "-key-out", ctl.path(t, filepath.Join(work, "agent-ca-root.key")))
	agentCABundle := filepath.Join(work, "agent-ca.crt")
	cli("agent-ca", "export", ctl.path(t, agentCABundle))
	registerCollector(t, cli, tenantA, agentAID, "agent-a")
	registerCollector(t, cli, tenantB, agentBID, "agent-b")
	canaryToken := mintEnrollTokenTTL(t, cli, tenantA, canaryAgentID, "e2e-canary", "10m")

	// ── serve ───────────────────────────────────────────────────────────
	serveEnv := writeEnvFile(t, filepath.Join(work, "serve.env"), map[string]string{
		"PROBECTL_AGENT_GRPC_ADDR":     ":" + agentListen,
		"PROBECTL_AGENT_TLS_CERT_FILE": base["PROBECTL_TLS_CERT_FILE"],
		"PROBECTL_AGENT_TLS_KEY_FILE":  base["PROBECTL_TLS_KEY_FILE"],
		"PROBECTL_AGENT_TLS_CA_FILE":   ctl.path(t, agentCABundle),
	})
	controlRunning := ctl.serve(t, []string{baseEnv, serveEnv},
		"127.0.0.1:"+apiPort+":"+apiListen, "127.0.0.1:"+agentPort+":"+agentListen)
	anon := api{base: apiBase, client: newHTTPS(t, nil, serverCA)}
	waitFor(t, "control plane /readyz", 120*time.Second, func() bool {
		controlRunning()
		code, _ := anon.doQuiet(http.MethodGet, "/readyz")
		return code == http.StatusOK
	})

	// ── real credentials: SSO through Dex, then API tokens ──────────────
	caFiles := []string{serverCA, filepath.Join(dexDir, "ca.crt")}
	password := dex["PROBECTL_TEST_DEX_PASSWORD"]
	a := api{base: apiBase, client: anon.client, token: ssoSignIn(t, apiBase, caFiles, tenantA, adminA, password, tokenScopes)}
	b := api{base: apiBase, client: anon.client, token: ssoSignIn(t, apiBase, caFiles, tenantB, adminB, password, tokenScopes)}
	assertUnauthenticated(t, anon, b, tenantA, "")
	// Each tenant's isolation posture is its own and reports the database
	// boundary enforced: RLS forced on a non-bypass serve login.
	for _, c := range []struct {
		a      api
		tenant string
	}{{a, tenantA}, {b, tenantB}} {
		body := c.a.get(t, "/v1/isolation/status")
		if !strings.Contains(body, `"tenant_id":"`+c.tenant+`"`) || !strings.Contains(body, `"enforced":true`) {
			t.Fatalf("tenant %s isolation status is not its own with RLS enforced:\n%s", c.tenant, body)
		}
	}

	// ── two-tenant writes and reads over HTTPS ──────────────────────────
	run := fmt.Sprintf("%x", time.Now().UnixNano())
	objA := writeObjects(t, a, tenantA, "e2e-a-"+run)
	objB := writeObjects(t, b, tenantB, "e2e-b-"+run)
	assertOwnOnly(t, a, objA, objB, b)
	assertOwnOnly(t, b, objB, objA, a)
	assertUnauthenticated(t, anon, b, tenantA, objA.mark)

	agentAndFlows(t, root, work, stack, cli, a, b, apiPort, agentPort, serverCA, canaryToken)

	t.Logf("e2e PASS: release image %s in session auth (Dex OIDC) over HTTPS + verify-full Postgres; "+
		"two tenants' writes and reads stay their own both ways; join token -> SVID -> mTLS canary -> result API; "+
		"flow ingest is tenant-scoped", ctl.image)
}

// agentAndFlows drives the agent planes against the running release image:
// enrollment refusals, the mTLS canary with rotation and revocation, and the
// two tenants' Kafka flow lanes, each read back through the public API.
func agentAndFlows(t *testing.T, root, work string, stack composeStack,
	cli func(...string) string, a, b api, apiPort, agentPort, serverCA, canaryToken string) {
	t.Helper()
	ebpfAgent := filepath.Join(work, "probectl-ebpf-agent")
	canaryAgent := filepath.Join(work, "probectl-agent")
	runCmd(t, root, nil, "go", "build", "-o", ebpfAgent, "./cmd/probectl-ebpf-agent")
	runCmd(t, root, nil, "go", "build", "-o", canaryAgent, "./cmd/probectl-agent")
	enrollBase := "https://127.0.0.1:" + apiPort
	agentGRPCAddr := "127.0.0.1:" + agentPort

	// First contact fails closed without trust and over plaintext. Neither
	// attempt may consume its single-use token.
	runCmdMustFail(t, root, nil, canaryAgent,
		"enroll", "--server", enrollBase, "--token", canaryToken,
		"--dir", filepath.Join(work, "missing-ca-identity"), "--hostname", "missing-ca")
	plainToken := mintEnrollTokenTTL(t, cli, tenantA, plainAgentID, "plaintext-refused", "10m")
	runCmdMustFail(t, root, nil, canaryAgent,
		"enroll", "--server", "http://127.0.0.1:"+apiPort, "--token", plainToken,
		"--dir", filepath.Join(work, "plaintext-identity"), "--hostname", "plaintext-refused")
	plainEnrollOut := runCmdOutput(t, root, nil, canaryAgent,
		"enroll", "--server", enrollBase, "--token", plainToken,
		"--dir", filepath.Join(work, "plaintext-identity"), "--ca-file", serverCA,
		"--hostname", "plaintext-refused")
	if !strings.Contains(plainEnrollOut, cryptoSPIFFE(tenantA, plainAgentID)) {
		t.Fatal("plaintext refusal consumed or changed the tenant-bound enrollment token")
	}

	// ── real canary agent: join token → SVID → mTLS → result API ──────
	identityDir := filepath.Join(work, "canary-identity")
	enrollOut := runCmdOutput(t, root, nil, canaryAgent, "enroll",
		"--server", enrollBase,
		"--token", canaryToken,
		"--dir", identityDir,
		"--ca-file", serverCA,
		"--hostname", "e2e-canary")
	wantSPIFFE := cryptoSPIFFE(tenantA, canaryAgentID)
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
	_, stopCanary, _ := startProc(t, work, "canary-agent", canaryAgent, []string{"-config", canaryConfig}, nil)

	var firstObserved time.Time
	waitFor(t, "tenant A's mTLS canary in /v1/results/latest", 90*time.Second, func() bool {
		var ok bool
		firstObserved, ok = resultsLatest(t, a, canaryAgentID, "noop", canaryTarget)
		return ok
	})
	if _, leaked := resultsLatest(t, b, canaryAgentID, "noop", canaryTarget); leaked {
		t.Fatalf("CROSS-TENANT LEAK: tenant B can read tenant A's mTLS canary result (%s/%s)", canaryAgentID, canaryTarget)
	}
	assertNoForeign(t, b, tenantB, "/v1/results/latest", canaryTarget, canaryAgentID)
	assertNoForeign(t, b, tenantB, "/v1/agents", canaryAgentID, plainAgentID)

	// Force a public-binary rotation, preserving the SPIFFE identity while the
	// leaf fingerprint changes, then prove the rotated credential reconnects.
	stopCanary()
	beforeSerial, beforeSPIFFE := certificateIdentity(t, filepath.Join(identityDir, "cert.pem"))
	runCmd(t, root, nil, canaryAgent, "rotate", "--server", enrollBase, "--dir", identityDir, "--ca-file", serverCA)
	afterSerial, afterSPIFFE := certificateIdentity(t, filepath.Join(identityDir, "cert.pem"))
	if beforeSerial == afterSerial || beforeSPIFFE != afterSPIFFE || afterSPIFFE != wantSPIFFE {
		t.Fatalf("rotation identity mismatch: before=(%s,%s) after=(%s,%s)",
			beforeSerial, beforeSPIFFE, afterSerial, afterSPIFFE)
	}
	_, stopRotated, _ := startProc(t, work, "canary-agent-rotated", canaryAgent, []string{"-config", canaryConfig}, nil)
	var rotatedObserved time.Time
	waitFor(t, "rotated mTLS identity to publish a newer result", 30*time.Second, func() bool {
		var ok bool
		rotatedObserved, ok = resultsLatest(t, a, canaryAgentID, "noop", canaryTarget)
		return ok && rotatedObserved.After(firstObserved)
	})

	// Tenant B cannot revoke tenant A's agent; tenant A can. API revocation
	// pushes the serial/SPIFFE deny-list into the live gRPC listener: a
	// reconnect and a further rotation both fail, and no newer result is
	// persisted for the revoked identity.
	if code, body := b.do(t, http.MethodPost, "/v1/agents/"+canaryAgentID+"/revoke", nil); code != http.StatusNotFound && code != http.StatusForbidden {
		t.Fatalf("CROSS-TENANT ACCESS: tenant B revoking tenant A's agent = %d, want 404/403: %s", code, body)
	}
	a.json(t, http.StatusOK, http.MethodPost, "/v1/agents/"+canaryAgentID+"/revoke", nil, nil)
	stopRotated()
	runCmdMustFail(t, root, nil, canaryAgent, "rotate", "--server", enrollBase, "--dir", identityDir, "--ca-file", serverCA)
	startProc(t, work, "canary-agent-revoked", canaryAgent, []string{"-config", canaryConfig}, nil)
	time.Sleep(3 * time.Second)
	revokedObserved, ok := resultsLatest(t, a, canaryAgentID, "noop", canaryTarget)
	if !ok || revokedObserved.After(rotatedObserved) {
		t.Fatalf("revoked identity persisted a newer result: before=%s after=%s", rotatedObserved, revokedObserved)
	}

	// Deliberately failing, server-reaching enrollment cases run only after
	// the valid lifecycle is complete. A redeemed token is immutable history,
	// never a reusable credential; an expired one never redeems.
	runCmdMustFail(t, root, nil, canaryAgent,
		"enroll", "--server", enrollBase, "--token", canaryToken,
		"--dir", filepath.Join(work, "replay-identity"), "--ca-file", serverCA,
		"--hostname", "replay-refused")
	expiredToken := mintEnrollTokenTTL(t, cli, tenantA, expiredAgentID, "expired-token", "1ms")
	time.Sleep(20 * time.Millisecond)
	runCmdMustFail(t, root, nil, canaryAgent,
		"enroll", "--server", enrollBase, "--token", expiredToken,
		"--dir", filepath.Join(work, "expired-identity"), "--ca-file", serverCA,
		"--hostname", "expired-token")

	// Two fixture-mode agents exercise tenant-namespaced flow ingestion.
	kafkaBroker := "localhost:" + stack.envValue("PROBECTL_DEV_KAFKA_PORT")
	for _, f := range []struct{ tenant, ip, name, agentID, lane string }{
		{tenantA, ipOnlyA, "agent-a", agentAID, laneA},
		{tenantB, ipOnlyB, "agent-b", agentBID, laneB},
	} {
		fixture := writeFixture(t, work, f.name, f.tenant, f.agentID, f.ip)
		cfg := filepath.Join(work, f.name+".yaml")
		writeFile(t, cfg, fmt.Sprintf(
			"apiVersion: probectl.io/ebpf-agent/v1\ntenant_id: %q\nhost: %q\nfixture_path: %q\nbus:\n  mode: kafka\n  brokers: [%q]\n  namespace: %q\n",
			f.tenant, f.agentID, fixture, kafkaBroker, f.lane))
		startProc(t, work, f.name, ebpfAgent, []string{"--config", cfg}, []string{
			"PROBECTL_EBPF_BUS_ALLOW_PLAINTEXT=true",
		})
	}
	t.Cleanup(func() {
		if t.Failed() {
			dumpKafkaDiagnostics(t, root, stack)
		}
	})

	// ── ingest lands: each tenant's edge appears via the PUBLIC API ─────
	waitFor(t, "tenant A's edge in /v1/topology", 90*time.Second, func() bool {
		return strings.Contains(a.get(t, "/v1/topology"), ipOnlyA)
	})
	waitFor(t, "tenant B's edge in /v1/topology", 90*time.Second, func() bool {
		return strings.Contains(b.get(t, "/v1/topology"), ipOnlyB)
	})
	// ── the tenancy boundary: no bleed in either direction ──────────────
	assertNoForeign(t, a, tenantA, "/v1/topology", ipOnlyB)
	assertNoForeign(t, b, tenantB, "/v1/topology", ipOnlyA)
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

// freeTCPPort returns a free loopback port number for a published container port.
func freeTCPPort(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(freeTCPAddr(t))
	if err != nil {
		t.Fatal(err)
	}
	return port
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

// composeStack is the run's disposable Compose project: its name, the files
// that define it and the environment they interpolate.
type composeStack struct {
	project string
	files   []string
	env     []string
}

func (c composeStack) args(args ...string) []string {
	base := []string{"compose", "--project-name", c.project}
	for _, f := range c.files {
		base = append(base, "-f", f)
	}
	return append(base, args...)
}

// composeOverride pins the published ports to loopback (the stack's
// credentials are throwaway dev values, so it never listens on a LAN
// interface) and serves Postgres over TLS with the run's certgen bundle, the
// way deploy/compose/probectl.yml does: the key is installed postgres-owned
// 0600 as the server requires.
const composeOverride = `services:
  postgres:
    ports: !override
      - "127.0.0.1:${PROBECTL_DEV_POSTGRES_PORT}:5432"
    command: >
      bash -c "install -o postgres -g postgres -m 600 /certs/tls.key /var/lib/postgresql/server.key
      && install -o postgres -g postgres -m 644 /certs/tls.crt /var/lib/postgresql/server.crt
      && exec docker-entrypoint.sh postgres -c ssl=on
      -c ssl_cert_file=/var/lib/postgresql/server.crt
      -c ssl_key_file=/var/lib/postgresql/server.key"
    volumes:
      - ${PROBECTL_E2E_TLS_DIR}:/certs:ro
  kafka:
    ports: !override
      - "127.0.0.1:${PROBECTL_DEV_KAFKA_PORT}:9092"
`

// kafkaInternalBroker is the broker's in-network listener. Admin tools run
// inside the kafka container must use it: the host-facing listener advertises
// the run's free loopback port, which does not exist inside the container.
const kafkaInternalBroker = "kafka:19092"

// e2eRuntimePassword is the disposable serve login's password: a throwaway
// value on a loopback-only, per-run database, deliberately not key-shaped.
const e2eRuntimePassword = "e2e-runtime-login-throwaway"

func TestComposeArgsScopesDisposableProject(t *testing.T) {
	t.Parallel()
	stack := composeStack{project: "probectl-e2e-123", files: []string{"/tmp/dev.yml", "/tmp/isolated.yml", "/tmp/loopback.yml"}}
	got := stack.args("down", "-v")
	want := []string{
		"compose", "--project-name", "probectl-e2e-123",
		"-f", "/tmp/dev.yml", "-f", "/tmp/isolated.yml", "-f", "/tmp/loopback.yml", "down", "-v",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("compose args = %q, want %q", got, want)
	}
}

// provisionRuntimeLogin creates the least-privilege serve login with the
// shipped deploy/compose/provision-app-login.sql, exactly as the Compose
// stack's pg-appuser one-shot does, after the migrations created its roles.
func provisionRuntimeLogin(t *testing.T, root string, stack composeStack) {
	t.Helper()
	sql, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "provision-app-login.sql"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", stack.args("exec", "-T", "postgres",
		"psql", "-U", "probectl", "-d", "probectl", "-v", "ON_ERROR_STOP=1",
		"-v", "app_password="+e2eRuntimePassword, "-f", "-")...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), stack.env...)
	cmd.Stdin = strings.NewReader(string(sql))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("provision the least-privilege serve login: %v\n%s", err, out)
	}
}

func seedE2ETenants(t *testing.T, root string, stack composeStack) {
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
	runCmd(t, root, stack.env, "docker", stack.args("exec", "-T",
		"postgres", "psql", "-U", "probectl", "-d", "probectl",
		"-v", "ON_ERROR_STOP=1", "-c", sql)...)
}

func registerCollector(t *testing.T, cli func(...string) string, tenant, agentID, name string) {
	t.Helper()
	token := mintEnrollTokenTTL(t, cli, tenant, agentID, name, "10m")
	regOut := cli("register-collector", "-token", token, "-plane", "ebpf", "-hostname", name)
	if !strings.Contains(regOut, agentID) || !strings.Contains(regOut, tenant) {
		t.Fatalf("collector registration did not bind expected tenant/agent (%s/%s):\n%s", tenant, agentID, regOut)
	}
}

// mintEnrollTokenTTL mints a one-time join token with the shipped
// enroll-token subcommand, run in the release image.
func mintEnrollTokenTTL(t *testing.T, cli func(...string) string, tenant, agentID, name, ttl string) string {
	t.Helper()
	tokenOut := cli("enroll-token", "-tenant", tenant, "-agent", agentID, "-name", name, "-ttl", ttl)
	for _, line := range strings.Split(tokenOut, "\n") {
		if candidate := strings.TrimSpace(line); strings.HasPrefix(candidate, "pjt_") {
			return candidate
		}
	}
	t.Fatal("enroll-token did not print a display token")
	return ""
}

func createKafkaTopics(t *testing.T, root string, stack composeStack, topics ...string) {
	t.Helper()
	for _, topic := range topics {
		runCmd(t, root, stack.env, "docker", stack.args("exec", "-T", "kafka",
			"/opt/kafka/bin/kafka-topics.sh",
			"--bootstrap-server", kafkaInternalBroker,
			"--create",
			"--if-not-exists",
			"--topic", topic,
			"--partitions", "3",
			"--replication-factor", "1")...)
	}
}

func dumpKafkaDiagnostics(t *testing.T, root string, stack composeStack) {
	t.Helper()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "topics", args: []string{"/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", kafkaInternalBroker, "--list"}},
		{name: "consumer-groups", args: []string{"/opt/kafka/bin/kafka-consumer-groups.sh", "--bootstrap-server", kafkaInternalBroker, "--all-groups", "--describe"}},
		{name: "tenant-a-ebpf-offsets", args: []string{"/opt/kafka/bin/kafka-get-offsets.sh", "--bootstrap-server", kafkaInternalBroker, "--topic", "probectl." + laneA + ".ebpf.flows"}},
		{name: "tenant-b-ebpf-offsets", args: []string{"/opt/kafka/bin/kafka-get-offsets.sh", "--bootstrap-server", kafkaInternalBroker, "--topic", "probectl." + laneB + ".ebpf.flows"}},
		{name: "tenant-a-result-offsets", args: []string{"/opt/kafka/bin/kafka-get-offsets.sh", "--bootstrap-server", kafkaInternalBroker, "--topic", "probectl." + laneA + ".network.results"}},
		{name: "tenant-b-result-offsets", args: []string{"/opt/kafka/bin/kafka-get-offsets.sh", "--bootstrap-server", kafkaInternalBroker, "--topic", "probectl." + laneB + ".network.results"}},
	} {
		args := stack.args(append([]string{"exec", "-T", "kafka"}, tc.args...)...)
		cmd := exec.Command("docker", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), stack.env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("---- kafka %s failed ----\n%v\n%s", tc.name, err, out)
			continue
		}
		t.Logf("---- kafka %s ----\n%s", tc.name, out)
	}
}

// startProc launches a long-running binary, captures its output to a log
// file, and guarantees teardown. It returns the log path for diagnostics, a
// stop func, and exited, which is nil while the process runs and its exit
// error once it has ended, so a wait can stop at once instead of spending its
// whole budget on a process that is already gone.
func startProc(t *testing.T, work, name, bin string, args, env []string) (string, func(), func() error) {
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
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	exited := func() error {
		select {
		case <-done:
			if waitErr == nil {
				return fmt.Errorf("%s exited with status 0", name)
			}
			return waitErr
		default:
			return nil
		}
	}
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = cmd.Process.Kill()
			<-done
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
	return logPath, stop, exited
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

// envValue returns the value the stack's environment gives key.
func (c composeStack) envValue(key string) string {
	for _, kv := range c.env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// mkdir creates an owner-only directory under the work directory.
func mkdir(t *testing.T, work, name string) string {
	t.Helper()
	dir := filepath.Join(work, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create e2e directory %s: %v", dir, err)
	}
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
