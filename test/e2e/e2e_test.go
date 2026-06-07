// Package e2e holds probectl's BLACK-BOX full-stack end-to-end tests
// (U-054): real binaries built from this tree, the real compose
// dependencies, and only public interfaces — process env/flags, the bus,
// and the versioned REST API. No internal packages are imported, by
// design.
//
// The happy path + tenancy boundary:
//
//	compose up (postgres+kafka) → build probectl-control +
//	probectl-ebpf-agent → boot the control plane (dev auth) → run TWO
//	fixture-mode agents (tenant A and tenant B, disjoint traffic) →
//	flows ride Kafka → query /v1/topology per tenant → A sees exactly
//	A's edges, B exactly B's → teardown.
//
// Gated on PROBECTL_E2E=1 (the nightly e2e workflow sets it; `go test
// ./test/...` stays a no-op skip everywhere else).
package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	apiAddr  = "127.0.0.1:18080"
	tenantA  = "00000000-0000-0000-0000-000000000001" // the seeded default tenant
	tenantB  = "00000000-0000-0000-0000-00000000e2e2"
	ipOnlyA  = "10.77.1.9"  // appears only in tenant A's traffic
	ipOnlyB  = "10.88.2.10" // appears only in tenant B's traffic
	composeF = "deploy/compose/dev.yml"
)

func TestE2E(t *testing.T) {
	if os.Getenv("PROBECTL_E2E") != "1" {
		t.Skip("set PROBECTL_E2E=1 to run the full-stack e2e (nightly ci job; needs docker)")
	}
	root := repoRoot(t)
	work := t.TempDir()

	// ── stack up ────────────────────────────────────────────────────────
	runCmd(t, root, nil, "docker", "compose", "-f", composeF, "up", "-d", "--wait", "postgres", "kafka")
	t.Cleanup(func() {
		_ = exec.Command("docker", "compose", "-f", filepath.Join(root, composeF), "down", "-v").Run()
	})

	// ── build the real binaries from this tree ──────────────────────────
	control := filepath.Join(work, "probectl-control")
	agent := filepath.Join(work, "probectl-ebpf-agent")
	runCmd(t, root, nil, "go", "build", "-o", control, "./cmd/probectl-control")
	runCmd(t, root, nil, "go", "build", "-o", agent, "./cmd/probectl-ebpf-agent")

	// ── control plane: public configuration surface only ────────────────
	controlLog := startProc(t, work, "control", control, nil, []string{
		"PROBECTL_DATABASE_URL=postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable",
		"PROBECTL_HTTP_ADDR=" + apiAddr,
		"PROBECTL_AUTH_MODE=dev",
		"PROBECTL_BUS_MODE=kafka",
		"PROBECTL_BUS_BROKERS=localhost:9092",
		"PROBECTL_BUS_ALLOW_PLAINTEXT=true", // dev compose kafka is plaintext (U-010 dev override)
	})
	waitFor(t, "control plane /readyz", 90*time.Second, func() bool {
		resp, err := http.Get("http://" + apiAddr + "/readyz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	// ── two fixture-mode agents, one per tenant, disjoint traffic ───────
	for _, a := range []struct{ tenant, ip, name string }{
		{tenantA, ipOnlyA, "agent-a"},
		{tenantB, ipOnlyB, "agent-b"},
	} {
		fixture := writeFixture(t, work, a.name, a.tenant, a.ip)
		cfg := filepath.Join(work, a.name+".yaml")
		writeFile(t, cfg, fmt.Sprintf(
			"tenant_id: %q\nfixture_path: %q\nbus:\n  mode: kafka\n  brokers: [\"localhost:9092\"]\n",
			a.tenant, fixture))
		startProc(t, work, a.name, agent, []string{"--config", cfg}, []string{
			"PROBECTL_EBPF_BUS_ALLOW_PLAINTEXT=true",
		})
	}

	// ── ingest lands: each tenant's edge appears via the PUBLIC API ─────
	waitFor(t, "tenant A's edge in /v1/topology", 90*time.Second, func() bool {
		return strings.Contains(topologyJSON(t, tenantA), ipOnlyA)
	})
	waitFor(t, "tenant B's edge in /v1/topology", 90*time.Second, func() bool {
		return strings.Contains(topologyJSON(t, tenantB), ipOnlyB)
	})

	// ── the tenancy boundary: no bleed in either direction ──────────────
	if body := topologyJSON(t, tenantA); strings.Contains(body, ipOnlyB) {
		t.Fatalf("CROSS-TENANT LEAK: tenant A's topology contains tenant B's endpoint %s:\n%s", ipOnlyB, body)
	}
	if body := topologyJSON(t, tenantB); strings.Contains(body, ipOnlyA) {
		t.Fatalf("CROSS-TENANT LEAK: tenant B's topology contains tenant A's endpoint %s:\n%s", ipOnlyA, body)
	}

	// And a malformed tenant override is rejected, not defaulted (dev-mode
	// fail-closed contract).
	req, _ := http.NewRequest(http.MethodGet, "http://"+apiAddr+"/v1/topology", nil)
	req.Header.Set("X-Probectl-Tenant", "not-a-uuid")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed tenant override returned %d, want 400", resp.StatusCode)
	}

	t.Logf("e2e PASS: ingest visible per tenant via the public API; isolation holds both ways (control log: %s)", controlLog)
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

func runCmd(t *testing.T, dir string, env []string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// startProc launches a long-running binary, captures its output to a log
// file, and guarantees teardown. Returns the log path for diagnostics.
func startProc(t *testing.T, work, name, bin string, args, env []string) string {
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
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logf.Close()
		if t.Failed() {
			if b, err := os.ReadFile(logPath); err == nil {
				tail := b
				if len(tail) > 4096 {
					tail = tail[len(tail)-4096:]
				}
				t.Logf("---- %s log tail ----\n%s", name, tail)
			}
		}
	})
	return logPath
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

// topologyJSON fetches /v1/topology as the given tenant (dev-auth header)
// and returns the raw body (valid JSON asserted).
func topologyJSON(t *testing.T, tenant string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "http://"+apiAddr+"/v1/topology", nil)
	req.Header.Set("X-Probectl-Tenant", tenant)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("topology query: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("topology query for %s: %d: %s", tenant, resp.StatusCode, body)
	}
	if !json.Valid(body) {
		t.Fatalf("topology response is not JSON: %s", body)
	}
	return string(body)
}

// writeFixture emits a small recorded-flow file whose endpoints are unique
// to the tenant — the basis of the isolation assertion.
func writeFixture(t *testing.T, work, name, tenant, ip string) string {
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
			TenantID: tenant, AgentID: name, Host: name + "-host",
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
