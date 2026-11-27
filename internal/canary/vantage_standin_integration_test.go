// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package canary_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// The cloud modules' native Terraform mock plans cover cloud resources and
// secret grants. The local CI VM here stands in for the prepared Linux images.
// The token comes from the fixture and enters the real agent only via stdin.
func TestCloudVantageStandInEnrollsAndProbesInTwoTenants(t *testing.T) {
	stack := shipped.Start(t, shipped.Options{Name: "cloud-vantage", TenantBand: 3})
	operator := stack.OnboardOperator(t, "root@msp-vantage-fixture.example")
	providers := []struct{ name, region string }{
		{"aws", "us-east-1"}, {"azure", "eastus"}, {"gcp", "us-central1"},
	}
	type vantage struct {
		agent, provider, region string
	}
	type lane struct {
		id, cookie string
		vantages   map[string]vantage
	}
	var lanes [2]lane
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		slug := fmt.Sprintf("vantage-%s-%d", run, i)
		var tenant struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, slug, slug))
		lanes[i] = lane{tenant.ID, stack.SignIn(t, tenant.ID, email, slug), make(map[string]vantage)}
	}
	for i, own := range lanes {
		for j, provider := range providers {
			name := provider.name + "-" + strconv.Itoa(i)
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(target.Close)
			address := target.Listener.Addr().String()
			params := map[string]string{"allow_private_targets": "true", "count": "1"}
			code, raw := stack.Do(t, own.cookie, http.MethodPost, "/v1/tests", map[string]any{
				"name": name, "type": "tcp", "target": address, "enabled": true,
				"interval_seconds": 20, "timeout_seconds": 5, "params": params,
			})
			var created synthTest
			if code != http.StatusCreated || json.Unmarshal(raw, &created) != nil || created.ID == "" {
				t.Fatalf("%s could not create its local canary: HTTP %d", name, code)
			}
			agentID := uuid.NewString()
			// All six stand-ins share one fixture IP. One wrong-tenant attempt
			// per tenant checks both directions below the normal lockout limit.
			var sibling string
			if j == 0 {
				sibling = lanes[1-i].id
			}
			identity := enrollVantageStandIn(t, stack, name, own.id, sibling, agentID)
			launchVantageStandIn(t, stack, identity, name, provider.name, provider.region, address, created.ID)
			own.vantages[created.ID] = vantage{agentID, provider.name, provider.region}
		}
	}
	for i, own := range lanes {
		shipped.Await(t, "tenant's three enrolled cloud canaries", 60*time.Second, func() bool {
			var results synthResults
			code, raw := stack.Do(t, own.cookie, http.MethodGet, "/v1/results/history?window=1h", nil)
			if code != http.StatusOK || json.Unmarshal(raw, &results) != nil {
				t.Fatalf("tenant %d results request: HTTP %d", i, code)
			}
			seen := map[string]bool{}
			for _, result := range results.Items {
				testID := result.Attributes["probectl.test.id"]
				want, belongs := own.vantages[testID]
				if !belongs || result.AgentID != want.agent {
					t.Fatalf("tenant %d received a foreign canary result", i)
				}
				if result.Type == "tcp" && result.Success {
					seen[testID] = true
				}
			}
			return len(seen) == len(providers)
		})

		var agents struct {
			Items []struct {
				ID     string
				Labels map[string]string
			}
		}
		code, raw := stack.Do(t, own.cookie, http.MethodGet, "/v1/agents", nil)
		if code != http.StatusOK || json.Unmarshal(raw, &agents) != nil || len(agents.Items) != len(providers) {
			t.Fatalf("tenant %d cloud inventory count: %d HTTP %d", i, len(agents.Items), code)
		}
		owned := map[string]vantage{}
		for _, fixture := range own.vantages {
			owned[fixture.agent] = fixture
		}
		for _, agent := range agents.Items {
			want, belongs := owned[agent.ID]
			if !belongs || agent.Labels["network_role"] != "cloud" || agent.Labels["provider"] != want.provider ||
				agent.Labels["region"] != want.region {
				t.Errorf("tenant %d received incorrect cloud agent ownership or labels", i)
			}
			delete(owned, agent.ID)
		}
	}
}

func enrollVantageStandIn(t *testing.T, stack *shipped.Stack, name, tenant, sibling, agentID string) string {
	t.Helper()
	minted := stack.Subcommand(t, "enroll-token", "-tenant", tenant, "-agent", agentID, "-name", name, "-ttl", "10m")
	var token string
	for _, line := range strings.Split(minted, "\n") {
		if candidate := strings.TrimSpace(line); strings.HasPrefix(candidate, "pjt_") {
			token = candidate
		}
	}
	if token == "" {
		t.Fatal("could not mint the local cloud-secret stand-in")
	}
	dir := t.TempDir()
	enroll := func(expectedTenant string) ([]byte, error) {
		cmd := exec.CommandContext(t.Context(), stack.Agent, "enroll", "--if-needed", "--token-stdin",
			"--server", stack.BaseURL, "--ca-file", stack.CAFile, "--expected-tenant", expectedTenant,
			"--hostname", name, "--dir", dir)
		cmd.Stdin = strings.NewReader(token + "\n")
		return cmd.CombinedOutput()
	}
	if sibling != "" {
		if raw, err := enroll(sibling); err == nil || !strings.Contains(string(raw), "HTTP 401") || strings.Contains(string(raw), token) {
			t.Fatalf("%s did not reject a sibling tenant claim without disclosing the token", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "cert.pem")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left credentials after refusing sibling enrollment: %v", name, err)
		}
	}
	raw, err := enroll(tenant)
	if err != nil || !strings.Contains(string(raw), crypto.AgentSPIFFEID(tenant, agentID)) || strings.Contains(string(raw), token) {
		t.Fatalf("%s failed to obtain an owned identity with the same token: %v", name, err)
	}
	return dir
}

func launchVantageStandIn(t *testing.T, stack *shipped.Stack, identity, name, provider, region, target, testID string) {
	t.Helper()
	config := fmt.Sprintf(`apiVersion: probectl.io/agent/v1
control_plane:
  grpc_addr: %q
tls:
  cert_file: %q
  key_file: %q
  ca_file: %q
  server_name: "localhost"
identity:
  server: %q
agent:
  hostname: %q
  capabilities: [tcp]
  heartbeat_interval: 1s
  labels:
    site: %q
    provider: %q
    region: %q
    network_role: cloud
buffer:
  dir: %q
  max_records: 100
test_sync:
  enabled: false
canaries:
  - test_id: %q
    type: tcp
    target: %q
    interval: 20s
    timeout: 5s
    params:
      allow_private_targets: "true"
      count: "1"
`, stack.AgentAddr, filepath.Join(identity, "cert.pem"), filepath.Join(identity, "key.pem"), stack.CAFile, stack.BaseURL,
		name, name, provider, region, filepath.Join(t.TempDir(), "buffer"), testID, target)
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	stack.StartProcess(t, "vantage-"+name, stack.Agent, []string{"--config", path},
		[]string{"PROBECTL_AGENT_METRICS_ADDR=127.0.0.1:0"})
}
