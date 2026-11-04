// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type releasePromVector struct {
	Status string `json:"status"`
	Data   struct {
		Kind   string `json:"resultType"`
		Result []struct {
			Labels map[string]string `json:"metric"`
			Value  []json.RawMessage `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

// Real source-built noop agents -> mTLS control -> Kafka -> authenticated TLS
// Prometheus -> tenant-forced public API. This does not prove object storage,
// tag-aware report publication, real SNMP sources or whole-item acceptance.
func provePersistedProbeMetrics(t *testing.T, work, binary, enrollBase, grpcAddr, port, ca string,
	secrets storeSecrets, cli func(...string) string, a, b api) {
	t.Helper()
	direct := api{base: "https://localhost:" + port, client: newHTTPS(t, nil, ca)}
	query := "/api/v1/query?query=" + url.QueryEscape("probectl_probe_success")
	if code, _ := direct.do(t, http.MethodGet, query, nil); code != http.StatusUnauthorized {
		t.Fatal("persisted metrics backend admitted an anonymous read", code)
	}
	identity := filepath.Join(work, "metrics-b-identity")
	token := mintEnrollTokenTTL(t, cli, tenantB, canaryBAgentID, "metrics-b", "10m")
	enrolled := runCmdOutput(t, work, nil, binary, "enroll", "--server", enrollBase,
		"--token", token, "--dir", identity, "--ca-file", ca, "--hostname", "metrics-b")
	if !strings.Contains(enrolled, cryptoSPIFFE(tenantB, canaryBAgentID)) {
		t.Fatal("second real metrics agent did not acquire its own tenant-bound identity")
	}
	const target = "e2e-b-mtls-noop"
	config := filepath.Join(work, "metrics-b-agent.yaml")
	writeFile(t, config, fmt.Sprintf(`apiVersion: probectl.io/agent/v1
control_plane:
  grpc_addr: %q
tls:
  cert_file: %q
  key_file: %q
  ca_file: %q
agent:
  hostname: metrics-b
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
`, grpcAddr, filepath.Join(identity, "cert.pem"), filepath.Join(identity, "key.pem"), ca,
		filepath.Join(work, "metrics-b-buffer"), target))
	_, stop, exited := startProc(t, work, "metrics-b-agent", binary, []string{"-config", config}, nil)
	defer stop()
	waitFor(t, "second real mTLS metrics producer", 90*time.Second, func() bool {
		if err := exited(); err != nil {
			t.Fatal("second metrics producer exited before result ingestion", err)
		}
		_, found := resultsLatest(t, b, canaryBAgentID, "noop", target)
		return found
	})
	if _, leaked := resultsLatest(t, a, canaryBAgentID, "noop", target); leaked {
		t.Fatal("second mTLS producer's result crossed tenant identity")
	}
	waitFor(t, "both tenants persisted through the real authenticated metrics backend", 90*time.Second, func() bool {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, direct.base+query, nil)
		if err != nil {
			t.Fatal("create private authenticated metrics backend read")
		}
		request.SetBasicAuth("probectl", secrets.prometheusControl)
		response, err := direct.client.Do(request)
		if err != nil {
			t.Fatal("verified TLS metrics backend read failed", err)
		}
		body := readBody(t, response)
		var result releasePromVector
		if response.StatusCode != http.StatusOK || json.Unmarshal(body, &result) != nil || result.Status != "success" || result.Data.Kind != "vector" {
			t.Fatal("authenticated metrics backend did not return a valid persisted vector")
		}
		foundA, foundB := false, false
		for _, sample := range result.Data.Result {
			foundA = foundA || sample.Labels["tenant_id"] == tenantA && sample.Labels["agent_id"] == canaryAgentID
			foundB = foundB || sample.Labels["tenant_id"] == tenantB && sample.Labels["agent_id"] == canaryBAgentID
		}
		return foundA && foundB
	})
	for _, lane := range []struct {
		client          api
		tenant, own, no string
	}{{a, tenantA, canaryAgentID, canaryBAgentID}, {b, tenantB, canaryBAgentID, canaryAgentID}} {
		for _, selector := range []string{
			"probectl_probe_success",
			`probectl_probe_success{tenant_id="` + otherReleaseTenant(lane.tenant) + `"}`,
		} {
			var result releasePromVector
			lane.client.json(t, http.StatusOK, http.MethodGet, "/v1/grafana/api/v1/query?query="+url.QueryEscape(selector), nil, &result)
			if result.Status != "success" || result.Data.Kind != "vector" {
				t.Fatal("tenant metrics API lost the real backend vector")
			}
			own := false
			for _, sample := range result.Data.Result {
				if sample.Labels["tenant_id"] != lane.tenant || sample.Labels["agent_id"] == lane.no {
					t.Fatal("real persisted metrics crossed the public tenant query boundary")
				}
				if sample.Labels["agent_id"] == lane.own {
					if len(sample.Value) != 2 || string(sample.Value[1]) != `"1"` {
						t.Fatal("persisted real noop result lost its success value")
					}
					own = true
				}
			}
			if !own {
				t.Fatal("public metrics API lost its own persisted sender")
			}
		}
		var foreign releasePromVector
		lane.client.json(t, http.StatusOK, http.MethodGet, "/v1/grafana/api/v1/query?query="+url.QueryEscape(`probectl_probe_success{agent_id="`+lane.no+`"}`), nil, &foreign)
		if foreign.Status != "success" || len(foreign.Data.Result) != 0 {
			t.Fatal("known foreign persisted sender was visible through the tenant API")
		}
	}
	t.Log("real paired mTLS/Kafka/Prometheus metrics: TLS/auth backend, owned persisted values and tenant-forced public selectors passed")
}

func otherReleaseTenant(tenant string) string {
	if tenant == tenantA {
		return tenantB
	}
	return tenantA
}
