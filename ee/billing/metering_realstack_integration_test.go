// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package billing_test

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// TestMeteringAndBillingExportRealStack is the real-stack receipt for F53
// (metering and billing export): per-tenant usage counted from the traffic a
// running deployment carries, attributed to the tenant that made it, and
// delivered to the MSP operator through the usage API, the signed export, the
// CLI and the provider console.
//
// The stack is the shipped control plane on the MSP license (metering
// licensed) with shipped agents, on the dev stack: PostgreSQL behind the
// least-privilege serve login, Kafka with strict tenant lanes, ClickHouse,
// Prometheus, TLS everywhere, and the real IdP. Two tenants: A (pooled) and B
// (hybrid, so its flow collector has a lane of its own).
//
//  1. Runtime counters, from production paths only: each tenant's shipped
//     agent runs an HTTP canary (results_ingested, ingest_bytes), A's admin
//     asks the AI assistant two questions and B's admin three (ai_calls), and
//     B's shipped flow agent receives NetFlow from a stand-in router
//     (flow_events). The usage recorder flushes them once a minute.
//  2. Attribution: the usage API reports A with exactly 2 AI calls and no
//     flow events, B with exactly 3 and its flows, each with results of its
//     own; the tenant filter returns only that tenant's rows.
//  3. Export: GET /provider/v1/usage/export as CSV and as JSON Lines carries
//     the stable column contract and the same meters, signed: the Ed25519
//     signature verifies over the exact bytes with the key the fingerprint
//     names, and fails once a byte changes.
//  4. CLI: `probectl billing usage` and `probectl billing export` deliver the
//     same; the export is verified on receipt.
//  5. Console: the provider console's Usage & showback card lists both
//     tenants, and its Export CSV download carries the same meters.
//  6. Neither tenant's admin session nor API token can read the usage.
func TestMeteringAndBillingExportRealStack(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "f53", TenantBand: 4})
	op := st.OnboardOperator(t, "root@msp-f53.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "checkout ok")
	}))
	t.Cleanup(page.Close)

	// 1. Two tenants, each carrying its own traffic.
	A := &f53Tenant{slug: "f53-acme-" + run, name: "Metered Acme", model: "pooled", admin: "ada@acme.example", asks: 2}
	B := &f53Tenant{slug: "f53-globex-" + run, name: "Metered Globex", model: "hybrid", admin: "bob@globex.example", asks: 3}
	for _, tn := range []*f53Tenant{A, B} {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id = row.ID
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "test.read")
		agent := uuid.NewString()
		name := "f53-agent-" + tn.id[:8]
		st.StartAgent(t, st.EnrollAgent(t, tn.id, agent, name), name, []string{"http"}, fmt.Sprintf(`canaries:
  - type: http
    target: %q
    interval: 2s
    timeout: 5s
    params:
      allow_private_targets: "true"
`, page.URL+"/checkout"))
		tn.agent = agent
		for i := 0; i < tn.asks; i++ {
			code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/ai/ask",
				map[string]string{"question": fmt.Sprintf("Why is checkout slow for %s? (%d)", tn.name, i)})
			if code != http.StatusOK {
				t.Fatalf("ask the AI assistant as %s = %d: %s", tn.slug, code, raw)
			}
		}
	}
	var posture struct {
		LaneNamespace struct{ Namespace string } `json:"lane_namespace"`
	}
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": B.token}, &posture, "isolation", "status")
	udp := shipped.FreeUDPAddr(t)
	st.StartCollector(t, "probectl-flow-agent", "f53-flow-"+B.id[:8], "PROBECTL_FLOW", fmt.Sprintf(`apiVersion: probectl.io/flow-agent/v1
tenant_id: %q
agent_id: %q
bus:
  mode: kafka
  brokers: ["%s"]
  namespace: %q
netflow:
  enabled: true
  listen: %q
  allowed_sources: ["127.0.0.1/32"]
ipfix:
  enabled: false
sflow:
  enabled: false
batch_size: 10
flush_interval: 1s
`, B.id, B.agent, strings.Join(testsupport.KafkaBrokers(), `","`), posture.LaneNamespace.Namespace, udp))
	go shipped.ExportNetFlow(t.Context(), udp)

	// 2. Attribution through the usage API, once the recorder has flushed.
	var usage f53Meters
	shipped.Await(t, "both tenants' metered usage", 180*time.Second, func() bool {
		usage = usageMeters(t, st, op, "")
		a, b := usage[A.id], usage[B.id]
		return a["results_ingested"] > 0 && a["ai_calls"] == 2 && b["results_ingested"] > 0 && b["ai_calls"] == 3 && b["flow_events"] > 0
	})
	a, b := usage[A.id], usage[B.id]
	if a["flow_events"] != 0 || a["ingest_bytes"] == 0 || b["ingest_bytes"] == 0 {
		t.Errorf("usage attribution: A %v, B %v; want A without flows, both with ingest bytes", a, b)
	}
	if only := usageMeters(t, st, op, A.id); len(only) != 1 || only[A.id] == nil {
		t.Errorf("GET /provider/v1/usage?tenant_id=A returned tenants %v, want only A", keys(only))
	}

	// 3. The signed export, as CSV and JSON Lines.
	csvBody := signedExport(t, st, op, "csv")
	header, exported := csvMeters(t, csvBody)
	if header != "tenant_id,tenant_slug,meter,kind,period_start,period_end,value,unit" {
		t.Errorf("the CSV export's columns are %q, not the stable contract", header)
	}
	checkExported(t, "the CSV export", exported, A, B)
	checkExported(t, "the JSON Lines export", jsonlMeters(t, signedExport(t, st, op, "jsonl")), A, B)
	if !strings.Contains(string(csvBody), A.slug) || !strings.Contains(string(csvBody), B.slug) {
		t.Errorf("the CSV export does not name both tenants' slugs")
	}

	// 4. The CLI.
	var cliUsage struct {
		Items []struct {
			TenantID string `json:"tenant_id"`
			Meter    string `json:"meter"`
			Kind     string `json:"kind"`
			Value    int64  `json:"value"`
		}
	}
	st.MustCLI(t, opEnv, &cliUsage, "billing", "usage", "--query", "tenant_id="+B.id, "--query", "rollup=day")
	cliAI := int64(0)
	for _, it := range cliUsage.Items {
		if it.TenantID != B.id {
			t.Errorf("probectl billing usage --query tenant_id=B returned a row of tenant %s", it.TenantID)
		}
		if it.Meter == "ai_calls" {
			cliAI += it.Value
		}
	}
	if cliAI != 3 {
		t.Errorf("probectl billing usage reports %d AI calls for B, want 3", cliAI)
	}
	stdout, stderr, code := st.CLI(opEnv, "billing", "export", "--query", "format=csv", "--query", "rollup=day")
	if code != 0 {
		t.Fatalf("probectl billing export: exit %d: %s", code, stderr)
	}
	_, cliExported := csvMeters(t, []byte(stdout))
	checkExported(t, "probectl billing export", cliExported, A, B)

	// 5. The provider console.
	download := filepath.Join(t.TempDir(), "console-usage.csv")
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/provider",
		Cookies:        []testsupport.RenderCookie{{Name: auth.ProviderSessionCookie, Value: op}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Usage & showback", A.slug, B.slug},
		Steps:  []testsupport.RenderStep{{Click: "Export CSV", Role: "link", Download: download}},
	})
	consoleCSV, err := os.ReadFile(download)
	if err != nil {
		t.Fatalf("the console's usage export download: %v", err)
	}
	_, consoleExported := csvMeters(t, consoleCSV)
	checkExported(t, "the console's Export CSV", consoleExported, A, B)

	// 6. A tenant cannot read the provider's usage, by session or token.
	for _, tn := range []*f53Tenant{A, B} {
		if code, _ := st.Do(t, tn.cookie, http.MethodGet, "/provider/v1/usage", nil); code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Errorf("tenant %s's admin session reads /provider/v1/usage: %d", tn.slug, code)
		}
		if code, _, _ := providerGet(t, st, tn.token, "/provider/v1/usage"); code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Errorf("tenant %s's API token reads /provider/v1/usage: %d", tn.slug, code)
		}
	}
}

type f53Tenant struct {
	slug, name, model, admin string
	asks                     int
	id, cookie, token, agent string
}

// f53Meters sums each tenant's counters for the period: tenant -> meter -> value.
type f53Meters map[string]map[string]int64

func (m f53Meters) add(tenant, meter, kind string, value int64) {
	if kind != "counter" {
		return
	}
	if m[tenant] == nil {
		m[tenant] = map[string]int64{}
	}
	m[tenant][meter] += value
}

func usageMeters(t *testing.T, st *shipped.Stack, op, tenant string) f53Meters {
	t.Helper()
	path := "/provider/v1/usage?rollup=day"
	if tenant != "" {
		path += "&tenant_id=" + tenant
	}
	code, _, body := providerGet(t, st, op, path)
	var out struct {
		Items []struct {
			TenantID string `json:"tenant_id"`
			Meter    string `json:"meter"`
			Kind     string `json:"kind"`
			Value    int64  `json:"value"`
		}
	}
	if code != http.StatusOK || json.Unmarshal(body, &out) != nil {
		t.Fatalf("GET %s = %d: %.300s", path, code, body)
	}
	m := f53Meters{}
	for _, it := range out.Items {
		m.add(it.TenantID, it.Meter, it.Kind, it.Value)
	}
	return m
}

// signedExport downloads the usage export and verifies its detached
// signature over the exact bytes, then that a changed byte fails it.
func signedExport(t *testing.T, st *shipped.Stack, op, format string) []byte {
	t.Helper()
	code, h, body := providerGet(t, st, op, "/provider/v1/usage/export?rollup=day&format="+format)
	if code != http.StatusOK {
		t.Fatalf("GET the %s usage export = %d: %.300s", format, code, body)
	}
	key, err := base64.StdEncoding.DecodeString(h.Get("X-Probectl-Usage-Signing-Key"))
	if err != nil {
		t.Fatalf("the %s export's signing key: %v", format, err)
	}
	sig, err := base64.StdEncoding.DecodeString(h.Get("X-Probectl-Usage-Signature"))
	if err != nil {
		t.Fatalf("the %s export's signature: %v", format, err)
	}
	if h.Get("X-Probectl-Usage-Signature-Alg") != "ed25519" ||
		h.Get("X-Probectl-Usage-Signing-Key-Fingerprint") != "sha256:"+hex.EncodeToString(crypto.Hash(key)) {
		t.Errorf("the %s export's signature headers are inconsistent: %v", format, h)
	}
	if ok, err := crypto.VerifyEd25519(key, body, sig); err != nil || !ok {
		t.Errorf("the %s export's signature does not verify over its bytes (%v)", format, err)
	}
	tampered := append([]byte(nil), body...)
	tampered[len(tampered)/2] ^= 0x01
	if ok, _ := crypto.VerifyEd25519(key, tampered, sig); ok {
		t.Errorf("the %s export's signature verifies over a changed byte", format)
	}
	return body
}

func csvMeters(t *testing.T, body []byte) (header string, m f53Meters) {
	t.Helper()
	records, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil || len(records) == 0 {
		t.Fatalf("parse the CSV usage export: %v: %.300s", err, body)
	}
	m = f53Meters{}
	for _, r := range records[1:] {
		if len(r) != 8 {
			t.Fatalf("a CSV usage row has %d columns: %v", len(r), r)
		}
		v, err := strconv.ParseInt(r[6], 10, 64)
		if err != nil {
			t.Fatalf("a CSV usage value %q: %v", r[6], err)
		}
		m.add(r[0], r[2], r[3], v)
	}
	return strings.Join(records[0], ","), m
}

func jsonlMeters(t *testing.T, body []byte) f53Meters {
	t.Helper()
	m := f53Meters{}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		var r struct {
			TenantID string `json:"tenant_id"`
			Meter    string `json:"meter"`
			Kind     string `json:"kind"`
			Value    int64  `json:"value"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("parse a JSON Lines usage row %q: %v", line, err)
		}
		m.add(r.TenantID, r.Meter, r.Kind, r.Value)
	}
	return m
}

// checkExported requires the exported meters to attribute the AI calls and
// flows exactly as the tenants made them.
func checkExported(t *testing.T, what string, m f53Meters, acme, globex *f53Tenant) {
	t.Helper()
	a, b := m[acme.id], m[globex.id]
	if a["ai_calls"] != 2 || b["ai_calls"] != 3 || a["flow_events"] != 0 || b["flow_events"] == 0 ||
		a["results_ingested"] == 0 || b["results_ingested"] == 0 {
		t.Errorf("%s attributes A %v and B %v; want A 2 AI calls and no flows, B 3 and flows, both results", what, a, b)
	}
}

// providerGet is an operator-authenticated GET on the provider API.
func providerGet(t *testing.T, st *shipped.Stack, token, path string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, st.BaseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := st.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, resp.Header, body
}

func keys(m f53Meters) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
