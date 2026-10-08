// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestRemoteAIEgressIsConsentGatedRedactedAndAuditedRealStack is the real-stack
// receipt for CLM-CONSENT-GATED: "Remote AI egress requires explicit tenant
// consent and redaction; denial is the default."
//
// Nothing is mocked inside probectl. The control plane is built by the
// production constructor from a real config (remote OpenAI-compatible provider,
// operator egress ack, redaction knobs) over real PostgreSQL with RLS, so the
// production egress gate, consent source (tenant_governance.ai_remote_egress),
// redaction (C8), resilient model, and tenant audit chain are the ones under
// test. The "remote model" is an OpenAI-compatible HTTPS endpoint listening on a
// genuinely NON-loopback interface with a certificate issued by probectl's own
// CA code, trusted only through PROBECTL_AI_MODEL_CA_FILE — so the production
// remote-endpoint classifier, TLS validation, and egress path all engage. Two
// tenants, driven only through the public /v1 API:
//
//  1. default deny — a tenant that never consented is refused (403), NOTHING
//     reaches the model, and the refusal is durably audited;
//  2. the consenting tenant is denied too until it opts in via the tenant-side
//     governance API;
//  3. after consent exactly one request leaves, its question AND evidence are
//     masked (no raw IP / email; redaction tokens present; no other tenant's
//     evidence), and the egress is audited in that tenant's tamper-evident chain;
//  4. the other tenant is still refused — consent never leaks across tenants.
func TestRemoteAIEgressIsConsentGatedRedactedAndAuditedRealStack(t *testing.T) {
	host := firstNonLoopbackIPv4(t)

	// A private CA and a server certificate for the non-loopback address, issued
	// by probectl's production certificate code (internal/crypto).
	ca, err := crypto.GenerateCA("probectl-integration-llm-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("llm-gateway.integration", []string{host}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "llm-ca.pem")
	if err := os.WriteFile(caFile, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}

	// The remote model: records every request body it receives.
	var (
		mu     sync.Mutex
		bodies []string
	)
	received := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
	model := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"{\"insufficient_evidence\":true,\"findings\":[]}"}}]}`)
	}))
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		testsupport.SkipOrFatal(t, "listen on non-loopback %s: %v", host, err)
	}
	_ = model.Listener.Close()
	model.Listener = ln
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	model.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	model.StartTLS()
	defer model.Close()

	// The production control plane, configured exactly as an operator would.
	_, db := setupAPIServerWithLatest(t, nil)
	cfg := &config.Config{
		HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev",
		AIModelProvider:   "openai",
		AIModelEndpoint:   model.URL,
		AIModelName:       "gpt-integration",
		AIModelTimeout:    15 * time.Second,
		AIModelCAFile:     caFile,
		AIMaxEvidence:     50,
		AIMaxConcurrent:   4,
		AIEgressAck:       config.AIEgressAckPhrase,
		AIRedactIPs:       true,
		AIRedactHostnames: true,
		AIRedactPII:       true,
	}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil).
		WithTenantStatus(NewTenantStatusCache(db.Pool(), 0))
	srv.WithGovernance(govern.NewPolicyStore(db.Pool()))
	h := srv.Handler()

	tenantA := freshTenant(t, db, "egress-a")
	tenantB := freshTenant(t, db, "egress-b")
	const ipA, ipB, emailA = "10.20.30.40", "10.50.60.70", "alice@example.com"
	seedIncident(t, db, tenantA, ipA)
	seedIncident(t, db, tenantB, ipB)
	questionA := "Why is checkout to " + ipA + " failing for " + emailA + "?"
	questionB := "Why is checkout to " + ipB + " failing?"

	ask := func(tenant, q string) *httptest.ResponseRecorder {
		return apiReq(t, h, http.MethodPost, "/v1/ai/ask", tenant, map[string]any{"question": q})
	}
	audited := func(tenant, action string) bool {
		for _, ev := range listAudit(t, h, tenant) {
			if ev.Action == action {
				return true
			}
		}
		return false
	}

	// 1. Default deny: tenant B never consented.
	if rec := ask(tenantB, questionB); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant B (no consent) ask = %d, want 403 — remote egress must be denied by default: %s", rec.Code, rec.Body)
	}
	if n := len(received()); n != 0 {
		t.Fatalf("%d request(s) reached the remote model with no tenant consent — tenant data left the deployment", n)
	}
	if !audited(tenantB, "ai.remote_egress_denied") {
		t.Error("tenant B's refused egress was not recorded in its audit chain")
	}

	// 2. Tenant A is denied too, until it opts in.
	if rec := ask(tenantA, questionA); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant A before consent ask = %d, want 403", rec.Code)
	}
	if n := len(received()); n != 0 {
		t.Fatalf("%d request(s) reached the remote model before tenant A consented", n)
	}

	// 3. Tenant A consents through the TENANT-side governance API.
	if rec := apiReq(t, h, http.MethodPut, "/v1/governance/policy", tenantA,
		map[string]any{"ai_remote_egress": true}); rec.Code != http.StatusOK {
		t.Fatalf("tenant A consent PUT = %d: %s", rec.Code, rec.Body)
	}

	// 4. Exactly one request leaves, and it is redacted.
	if rec := ask(tenantA, questionA); rec.Code != http.StatusOK {
		t.Fatalf("tenant A after consent ask = %d, want 200: %s", rec.Code, rec.Body)
	}
	got := received()
	if len(got) != 1 {
		t.Fatalf("remote model received %d request(s) after tenant A consented, want exactly 1", len(got))
	}
	body := got[0]
	for _, raw := range []string{ipA, emailA} {
		if strings.Contains(body, raw) {
			t.Errorf("raw %q left the deployment in the remote-model request; redaction must mask it before egress", raw)
		}
	}
	if !strings.Contains(body, "[ip:") {
		t.Errorf("no redaction token in the outbound request — masking did not run:\n%s", body)
	}
	if strings.Contains(body, ipB) {
		t.Error("tenant B's evidence appeared in tenant A's remote-model request — evidence crossed the tenant boundary")
	}
	if !audited(tenantA, "ai.remote_egress") {
		t.Error("tenant A's remote egress was not recorded in its audit chain")
	}
	if ok, detail := verifyAudit(t, h, tenantA); !ok {
		t.Errorf("tenant A's audit chain does not verify after the egress record: %s", detail)
	}

	// 5. Consent never leaks across tenants: B is still refused.
	if rec := ask(tenantB, questionB); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant B ask after tenant A consented = %d, want 403 — consent leaked across tenants", rec.Code)
	}
	if n := len(received()); n != 1 {
		t.Fatalf("remote model request count = %d after tenant B's second ask, want still 1", n)
	}
	if audited(tenantB, "ai.remote_egress") {
		t.Error("tenant B's audit chain records a remote egress it never consented to")
	}
}

// firstNonLoopbackIPv4 returns an address on a real, up, non-loopback interface,
// so the production endpoint classifier treats the model as REMOTE. A host with
// no such interface cannot run this proof: skip, or fail in the required lane.
func firstNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		testsupport.SkipOrFatal(t, "list interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			return ip.String()
		}
	}
	testsupport.SkipOrFatal(t, "no up, non-loopback IPv4 interface to host the remote-model endpoint")
	return ""
}
