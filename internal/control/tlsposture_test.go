package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/threat"
)

func seededPostures(t *testing.T) *threat.PostureStore {
	t.Helper()
	ps := threat.NewPostureStore(0)
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	ps.Record(tenancy.DefaultTenantID.String(), threat.Posture{
		Target: "web.acme.example:443", Source: "http", TLSVersion: "1.0", Cipher: "TLS_RSA_WITH_RC4_128_SHA",
		Leaf:     &threat.Certificate{Subject: "CN=web.acme.example", Issuer: "CN=Old CA", NotAfter: at.Add(-24 * time.Hour)},
		Findings: []threat.Finding{{Kind: threat.FindingExpired, Severity: threat.SeverityCritical, Message: "expired"}},
		Severity: threat.SeverityCritical,
		Handoff: &threat.HandoffPayload{Target: "web.acme.example:443", Subject: "CN=web.acme.example",
			Serial: "01", NotAfter: at.Add(-24 * time.Hour).Format(time.RFC3339), Reason: "cert_expired"},
		ObservedAt: at,
	})
	ps.Record("00000000-0000-0000-0000-000000000002", threat.Posture{
		Target: "secret.other:443", Source: "http", TLSVersion: "1.3", Severity: threat.SeverityInfo, ObservedAt: at,
	})
	return ps
}

func TestTLSPostureEndpoint(t *testing.T) {
	srv := testServer(fakePinger{}).WithTLSPosture(seededPostures(t))

	rec := do(srv, http.MethodGet, "/v1/tls/posture")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CollectorRunning bool             `json:"collector_running"`
		Items            []threat.Posture `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.CollectorRunning || len(resp.Items) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	p := resp.Items[0]
	if p.Target != "web.acme.example:443" || p.Handoff == nil || p.Handoff.Reason != "cert_expired" {
		t.Fatalf("posture = %+v", p)
	}

	// TENANT BOUNDARY: the default tenant never sees the other tenant's target;
	// a caller from the other tenant sees only its own.
	if strings.Contains(rec.Body.String(), "secret.other") {
		t.Fatalf("CROSS-TENANT LEAK: %s", rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/tls/posture", nil)
	req.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	srv.Handler().ServeHTTP(rec2, req)
	if !strings.Contains(rec2.Body.String(), "secret.other") || strings.Contains(rec2.Body.String(), "web.acme.example") {
		t.Fatalf("other-tenant view wrong: %s", rec2.Body.String())
	}

	// No store wired: honest empty response.
	bare := do(testServer(fakePinger{}), http.MethodGet, "/v1/tls/posture")
	if bare.Code != http.StatusOK || !strings.Contains(bare.Body.String(), `"collector_running":false`) {
		t.Fatalf("bare = %d %s", bare.Code, bare.Body.String())
	}
}

func TestTLSPostureRoutePerm(t *testing.T) {
	for _, rt := range testServer(fakePinger{}).apiRoutes() {
		if rt.Pattern == "/v1/tls/posture" {
			if rt.Permission != permThreatRead {
				t.Fatalf("perm = %q, want threat.read", rt.Permission)
			}
			return
		}
	}
	t.Fatal("/v1/tls/posture not registered")
}
