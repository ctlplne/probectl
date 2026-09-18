// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/enroll"
)

type forensicEnrollmentService struct {
	enrollErr error
	rotateErr error
	// collectorErr is what RegisterCollectorForTenant fails with (DPR-048).
	collectorErr error
	// identity is what a successful Enroll/Rotate returns (DPR-098).
	identity *enroll.Identity
}

func (f forensicEnrollmentService) Enroll(context.Context, enroll.Request) (*enroll.Identity, error) {
	return f.identity, f.enrollErr
}

func (forensicEnrollmentService) MintToken(context.Context, string, string, string, string, time.Duration) (string, string, error) {
	return "", "", nil
}

func (f forensicEnrollmentService) RegisterCollectorForTenant(context.Context, string, string, string, string, string) (*enroll.CollectorIdentity, error) {
	if f.collectorErr != nil {
		return nil, f.collectorErr
	}
	return nil, nil
}

func (f forensicEnrollmentService) Rotate(context.Context, enroll.RotateRequest) (*enroll.Identity, error) {
	return f.identity, f.rotateErr
}

// DPR-177: the issuing intermediate's window. This double reports a healthy
// year so the forensics tests keep testing forensics.
func (forensicEnrollmentService) IssuingWindow() (time.Time, time.Time) {
	now := time.Now()
	return now.Add(-24 * time.Hour), now.Add(364 * 24 * time.Hour)
}

func (forensicEnrollmentService) Revoke(context.Context, string, string, string) ([]string, string, error) {
	return nil, "", nil
}

func TestEnrollmentFailureEmitsBoundedForensicSignal(t *testing.T) {
	const (
		secretToken = "pjt_DO_NOT_LEAK_THIS_TOKEN"
		secretCSR   = "DO_NOT_LEAK_THIS_CSR"
		secretCert  = "DO_NOT_LEAK_THIS_CERT"
		secretProof = "DO_NOT_LEAK_THIS_PROOF"
	)
	tests := []struct {
		name        string
		path        string
		body        string
		enrollErr   error
		rotateErr   error
		wantStatus  int
		wantClass   enrollmentFailureClass
		wantSurface enrollmentSurface
	}{
		{
			name: "invalid agent token", path: "/enroll/agent",
			body:      `{"token":"` + secretToken + `","csr_pem":"` + secretCSR + `"}`,
			enrollErr: enroll.ErrInvalidToken, wantStatus: http.StatusUnauthorized,
			wantClass: enrollmentFailureInvalidToken, wantSurface: enrollmentSurfaceAgent,
		},
		{
			name: "invalid agent CSR", path: "/enroll/agent",
			body:      `{"token":"` + secretToken + `","csr_pem":"` + secretCSR + `"}`,
			enrollErr: enroll.ErrBadCSR, wantStatus: http.StatusBadRequest,
			wantClass: enrollmentFailureInvalidCSR, wantSurface: enrollmentSurfaceAgent,
		},
		{
			name: "revoked agent identity", path: "/enroll/agent",
			body:      `{"token":"` + secretToken + `","csr_pem":"` + secretCSR + `"}`,
			enrollErr: enroll.ErrRevoked, wantStatus: http.StatusUnauthorized,
			wantClass: enrollmentFailureRevokedIdentity, wantSurface: enrollmentSurfaceAgent,
		},
		{
			name: "invalid rotation identity", path: "/enroll/agent/rotate",
			body:      `{"cert_pem":"` + secretCert + `","csr_pem":"` + secretCSR + `","proof":"` + secretProof + `"}`,
			rotateErr: enroll.ErrNotOurs, wantStatus: http.StatusUnauthorized,
			wantClass: enrollmentFailureInvalidRotationIdentity, wantSurface: enrollmentSurfaceRotation,
		},
		{
			name: "invalid rotation proof", path: "/enroll/agent/rotate",
			body:      `{"cert_pem":"` + secretCert + `","csr_pem":"` + secretCSR + `","proof":"` + secretProof + `"}`,
			rotateErr: enroll.ErrInvalidProof, wantStatus: http.StatusUnauthorized,
			wantClass: enrollmentFailureInvalidRotationProof, wantSurface: enrollmentSurfaceRotation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := testServer(nil)
			var logs bytes.Buffer
			srv.log = slog.New(slog.NewJSONHandler(&logs, nil))
			srv.enrollSvc = forensicEnrollmentService{enrollErr: tt.enrollErr, rotateErr: tt.rotateErr}
			var audited []enrollmentFailureEvent
			srv.enrollmentFailureAudit = func(_ context.Context, event enrollmentFailureEvent) error {
				audited = append(audited, event)
				return nil
			}

			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}

			metricsRec := httptest.NewRecorder()
			srv.Metrics().Handler().ServeHTTP(metricsRec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			metricLine := enrollmentFailureMetricName(tt.wantClass) + " 1\n"
			if got := strings.Count(metricsRec.Body.String(), metricLine); got != 1 {
				t.Fatalf("typed metric %q count = %d, want 1:\n%s", metricLine, got, metricsRec.Body.String())
			}
			if len(audited) != 1 {
				t.Fatalf("audit signals = %d, want exactly 1", len(audited))
			}
			if audited[0].Class != tt.wantClass || audited[0].Surface != tt.wantSurface {
				t.Fatalf("audit classification = %q/%q, want %q/%q",
					audited[0].Class, audited[0].Surface, tt.wantClass, tt.wantSurface)
			}

			evidence := rec.Body.String() + metricsRec.Body.String() + logs.String() +
				string(audited[0].Class) + string(audited[0].Surface) + audited[0].Actor
			for _, secret := range []string{secretToken, secretCSR, secretCert, secretProof} {
				if strings.Contains(evidence, secret) {
					t.Fatalf("secret %q leaked into response, metric, log, or audit signal", secret)
				}
			}
			if !strings.Contains(logs.String(), `"failure_class":"`+string(tt.wantClass)+`"`) ||
				!strings.Contains(logs.String(), `"surface":"`+string(tt.wantSurface)+`"`) {
				t.Fatalf("structured rejection log missing bounded classification: %s", logs.String())
			}
		})
	}

	t.Run("attacker supplied dimensions collapse to unknown", func(t *testing.T) {
		srv := testServer(nil)
		var audited enrollmentFailureEvent
		srv.enrollmentFailureAudit = func(_ context.Context, event enrollmentFailureEvent) error {
			audited = event
			return nil
		}
		req := httptest.NewRequest(http.MethodPost, "/enroll/agent", nil)
		srv.recordEnrollmentFailure(req, enrollmentFailureClass(secretToken), enrollmentSurface(secretProof), "")
		if audited.Class != enrollmentFailureUnknown || audited.Surface != enrollmentSurfaceUnknown {
			t.Fatalf("unbounded dimensions reached audit: %+v", audited)
		}
		if got := srv.Metrics().Counter(enrollmentFailureMetricName(enrollmentFailureUnknown), "").Value(); got != 1 {
			t.Fatalf("unknown bounded counter = %d, want 1", got)
		}
	})

	t.Run("client cancellation does not erase the durable signal", func(t *testing.T) {
		srv := testServer(nil)
		srv.enrollSvc = forensicEnrollmentService{enrollErr: enroll.ErrInvalidToken}
		var audited bool
		srv.enrollmentFailureAudit = func(ctx context.Context, _ enrollmentFailureEvent) error {
			if err := ctx.Err(); err != nil {
				t.Fatalf("audit context inherited client cancellation: %v", err)
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > enrollmentFailureAuditTimeout {
				t.Fatalf("audit context deadline = %v, %v; want bounded timeout", deadline, ok)
			}
			audited = true
			return nil
		}

		req := httptest.NewRequest(http.MethodPost, "/enroll/agent",
			strings.NewReader(`{"token":"`+secretToken+`","csr_pem":"`+secretCSR+`"}`))
		ctx, cancel := context.WithCancel(req.Context())
		cancel()
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusUnauthorized || !audited {
			t.Fatalf("canceled request status=%d audited=%v, want 401 and durable signal", rec.Code, audited)
		}
	})
}

// Sprint 11: with no enrollment service configured, the bootstrap surface
// answers 503 WITH the operator instruction — never a silent half-trust-root.
// (Token/replay/rotation behavior is covered by the enroll integration suite;
// this pins the unconfigured posture and the route mounting, DB-less.)
func TestEnrollRoutesUnconfiguredAnswer503(t *testing.T) {
	srv := testServer(nil) // no enroll service installed
	h := srv.Handler()

	for _, path := range []string{"/enroll/agent", "/enroll/agent/rotate"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s unconfigured = %d, want 503", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "agent-ca init") {
			t.Fatalf("%s must tell the operator HOW to configure: %s", path, rec.Body.String())
		}
	}

	// The admin mint route (the test harness runs dev-mode auth, so the
	// caller is authenticated and RBAC passes): unconfigured = the same 503 +
	// instruction. RBAC enforcement itself is covered by the shared
	// requirePermission suite over the route table.
	for _, path := range []string{"/v1/agents/enroll-tokens", "/v1/collectors/register"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "agent-ca init") {
			t.Fatalf("%s unconfigured = %d (%s), want 503 + init instruction", path, rec.Code, rec.Body.String())
		}
	}
}

func TestCollectorCollectionProfileIsBoundedAndDeviceOnly(t *testing.T) {
	tests := []struct {
		name    string
		plane   string
		raw     string
		want    string
		wantErr string
	}{
		{name: "device default", plane: "device", want: "standard"},
		{name: "device minimal", plane: "device", raw: "minimal", want: "minimal"},
		{name: "device topology", plane: "device", raw: "topology-rich", want: "topology-rich"},
		{name: "unknown", plane: "device", raw: "vendor-ultra", wantErr: "unknown collection_profile"},
		{name: "other plane", plane: "flow", raw: "standard", wantErr: "valid only for the device collector"},
		{name: "other plane empty", plane: "flow", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := collectorCollectionProfile(tt.plane, tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("profile = %q, err=%v, want %q", got, err, tt.want)
			}
		})
	}
}

func TestDeviceCollectorConfigIncludesCompiledProfile(t *testing.T) {
	hint := collectorConfig("device", "tenant-a", "agent-a", "topology-rich", "t-acme")
	if got := hint.Env["PROBECTL_DEVICE_PROFILE"]; got != "topology-rich" {
		t.Fatalf("profile env = %q", got)
	}
	if got := hint.YAML["collection_profile"]; got != "topology-rich" {
		t.Fatalf("profile YAML = %q", got)
	}
	// DPR-049: the tenant's namespaced lane rides along for every
	// agent-published plane, and BGP/BMP (listener-fed) get none.
	// DPR-053: the YAML form is the collector's real nested key, bus.namespace.
	if bus, _ := hint.YAML["bus"].(map[string]string); hint.Env["PROBECTL_DEVICE_BUS_NAMESPACE"] != "t-acme" || bus["namespace"] != "t-acme" {
		t.Fatalf("device hint lacks the bus namespace: %+v", hint)
	}
	for plane, key := range map[string]string{"flow": "PROBECTL_FLOW_BUS_NAMESPACE", "endpoint": "PROBECTL_ENDPOINT_BUS_NAMESPACE", "ebpf": "PROBECTL_EBPF_BUS_NAMESPACE"} {
		if h := collectorConfig(plane, "tenant-a", "agent-a", "", "t-acme"); h.Env[key] != "t-acme" {
			t.Fatalf("%s hint lacks %s: %+v", plane, key, h)
		}
	}
	if h := collectorConfig("bgp", "tenant-a", "agent-a", "", "t-acme"); h.YAML["bus"] != nil {
		t.Fatalf("bgp must not advertise a collector lane: %+v", h)
	}
	if h := collectorConfig("flow", "tenant-a", "agent-a", "", ""); h.YAML["bus"] != nil {
		t.Fatalf("no slug, no lane hint: %+v", h)
	}
	// DPR-051: eBPF carries the registered identity as agent_id, not host.
	if h := collectorConfig("ebpf", "tenant-a", "agent-a", "", "t-acme"); h.Env["PROBECTL_EBPF_AGENT_ID"] != "agent-a" || h.YAML["agent_id"] != "agent-a" || h.Env["PROBECTL_EBPF_HOST"] != "" || h.YAML["host"] != nil {
		t.Fatalf("ebpf hint must name the registered collector as agent_id: %+v", h)
	}
}

// TestSuccessfulIssuanceAndRotationAreAudited (DPR-098): the lab rotated an
// agent's SVID twice and the tenant audit stream showed nothing — only token
// minting and collector registration were audited. A first SVID and every
// rotation now land in the agent's tenant stream, attributed to the agent,
// with the serial and expiry an investigator needs; a failed append never
// turns into a rotation failure.
func TestSuccessfulIssuanceAndRotationAreAudited(t *testing.T) {
	identity := &enroll.Identity{
		SPIFFEID: "spiffe://probectl/tenant/11111111-1111-4111-8111-111111111111/agent/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		TenantID: "11111111-1111-4111-8111-111111111111", AgentID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Plane: "synthetic", Serial: "0a1b2c", NotAfter: time.Date(2026, 9, 18, 6, 11, 26, 0, time.UTC),
	}
	const (
		csrPEM  = "-----BEGIN CERTIFICATE REQUEST-----\\nZmFrZS1jc3ItZm9yLWF1ZGl0LXRlc3Q=\\n-----END CERTIFICATE REQUEST-----\\n"
		certPEM = "-----BEGIN CERTIFICATE-----\\nZmFrZS1jZXJ0LWZvci1hdWRpdC10ZXN0\\n-----END CERTIFICATE-----\\n"
	)
	for _, tc := range []struct {
		name, path, body, wantAction string
	}{
		{"enroll", "/enroll/agent", `{"token":"join-token","csr_pem":"` + csrPEM + `"}`, agentEnrolledAuditAction},
		{"rotate", "/enroll/agent/rotate", `{"cert_pem":"` + certPEM + `","csr_pem":"` + csrPEM + `","proof":"00ff"}`, agentIdentityRotatedAuditAction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := testServer(nil)
			srv.enrollSvc = forensicEnrollmentService{identity: identity}
			type call struct {
				tenant, agent, action string
				data                  map[string]any
			}
			var calls []call
			srv.identityAudit = func(_ context.Context, tenantID, agentID, action string, data map[string]any) error {
				calls = append(calls, call{tenantID, agentID, action, data})
				return nil
			}
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}
			if len(calls) != 1 {
				t.Fatalf("audit calls = %d, want 1", len(calls))
			}
			c := calls[0]
			if c.tenant != identity.TenantID || c.agent != identity.AgentID || c.action != tc.wantAction {
				t.Fatalf("audited %+v, want %s for %s/%s", c, tc.wantAction, identity.TenantID, identity.AgentID)
			}
			if c.data["serial"] != identity.Serial || c.data["not_after"] != "2026-09-18T06:11:26Z" || c.data["spiffe_id"] != identity.SPIFFEID {
				t.Fatalf("audit data must carry serial, expiry and identity: %v", c.data)
			}
			if strings.Contains(fmt.Sprint(c.data), "PRIVATE KEY") || strings.Contains(fmt.Sprint(c.data), "ZmFrZS1jc3It") {
				t.Fatal("audit data must never carry key material or the CSR")
			}

			// The append failing must not fail the issuance.
			srv.identityAudit = func(context.Context, string, string, string, map[string]any) error {
				return errors.New("audit store down")
			}
			rec = httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if rec.Code != http.StatusOK {
				t.Fatalf("a failed audit append must not fail the issuance: %d", rec.Code)
			}
		})
	}
}
