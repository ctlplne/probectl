// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"context"
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
}

func (f forensicEnrollmentService) Enroll(context.Context, enroll.Request) (*enroll.Identity, error) {
	return nil, f.enrollErr
}

func (forensicEnrollmentService) MintToken(context.Context, string, string, string, string, time.Duration) (string, string, error) {
	return "", "", nil
}

func (forensicEnrollmentService) RegisterCollectorForTenant(context.Context, string, string, string, string, string) (*enroll.CollectorIdentity, error) {
	return nil, nil
}

func (f forensicEnrollmentService) Rotate(context.Context, enroll.RotateRequest) (*enroll.Identity, error) {
	return nil, f.rotateErr
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
	hint := collectorConfig("device", "tenant-a", "agent-a", "topology-rich")
	if got := hint.Env["PROBECTL_DEVICE_PROFILE"]; got != "topology-rich" {
		t.Fatalf("profile env = %q", got)
	}
	if got := hint.YAML["collection_profile"]; got != "topology-rich" {
		t.Fatalf("profile YAML = %q", got)
	}
}
