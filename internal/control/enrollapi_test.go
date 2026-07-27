// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
