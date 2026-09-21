// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/threat"
)

func seededDetections() *threat.DetectionStore {
	ds := threat.NewDetectionStore(0)
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	ds.Record(tenancy.DefaultTenantID.String(), threat.Detection{
		Kind: "ioc.botnet", Plane: "threat", Severity: "critical", Confidence: 90,
		Source: "feodo", Category: "botnet", Indicator: "203.0.113.66",
		Entity: "203.0.113.66", Title: "203.0.113.66 matches threat-intel indicator (botnet, source feodo)",
		IncidentID: "inc-42", ObservedAt: at,
	})
	ds.Record("00000000-0000-0000-0000-000000000002", threat.Detection{
		Kind: "ioc.tor", Plane: "threat", Severity: "warning", Source: "tor-exits",
		Entity: "secret.other.entity", ObservedAt: at,
	})
	return ds
}

func TestThreatDetectionsEndpoint(t *testing.T) {
	srv := testServer(fakePinger{}).withDetections(seededDetections())

	rec := do(srv, http.MethodGet, "/v1/threat/detections")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		DetectionsRunning bool               `json:"detections_running"`
		Items             []threat.Detection `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.DetectionsRunning || len(resp.Items) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	d := resp.Items[0]
	if d.Source != "feodo" || d.Confidence != 90 || d.IncidentID != "inc-42" || d.Indicator != "203.0.113.66" {
		t.Fatalf("detection = %+v", d)
	}

	// TENANT BOUNDARY both directions.
	if strings.Contains(rec.Body.String(), "secret.other.entity") {
		t.Fatalf("CROSS-TENANT LEAK: %s", rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/threat/detections", nil)
	req.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	srv.Handler().ServeHTTP(rec2, req)
	if !strings.Contains(rec2.Body.String(), "secret.other.entity") || strings.Contains(rec2.Body.String(), "feodo") {
		t.Fatalf("other-tenant view wrong: %s", rec2.Body.String())
	}

	// No store wired: honest empty response.
	bare := do(testServer(fakePinger{}), http.MethodGet, "/v1/threat/detections")
	if bare.Code != http.StatusOK || !strings.Contains(bare.Body.String(), `"detections_running":false`) {
		t.Fatalf("bare = %d %s", bare.Code, bare.Body.String())
	}
}

func TestThreatDetectionsRoutePerm(t *testing.T) {
	for _, rt := range testServer(fakePinger{}).apiRoutes() {
		if rt.Pattern == "/v1/threat/detections" {
			if rt.Permission != permThreatRead {
				t.Fatalf("perm = %q, want threat.read", rt.Permission)
			}
			return
		}
	}
	t.Fatal("/v1/threat/detections not registered")
}
