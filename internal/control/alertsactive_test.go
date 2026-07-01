// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// stubAlertState is a deterministic AlertStateSource standing in for the
// evaluator engine.
type stubAlertState struct {
	items   map[string]*alert.ActiveAlert
	windows map[string]alert.MaintenanceWindow
}

func newStubAlertState() *stubAlertState {
	since := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	return &stubAlertState{
		items: map[string]*alert.ActiveAlert{
			"fp-1": {Fingerprint: "fp-1", RuleID: "r1", RuleName: "rtt high", Severity: alert.SeverityCritical,
				Metric: "probectl_result_rtt_ms", Labels: map[string]string{"target": "db"},
				Value: 250, Reason: "rtt=250 gt 100", Since: since, LastSeenAt: since},
		},
		windows: map[string]alert.MaintenanceWindow{},
	}
}

func (s *stubAlertState) Active() []alert.ActiveAlert {
	out := make([]alert.ActiveAlert, 0, len(s.items))
	for _, a := range s.items {
		out = append(out, *a)
	}
	return out
}

func (s *stubAlertState) Silence(fp string, d time.Duration) (alert.ActiveAlert, error) {
	a, ok := s.items[fp]
	if !ok {
		return alert.ActiveAlert{}, alert.ErrNotActive
	}
	if d == 0 {
		a.SilencedUntil = nil
	} else {
		t := a.Since.Add(d)
		a.SilencedUntil = &t
	}
	return *a, nil
}

func (s *stubAlertState) Acknowledge(fp, by string) (alert.ActiveAlert, error) {
	a, ok := s.items[fp]
	if !ok {
		return alert.ActiveAlert{}, alert.ErrNotActive
	}
	t := a.Since.Add(time.Minute)
	a.AckedBy, a.AckedAt = by, &t
	return *a, nil
}

func (s *stubAlertState) MaintenanceWindows() []alert.MaintenanceWindow {
	out := make([]alert.MaintenanceWindow, 0, len(s.windows))
	for _, w := range s.windows {
		out = append(out, w)
	}
	return out
}

func (s *stubAlertState) UpsertMaintenanceWindow(w alert.MaintenanceWindow) (alert.MaintenanceWindow, error) {
	if err := w.Validate(); err != nil {
		return alert.MaintenanceWindow{}, err
	}
	s.windows[w.ID] = w
	return w, nil
}

func (s *stubAlertState) DeleteMaintenanceWindow(id string) bool {
	if _, ok := s.windows[id]; !ok {
		return false
	}
	delete(s.windows, id)
	return true
}

func (s *stubAlertState) PreviewMaintenance(rule alert.Rule, labels map[string]string, from, to time.Time) []alert.MaintenancePreview {
	var out []alert.MaintenancePreview
	for _, w := range s.windows {
		if w.Matches(rule, labels) {
			out = append(out, w.OccurrencesBetween(from, to)...)
		}
	}
	return out
}

func doJSONReq(srv *Server, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestActiveAlertsEndpoint(t *testing.T) {
	srv := testServer(fakePinger{}).WithAlertState(tenancy.DefaultTenantID.String(), newStubAlertState())

	rec := do(srv, http.MethodGet, "/v1/alerts/active")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		EvaluatorRunning bool                `json:"evaluator_running"`
		Items            []alert.ActiveAlert `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.EvaluatorRunning || len(resp.Items) != 1 || resp.Items[0].RuleName != "rtt high" {
		t.Fatalf("resp = %+v", resp)
	}

	// No engine for the tenant: empty + evaluator_running=false (fail closed).
	bare := testServer(fakePinger{})
	rec = do(bare, http.MethodGet, "/v1/alerts/active")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"evaluator_running":false`) {
		t.Fatalf("bare = %d %s", rec.Code, rec.Body.String())
	}

	// TENANT BOUNDARY: a caller from another tenant gets no engine — and
	// therefore none of the default tenant's alerts.
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/active", nil)
	req.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	srv.Handler().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("other tenant = %d", rec2.Code)
	}
	if strings.Contains(rec2.Body.String(), "rtt high") {
		t.Fatalf("CROSS-TENANT LEAK: %s", rec2.Body.String())
	}
}

func TestSilenceAndAckEndpoints(t *testing.T) {
	srv := testServer(fakePinger{}).WithAlertState(tenancy.DefaultTenantID.String(), newStubAlertState())

	rec := doJSONReq(srv, http.MethodPost, "/v1/alerts/active/silence", `{"fingerprint":"fp-1","duration_minutes":30}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "silenced_until") {
		t.Fatalf("silence = %d %s", rec.Code, rec.Body.String())
	}

	// Ack records the dev principal's identity (engine truth in the response).
	rec = doJSONReq(srv, http.MethodPost, "/v1/alerts/active/ack", `{"fingerprint":"fp-1"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "dev@probectl.local") {
		t.Fatalf("ack = %d %s", rec.Code, rec.Body.String())
	}

	// Unknown fingerprint -> 404; missing fingerprint -> 422/400; no engine -> 503.
	if rec := doJSONReq(srv, http.MethodPost, "/v1/alerts/active/silence", `{"fingerprint":"nope"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown fp = %d", rec.Code)
	}
	if rec := doJSONReq(srv, http.MethodPost, "/v1/alerts/active/ack", `{}`); rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
		t.Fatalf("missing fp = %d", rec.Code)
	}
	bare := testServer(fakePinger{})
	if rec := doJSONReq(bare, http.MethodPost, "/v1/alerts/active/ack", `{"fingerprint":"fp-1"}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no engine = %d", rec.Code)
	}
}

func TestMaintenanceWindowEndpoints(t *testing.T) {
	state := newStubAlertState()
	srv := testServer(fakePinger{}).WithAlertState(tenancy.DefaultTenantID.String(), state)
	body := `{"id":"mw-api","name":"database patch","reason":"planned deploy","starts_at":"2026-06-04T12:00:00Z","ends_at":"2026-06-04T13:00:00Z","recurrence":"daily","match":{"target":"db"},"rule_ids":["r1"]}`

	rec := doJSONReq(srv, http.MethodPost, "/v1/alerts/maintenance", body)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"created_by":"dev@probectl.local"`) {
		t.Fatalf("upsert maintenance = %d %s", rec.Code, rec.Body.String())
	}

	rec = do(srv, http.MethodGet, "/v1/alerts/maintenance")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "database patch") {
		t.Fatalf("list maintenance = %d %s", rec.Code, rec.Body.String())
	}

	rec = doJSONReq(srv, http.MethodPost, "/v1/alerts/maintenance/preview", `{"rule_id":"r1","labels":{"target":"db"},"from":"2026-06-04T12:00:00Z","to":"2026-06-06T12:00:00Z"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"window_id":"mw-api"`) {
		t.Fatalf("preview maintenance = %d %s", rec.Code, rec.Body.String())
	}

	rec = do(srv, http.MethodDelete, "/v1/alerts/maintenance/mw-api")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete maintenance = %d %s", rec.Code, rec.Body.String())
	}

	// Another tenant gets no engine/schedule from the default tenant.
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/maintenance", nil)
	req.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	srv.Handler().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK || strings.Contains(rec2.Body.String(), "database patch") {
		t.Fatalf("cross-tenant list leaked maintenance: %d %s", rec2.Code, rec2.Body.String())
	}
}

func TestActiveAlertRoutePerms(t *testing.T) {
	srv := testServer(fakePinger{})
	want := map[string]string{
		"GET /v1/alerts/active":               permAlertRead,
		"POST /v1/alerts/active/silence":      permAlertWrite,
		"POST /v1/alerts/active/ack":          permAlertWrite,
		"GET /v1/alerts/maintenance":          permAlertRead,
		"POST /v1/alerts/maintenance":         permAlertWrite,
		"POST /v1/alerts/maintenance/preview": permAlertRead,
		"DELETE /v1/alerts/maintenance/{id}":  permAlertWrite,
	}
	seen := 0
	for _, rt := range srv.apiRoutes() {
		key := rt.Method + " " + rt.Pattern
		if p, ok := want[key]; ok {
			seen++
			if rt.Permission != p {
				t.Errorf("%s perm = %q, want %q", key, rt.Permission, p)
			}
		}
	}
	if seen != len(want) {
		t.Fatalf("routes registered = %d, want %d", seen, len(want))
	}
}
