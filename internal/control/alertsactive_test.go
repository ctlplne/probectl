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
	items map[string]*alert.ActiveAlert
}

func newStubAlertState() *stubAlertState {
	since := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	return &stubAlertState{items: map[string]*alert.ActiveAlert{
		"fp-1": {Fingerprint: "fp-1", RuleID: "r1", RuleName: "rtt high", Severity: alert.SeverityCritical,
			Metric: "probectl_result_rtt_ms", Labels: map[string]string{"target": "db"},
			Value: 250, Reason: "rtt=250 gt 100", Since: since, LastSeenAt: since},
	}}
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

func TestActiveAlertRoutePerms(t *testing.T) {
	srv := testServer(fakePinger{})
	want := map[string]string{
		"/v1/alerts/active":         permAlertRead,
		"/v1/alerts/active/silence": permAlertWrite,
		"/v1/alerts/active/ack":     permAlertWrite,
	}
	seen := 0
	for _, rt := range srv.apiRoutes() {
		if p, ok := want[rt.Pattern]; ok {
			seen++
			if rt.Permission != p {
				t.Errorf("%s perm = %q, want %q", rt.Pattern, rt.Permission, p)
			}
		}
	}
	if seen != len(want) {
		t.Fatalf("routes registered = %d, want %d", seen, len(want))
	}
}
