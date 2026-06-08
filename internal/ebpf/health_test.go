package ebpf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeHealth struct{ live, ready bool }

func (f fakeHealth) Live() bool  { return f.live }
func (f fakeHealth) Ready() bool { return f.ready }

// OPS-001: the probe endpoints reflect liveness/readiness with the right
// status codes so Kubernetes restarts a dead agent and depools a not-ready
// one.
func TestHealthEndpoints(t *testing.T) {
	cases := []struct {
		name              string
		c                 fakeHealth
		wantLive, wantRdy int
	}{
		{"starting: live, not ready", fakeHealth{live: true, ready: false}, 200, 503},
		{"attached: live + ready", fakeHealth{live: true, ready: true}, 200, 200},
		{"dead: neither", fakeHealth{live: false, ready: false}, 503, 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHealthServer(":0", tc.c)
			for path, want := range map[string]int{"/healthz": tc.wantLive, "/readyz": tc.wantRdy} {
				rec := httptest.NewRecorder()
				h.srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
				if rec.Code != want {
					t.Errorf("%s = %d, want %d", path, rec.Code, want)
				}
			}
		})
	}
}

// A nil HealthServer.Run is a no-op (health disabled — the dev/no-k8s
// default).
func TestNilHealthServerRunNoop(t *testing.T) {
	var h *HealthServer
	if err := h.Run(nil); err != nil { //nolint:staticcheck // nil ctx is fine for the nil-receiver no-op
		t.Fatalf("nil health server must be a no-op: %v", err)
	}
}
