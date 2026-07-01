// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/cluster"
)

// stubProbe is a settable cluster.Prober for the HTTP-level fence tests.
type stubProbe struct{ p cluster.Probe }

func (s *stubProbe) Probe(context.Context) cluster.Probe { return s.p }

func clusterTopo() cluster.Topology {
	return cluster.Topology{Region: "us-east", Regions: []string{"us-east", "eu-west"},
		ReplicationMode: cluster.ReplicationSync, RTOSeconds: 60}
}

// TestWriteFenceStartupFailsClosedUntilFirstWriterProbe: a configured cluster
// manager starts fenced. Every mutating method stays read-only until the first
// successful writer-role probe proves the endpoint is safe.
func TestWriteFenceStartupFailsClosedUntilFirstWriterProbe(t *testing.T) {
	srv := testServer(nil)
	probe := &stubProbe{p: cluster.Probe{InRecovery: false, Epoch: 1, WriterRegion: "us-east"}}
	mgr := cluster.NewManager(clusterTopo(), probe, nil)
	srv.WithCluster(mgr)

	mutating := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/tests"},
		{http.MethodPut, "/v1/tests/startup-fence"},
		{http.MethodPatch, "/v1/tests/startup-fence"},
		{http.MethodDelete, "/v1/tests/startup-fence"},
	}
	for _, tc := range mutating {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`)))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "writer_unavailable") {
			t.Fatalf("%s %s before first probe = %d %s, want 503 writer_unavailable", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}

	mgr.Refresh(context.Background())
	for _, tc := range mutating {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`)))
		if rr.Code == http.StatusServiceUnavailable && strings.Contains(rr.Body.String(), "writer_unavailable") {
			t.Fatalf("%s %s after writer probe must not be fenced: %s", tc.method, tc.path, rr.Body.String())
		}
	}
}

// TestWriteFenceDuringFailover: while the writer is fenced (a failover in
// progress), mutating API requests get 503 writer_unavailable with Retry-After,
// reads keep working, and /readyz stays 200 (ready for reads) but reports
// writes_usable=false — the "surfaced via existing health/status" contract.
func TestWriteFenceDuringFailover(t *testing.T) {
	srv := testServer(nil)
	probe := &stubProbe{p: cluster.Probe{InRecovery: false, Epoch: 1, WriterRegion: "us-east"}}
	mgr := cluster.NewManager(clusterTopo(), probe, nil)
	srv.WithCluster(mgr)
	ctx := context.Background()

	// Healthy primary: a write is NOT fenced (it 404s/whatever downstream, but
	// never 503 writer_unavailable).
	mgr.Refresh(ctx)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/tests", strings.NewReader(`{}`)))
	if rr.Code == http.StatusServiceUnavailable && strings.Contains(rr.Body.String(), "writer_unavailable") {
		t.Fatalf("a healthy primary must not fence writes: %s", rr.Body.String())
	}

	// Failover: the writer endpoint now points at a read-only standby.
	probe.p = cluster.Probe{InRecovery: true, Epoch: 1}
	mgr.Refresh(ctx)

	// A mutating request fences with 503 + Retry-After + the stable code.
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/tests", strings.NewReader(`{}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("a fenced writer must 503 on writes, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" || !strings.Contains(rr.Body.String(), "writer_unavailable") {
		t.Fatalf("fence response: %q / %s", rr.Header().Get("Retry-After"), rr.Body.String())
	}

	// Reads keep working — the region still serves traffic during a failover.
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/tests", nil))
	if rr.Code == http.StatusServiceUnavailable {
		t.Fatalf("reads must keep working while writes are fenced: %d", rr.Code)
	}

	// /readyz is still 200 (ready) but reports writes paused.
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("the node must stay ready for reads during a failover: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"writes_usable":false`) || !strings.Contains(rr.Body.String(), `"region":"us-east"`) {
		t.Fatalf("readyz must surface the cluster state: %s", rr.Body.String())
	}

	// Promotion completes: the endpoint catches up to the new primary.
	probe.p = cluster.Probe{InRecovery: false, Epoch: 2, WriterRegion: "eu-west"}
	mgr.Refresh(ctx)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/tests", strings.NewReader(`{}`)))
	if rr.Code == http.StatusServiceUnavailable && strings.Contains(rr.Body.String(), "writer_unavailable") {
		t.Fatalf("writes must resume after promotion: %s", rr.Body.String())
	}
}

// TestWriteFenceExemptsLogin: even with the writer fenced, the auth endpoints
// are reachable so operators can log in to run the failover.
func TestWriteFenceExemptsLogin(t *testing.T) {
	srv := testServer(nil)
	mgr := cluster.NewManager(clusterTopo(), &stubProbe{p: cluster.Probe{InRecovery: true}}, nil)
	srv.WithCluster(mgr)
	mgr.Refresh(context.Background())

	// A POST to an /auth/ path is not fenced (it may fail for other reasons,
	// but never with writer_unavailable).
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
	if strings.Contains(rr.Body.String(), "writer_unavailable") {
		t.Fatalf("auth endpoints must be exempt from the write fence: %s", rr.Body.String())
	}
}

// TestNoClusterNoFence: a single-region deployment (no cluster manager) never
// fences and omits cluster state from /readyz.
func TestNoClusterNoFence(t *testing.T) {
	srv := testServer(nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/tests", strings.NewReader(`{}`)))
	if rr.Code == http.StatusServiceUnavailable && strings.Contains(rr.Body.String(), "writer_unavailable") {
		t.Fatal("single-region deployments must never fence writes")
	}
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if strings.Contains(rr.Body.String(), "cluster") {
		t.Fatalf("readyz must omit cluster state when single-region: %s", rr.Body.String())
	}
}
