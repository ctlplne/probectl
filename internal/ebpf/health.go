package ebpf

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Health server (OPS-001): the eBPF agent DaemonSet needs real liveness +
// readiness signals for Kubernetes. This is a tiny, plaintext, LOOPBACK-bound
// (or pod-local) HTTP server — it carries NO telemetry, only the agent's own
// up/ready booleans, so it is exempt from the TLS-everywhere rule the way
// /healthz is (no tenant data crosses it; guardrail 12 covers data channels).
//
//	GET /healthz → 200 once the process is running its loop (liveness)
//	GET /readyz  → 200 once the flow source is attached + streaming (readiness)
//
// A k8s probe restarts the pod on a failing /healthz and pulls it from
// endpoints on a failing /readyz — so a stuck attach (e.g. lost CAP_PERFMON,
// kernel lockdown) is visible instead of a silently-dead agent.

// healthChecker is the readiness/liveness source (the Agent satisfies it).
type healthChecker interface {
	Live() bool
	Ready() bool
}

// HealthServer serves the agent's probe endpoints on addr.
type HealthServer struct {
	srv *http.Server
}

// NewHealthServer builds the probe server over c at addr (e.g. ":9090").
func NewHealthServer(addr string, c healthChecker) *HealthServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, c.Live(), "live")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, c.Ready(), "ready")
	})
	return &HealthServer{srv: &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}}
}

// Run serves until ctx is canceled, then shuts down gracefully. A nil
// HealthServer is a no-op (health disabled).
func (h *HealthServer) Run(ctx context.Context) error {
	if h == nil {
		return nil
	}
	errCh := make(chan error, 1)
	go func() {
		if err := h.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return h.srv.Shutdown(sctx)
	case err := <-errCh:
		return err
	}
}

func writeHealth(w http.ResponseWriter, ok bool, label string) {
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{label: ok})
}
