// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultHealthStateDir = "/var/run/probectl-ebpf-agent"
	healthFileInterval    = 2 * time.Second
)

// DefaultHealthStateMaxAge is the exec-probe freshness window. It is several
// write intervals so brief scheduling jitter does not flap readiness, but stale
// files from a wedged process fail closed.
const DefaultHealthStateMaxAge = 15 * time.Second

// Health server (OPS-001): the eBPF agent can expose liveness/readiness signals
// for Kubernetes. The secure-by-default Helm path uses health state files plus
// exec probes, so no plaintext listener is opened. This HTTP server remains for
// explicit compatibility-only deployments and carries no tenant telemetry.
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

type healthStateFile struct {
	Status    bool      `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

// StartHealthFileWriter writes liveness/readiness state for exec probes. The
// first write happens synchronously so a bad mount fails startup instead of
// letting Kubernetes discover it later through repeated probe failures.
func StartHealthFileWriter(ctx context.Context, dir string, c healthChecker) error {
	if dir == "" {
		return nil
	}
	if err := writeHealthFiles(dir, c); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(healthFileInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = writeHealthFiles(dir, c)
			}
		}
	}()
	return nil
}

func writeHealthFiles(dir string, c healthChecker) error {
	if c == nil {
		return errors.New("health state: nil checker")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("health state: create dir: %w", err)
	}
	now := time.Now().UTC()
	if err := writeHealthFile(dir, "live", healthStateFile{Status: c.Live(), UpdatedAt: now}); err != nil {
		return err
	}
	if err := writeHealthFile(dir, "ready", healthStateFile{Status: c.Ready(), UpdatedAt: now}); err != nil {
		return err
	}
	return nil
}

func writeHealthFile(dir, name string, st healthStateFile) error {
	if name != "live" && name != "ready" {
		return fmt.Errorf("health state: invalid file %q", name)
	}
	body, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("health state: encode %s: %w", name, err)
	}
	body = append(body, '\n')
	path := filepath.Join(dir, name+".json")
	tmp, err := os.CreateTemp(dir, "."+name+"-*.tmp")
	if err != nil {
		return fmt.Errorf("health state: create %s temp: %w", name, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("health state: write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("health state: close %s: %w", name, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("health state: publish %s: %w", name, err)
	}
	return nil
}

// CheckHealthState verifies one exec-probe state file.
func CheckHealthState(dir, name string, maxAge time.Duration) error {
	if dir == "" {
		dir = DefaultHealthStateDir
	}
	if maxAge <= 0 {
		maxAge = DefaultHealthStateMaxAge
	}
	if name != "live" && name != "ready" {
		return fmt.Errorf("health state: invalid probe %q", name)
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		return fmt.Errorf("health state: read %s: %w", name, err)
	}
	var st healthStateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("health state: decode %s: %w", name, err)
	}
	if !st.Status {
		return fmt.Errorf("health state: %s=false", name)
	}
	if st.UpdatedAt.IsZero() {
		return fmt.Errorf("health state: %s missing updated_at", name)
	}
	if age := time.Since(st.UpdatedAt); age > maxAge {
		return fmt.Errorf("health state: %s stale (%s > %s)", name, age.Round(time.Second), maxAge)
	}
	return nil
}
