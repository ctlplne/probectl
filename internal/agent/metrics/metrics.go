// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package agentmetrics provides the shared, tenant-agnostic Prometheus surface
// used by every probectl collector binary. It deliberately exports process and
// aggregate pipeline health only: tenant ids, targets, devices, and payload
// attributes never become labels.
package agentmetrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ctlplne/probectl/internal/crypto"
	basemetrics "github.com/ctlplne/probectl/internal/metrics"
)

const (
	// Default ports are distinct so several collectors can coexist on one host.
	DefaultCanaryAddr   = "127.0.0.1:9464"
	DefaultFlowAddr     = "127.0.0.1:9465"
	DefaultDeviceAddr   = "127.0.0.1:9466"
	DefaultEBPFAddr     = "127.0.0.1:9467"
	DefaultEndpointAddr = "127.0.0.1:9468"
	DefaultBMPAddr      = "127.0.0.1:9469"
)

// Components is the complete shipped collector-binary set covered by H6.
var Components = []string{
	"probectl-agent",
	"probectl-flow-agent",
	"probectl-device-agent",
	"probectl-ebpf-agent",
	"probectl-endpoint",
	"probectl-bmp-listener",
}

// Config controls one agent's metrics listener. Plain HTTP is accepted only on
// loopback. A bind reachable from another host requires a TLS certificate/key.
type Config struct {
	Addr        string
	TLSCertFile string
	TLSKeyFile  string
}

// ConfigFromEnv reads PREFIX_METRICS_{ADDR,TLS_CERT_FILE,TLS_KEY_FILE}.
func ConfigFromEnv(getenv func(string) string, prefix, defaultAddr string) Config {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	addr := strings.TrimSpace(getenv(prefix + "_METRICS_ADDR"))
	if addr == "" {
		addr = defaultAddr
	}
	return Config{
		Addr:        addr,
		TLSCertFile: strings.TrimSpace(getenv(prefix + "_METRICS_TLS_CERT_FILE")),
		TLSKeyFile:  strings.TrimSpace(getenv(prefix + "_METRICS_TLS_KEY_FILE")),
	}
}

// Runtime owns both the metrics values and their HTTP(S) listener.
type Runtime struct {
	cfg Config
	srv *http.Server

	collections *basemetrics.Counter
	published   *basemetrics.Counter
	errors      *basemetrics.Counter
	timeouts    *basemetrics.Counter
	rejections  *basemetrics.Counter

	bufferDepth atomic.Int64
	active      atomic.Int64
	latencyBits atomic.Uint64

	ready     chan struct{}
	readyOnce sync.Once
	addrMu    sync.RWMutex
	addr      string
}

// New builds an agent metrics runtime. The listener is opened by Serve or
// RunTogether, so construction remains side-effect free.
func New(component, version, commit string, cfg Config) (*Runtime, error) {
	if !knownComponent(component) {
		return nil, fmt.Errorf("agent metrics: unknown component %q", component)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	reg := basemetrics.New(version, commit)
	r := &Runtime{
		cfg:         cfg,
		collections: reg.Counter("probectl_agent_collections_total", "Probe or collector batches attempted by this agent process."),
		published:   reg.Counter("probectl_agent_published_total", "Results or batches accepted by this agent process's output transport."),
		errors:      reg.Counter("probectl_agent_errors_total", "Probe, collection, buffer, or publish errors observed by this agent process."),
		timeouts:    reg.Counter("probectl_agent_session_timeouts_total", "Inbound collector sessions closed after a bounded handshake or read timeout."),
		rejections:  reg.Counter("probectl_agent_session_rejections_total", "Inbound collector sessions rejected by the process-wide concurrency bound."),
		ready:       make(chan struct{}),
	}
	reg.Gauge("probectl_agent_buffer_depth", "Results currently waiting in this agent process's local buffer or queue.", func() float64 {
		return float64(r.bufferDepth.Load())
	})
	reg.Gauge("probectl_agent_publish_latency_seconds", "Wall-clock seconds used by the most recently completed publish attempt.", func() float64 {
		return math.Float64frombits(r.latencyBits.Load())
	})
	reg.Gauge("probectl_agent_active_sessions", "Inbound collector sessions currently admitted by this process.", func() float64 {
		return float64(r.active.Load())
	})
	reg.Gauge("probectl_agent_metrics_tls", "Whether this agent metrics listener uses TLS (1 yes, 0 loopback-only HTTP).", func() float64 {
		if r.usesTLS() {
			return 1
		}
		return 0
	})

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", reg.Handler())
	r.srv = &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	if r.usesTLS() {
		if err := crypto.ConfigureServerTLS(r.srv, cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
			return nil, fmt.Errorf("agent metrics: configure TLS: %w", err)
		}
	}
	return r, nil
}

func knownComponent(component string) bool {
	for _, candidate := range Components {
		if component == candidate {
			return true
		}
	}
	return false
}

func (c Config) validate() error {
	if c.Addr == "" {
		return errors.New("agent metrics: listen address is required")
	}
	host, _, err := net.SplitHostPort(c.Addr)
	if err != nil {
		return fmt.Errorf("agent metrics: invalid listen address %q: %w", c.Addr, err)
	}
	hasCert, hasKey := c.TLSCertFile != "", c.TLSKeyFile != ""
	if hasCert != hasKey {
		return errors.New("agent metrics: TLS certificate and key must be configured together")
	}
	if !hasCert && !isLoopbackHost(host) {
		return fmt.Errorf("agent metrics: non-loopback address %q requires TLS certificate and key", c.Addr)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (r *Runtime) usesTLS() bool { return r.cfg.TLSCertFile != "" }

// Collection records n completed probe/collector units. A publish-observing
// bus calls this once per batch; the synthetic agent calls it once per probe.
func (r *Runtime) Collection(n uint64) {
	if r != nil && n > 0 {
		r.collections.Add(n)
	}
}

// Error records one operational error without attaching tenant data.
func (r *Runtime) Error() {
	if r != nil {
		r.errors.Inc()
	}
}

// Publish records the outcome and duration of one publish attempt. n is the
// number of results/batches durably accepted; failures increment errors only.
func (r *Runtime) Publish(n uint64, latency time.Duration, err error) {
	if r == nil {
		return
	}
	r.latencyBits.Store(math.Float64bits(max(0, latency.Seconds())))
	if err != nil {
		r.errors.Inc()
		return
	}
	if n > 0 {
		r.published.Add(n)
	}
}

// SetBufferDepth updates the current bounded queue/backlog depth.
func (r *Runtime) SetBufferDepth(depth int) {
	if r == nil {
		return
	}
	if depth < 0 {
		depth = 0
	}
	r.bufferDepth.Store(int64(depth))
}

// SessionTimeout records one inbound collector session closed by its bounded
// handshake or rolling read deadline.
func (r *Runtime) SessionTimeout() {
	if r != nil {
		r.timeouts.Inc()
	}
}

// SessionAdmissionRejected records one inbound session refused because the
// process-wide concurrency bound was already full.
func (r *Runtime) SessionAdmissionRejected() {
	if r != nil {
		r.rejections.Inc()
	}
}

// SetActiveSessions updates the aggregate number of admitted inbound sessions.
// It deliberately carries no tenant or peer labels.
func (r *Runtime) SetActiveSessions(active int) {
	if r == nil {
		return
	}
	if active < 0 {
		active = 0
	}
	r.active.Store(int64(active))
}

// Serve opens the configured listener and blocks until it fails or ctx is
// canceled. TLS listeners use internal/crypto's TLS 1.3 server policy.
func (r *Runtime) Serve(ctx context.Context) error {
	if r == nil {
		return errors.New("agent metrics: nil runtime")
	}
	ln, err := net.Listen("tcp", r.cfg.Addr)
	if err != nil {
		return fmt.Errorf("agent metrics: listen %s: %w", r.cfg.Addr, err)
	}
	r.addrMu.Lock()
	r.addr = ln.Addr().String()
	r.addrMu.Unlock()
	r.readyOnce.Do(func() { close(r.ready) })

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = r.srv.Shutdown(shutdownCtx)
	}()
	if r.usesTLS() {
		err = r.srv.ServeTLS(ln, "", "")
	} else {
		err = r.srv.Serve(ln)
	}
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("agent metrics: serve: %w", err)
}

// Ready closes after the listener has bound successfully. It is a test/smoke
// synchronization seam, not a network health endpoint.
func (r *Runtime) Ready() <-chan struct{} { return r.ready }

// Addr returns the actual bound address (useful when Config.Addr uses port 0).
func (r *Runtime) Addr() string {
	r.addrMu.RLock()
	defer r.addrMu.RUnlock()
	return r.addr
}

// RunTogether supervises the metrics listener and the collector as one unit.
// Either failure cancels the other; a finite job (for example cloud-flow import)
// also shuts its metrics listener down cleanly when the job completes.
func (r *Runtime) RunTogether(ctx context.Context, workload func(context.Context) error) error {
	if workload == nil {
		return errors.New("agent metrics: workload is required")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, gctx := errgroup.WithContext(runCtx)
	g.Go(func() error { return r.Serve(gctx) })
	g.Go(func() error {
		defer cancel()
		err := workload(gctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			r.Error()
		}
		return err
	})
	return g.Wait()
}
