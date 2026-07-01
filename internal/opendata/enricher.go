// SPDX-License-Identifier: LicenseRef-probectl-TBD

package opendata

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/metrics"
)

const (
	defaultSourceTimeout = 5 * time.Second
	defaultCacheTTL      = time.Hour
)

// managedSource pairs a registered source with its mutable health.
type managedSource struct {
	src    Source
	health Health
}

// Enricher runs an IP through every enabled source and merges the results,
// degrading gracefully: a source that is disabled, errors, times out, or panics
// is logged and skipped, and never fails the enrichment (a core path must not
// break because an external dataset is unavailable — S15 Done-when).
type Enricher struct {
	log     *slog.Logger
	timeout time.Duration
	cache   *cache

	mu      sync.Mutex
	sources []*managedSource
}

// Option configures an Enricher.
type Option func(*Enricher)

// WithSourceTimeout bounds each source's per-lookup time.
func WithSourceTimeout(d time.Duration) Option { return func(e *Enricher) { e.timeout = d } }

// WithCacheTTL sets the enrichment cache TTL (0 disables caching).
func WithCacheTTL(d time.Duration) Option { return func(e *Enricher) { e.cache.setTTL(d) } }

// WithCacheMaxEntries sets the hard entry cap for the shared enrichment cache.
// Non-positive values disable caching; callers normally keep the finite default.
func WithCacheMaxEntries(n int) Option { return func(e *Enricher) { e.cache.setMax(n) } }

// NewEnricher builds an Enricher. Register sources with Register.
func NewEnricher(log *slog.Logger, opts ...Option) *Enricher {
	if log == nil {
		log = slog.Default()
	}
	e := &Enricher{log: log, timeout: defaultSourceTimeout, cache: newCache(defaultCacheTTL)}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// WithMetrics exposes aggregate cache metrics. The cache is shared and
// tenant-agnostic, so these are process/cache metrics with no tenant labels.
func (en *Enricher) WithMetrics(reg *metrics.Registry) *Enricher {
	en.cache.withMetrics(reg)
	return en
}

// CacheStats returns aggregate cache behavior for tests and diagnostics.
func (en *Enricher) CacheStats() CacheStats { return en.cache.stats() }

// Register adds a source (enabled by default). Sources run in registration order,
// so an ASN-providing source (Team Cymru) should be registered before one that
// keys on the ASN (PeeringDB).
func (en *Enricher) Register(s Source) {
	en.mu.Lock()
	defer en.mu.Unlock()
	en.sources = append(en.sources, &managedSource{
		src:    s,
		health: Health{Enabled: true, Status: "ok"},
	})
}

// SetEnabled enables/disables a source by name (e.g. to honor an AUP restriction
// or quarantine a flapping upstream). A disabled source is skipped, not removed.
func (en *Enricher) SetEnabled(name string, enabled bool) {
	en.mu.Lock()
	defer en.mu.Unlock()
	for _, ms := range en.sources {
		if ms.src.Descriptor().Name == name {
			ms.health.Enabled = enabled
			if !enabled {
				ms.health.Status = "disabled"
			} else if ms.health.Status == "disabled" {
				ms.health.Status = "ok"
			}
			return
		}
	}
}

// SourceStatus is a source's descriptor + current health — the OpenDataSource
// "AUP/health matrix" surfaced to operators.
type SourceStatus struct {
	Descriptor Descriptor
	Health     Health
}

// Status returns the current descriptor + health of every registered source.
func (en *Enricher) Status() []SourceStatus {
	en.mu.Lock()
	defer en.mu.Unlock()
	out := make([]SourceStatus, 0, len(en.sources))
	for _, ms := range en.sources {
		out = append(out, SourceStatus{Descriptor: ms.src.Descriptor(), Health: ms.health})
	}
	return out
}

// Enrich annotates ip with every enabled source's context. It returns an error
// only for an unparseable IP; a source failure degrades to a partial result.
func (en *Enricher) Enrich(ctx context.Context, ip string) (Enrichment, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Enrichment{IP: ip}, fmt.Errorf("opendata: invalid ip %q: %w", ip, err)
	}
	if cached, ok := en.cache.get(ip); ok {
		return cached, nil
	}

	en.mu.Lock()
	snapshot := append([]*managedSource(nil), en.sources...)
	en.mu.Unlock()

	e := Enrichment{IP: ip}
	for _, ms := range snapshot {
		if !en.enabled(ms) {
			continue
		}
		serr := en.runSource(ctx, ms.src, addr, &e)
		en.recordHealth(ms, ms.src.Descriptor().Name, serr)
	}

	en.cache.put(ip, e)
	return e, nil
}

func (en *Enricher) enabled(ms *managedSource) bool {
	en.mu.Lock()
	defer en.mu.Unlock()
	return ms.health.Enabled
}

// runSource invokes one source under a timeout, converting a panic into an error
// so a misbehaving plugin can never crash enrichment (defense in depth).
func (en *Enricher) runSource(ctx context.Context, s Source, addr netip.Addr, e *Enrichment) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("source panicked: %v", r)
		}
	}()
	sctx, cancel := context.WithTimeout(ctx, en.timeout)
	defer cancel()
	return s.Enrich(sctx, addr, e)
}

func (en *Enricher) recordHealth(ms *managedSource, name string, err error) {
	en.mu.Lock()
	defer en.mu.Unlock()
	if err != nil {
		ms.health.Status = "degraded"
		ms.health.LastError = err.Error()
		en.log.Warn("opendata source degraded; skipping",
			"source", name, "error", err)
		return
	}
	ms.health.Status = "ok"
	ms.health.LastError = ""
	ms.health.LastSuccess = time.Now()
}
