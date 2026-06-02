package opendata

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// IntelRefresher periodically refreshes a set of threat-intel feeds into an
// IOCStore. It keeps each source's LAST-GOOD IOCs, so a feed that is down /
// rate-limited / malformed leaves the prior indicators in place (graceful
// degradation — CLAUDE.md §7 guardrail 10). Feeds are shared infrastructure,
// ingested once.
type IntelRefresher struct {
	store    *IOCStore
	sources  []ThreatIntelSource
	interval time.Duration
	log      *slog.Logger

	mu       sync.Mutex
	lastGood map[string][]IOC
}

// NewIntelRefresher builds a refresher over the given feeds.
func NewIntelRefresher(store *IOCStore, sources []ThreatIntelSource, interval time.Duration, log *slog.Logger) *IntelRefresher {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	if log == nil {
		log = slog.Default()
	}
	return &IntelRefresher{store: store, sources: sources, interval: interval, log: log, lastGood: map[string][]IOC{}}
}

// Refresh fetches every source once — keeping the prior IOCs on failure — then
// rebuilds the store from the union. Returns the number of indicators loaded.
func (r *IntelRefresher) Refresh(ctx context.Context) int {
	for _, s := range r.sources {
		name := s.Descriptor().Name
		iocs, err := s.Fetch(ctx)
		if err != nil {
			r.log.Warn("threat-intel feed refresh failed (keeping last-good)", "source", name, "error", err)
			continue
		}
		r.mu.Lock()
		r.lastGood[name] = iocs
		r.mu.Unlock()
		r.log.Info("threat-intel feed refreshed", "source", name, "iocs", len(iocs))
	}
	union := r.union()
	r.store.Load(union)
	return len(union)
}

func (r *IntelRefresher) union() []IOC {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []IOC
	for _, iocs := range r.lastGood {
		out = append(out, iocs...)
	}
	return out
}

// Run refreshes immediately, then on the configured interval until ctx is done.
func (r *IntelRefresher) Run(ctx context.Context) error {
	r.Refresh(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			r.Refresh(ctx)
		}
	}
}
