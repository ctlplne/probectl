package endpoint

import (
	"context"
	"log/slog"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
)

// Runtime is the endpoint agent: on an interval it collects a DEM sample,
// attributes any slowdown, and emits the results to the bus. It mirrors the
// canary/eBPF agents (New + Run), and like them it never phones home — results go
// only to the operator's own bus, tenant-tagged.
type Runtime struct {
	cfg       *Config
	collector *Collector
	emitter   Emitter
	log       *slog.Logger
}

// New builds the runtime with the real platform collectors (per-OS WiFi reader,
// system traceroute, hardened HTTP session) and the bus emitter.
func New(cfg *Config, b bus.Bus, log *slog.Logger) (*Runtime, error) {
	collector := NewCollector(cfg,
		newPlatformWiFiCollector(),
		newPlatformLastMileCollector(cfg.Probes, cfg.MaxHops),
		NewHTTPSessionCollector(cfg.SessionTimeout),
	)
	return &Runtime{
		cfg:       cfg,
		collector: collector,
		emitter:   NewBusEmitter(b, cfg.TenantID, cfg.AgentID),
		log:       log,
	}, nil
}

// NewWith builds a runtime from an explicit collector + emitter (the test seam).
func NewWith(cfg *Config, collector *Collector, emitter Emitter, log *slog.Logger) *Runtime {
	return &Runtime{cfg: cfg, collector: collector, emitter: emitter, log: log}
}

// Run collects + emits on the configured interval until ctx is canceled. A
// collection or emit error is logged and the loop continues (one bad sample must
// not stop monitoring).
func (r *Runtime) Run(ctx context.Context) error {
	r.discloseCollection()
	r.log.Info("endpoint agent starting",
		"tenant", r.cfg.TenantID, "agent", r.cfg.AgentID,
		"interval", r.cfg.Interval.String(), "topic", bus.EndpointResultsTopic,
		"targets", len(r.cfg.Targets))

	r.tick(ctx) // emit one sample immediately, then on the interval
	t := time.NewTicker(r.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.log.Info("endpoint agent stopping")
			return nil
		case <-t.C:
			r.tick(ctx)
		}
	}
}

// tick collects one sample, logs the attribution verdict, and emits it.
func (r *Runtime) tick(ctx context.Context) {
	s := r.collector.Collect(ctx)
	a := s.Attribution
	r.log.Info("endpoint sample",
		"cause", string(a.Cause), "confidence", a.Confidence, "slow", a.Slow, "summary", a.Summary)
	if err := r.emitter.Emit(ctx, s); err != nil {
		r.log.Warn("endpoint emit failed", "err", err)
	}
}

// discloseCollection logs exactly what this agent collects, every start — it runs
// on an end-user device, so the data it gathers must be transparent.
func (r *Runtime) discloseCollection() {
	for _, line := range r.cfg.Privacy.Disclosure() {
		r.log.Info("endpoint data-collection disclosure", "collects", line)
	}
}
