// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
)

// Runtime is the endpoint agent: on an interval it collects a DEM sample,
// attributes any slowdown, and emits the results to the bus. It mirrors the
// canary/eBPF agents (New + Run), and like them it never phones home — results go
// only to the operator's own bus, tenant-tagged.
type Runtime struct {
	cfg             *Config
	collector       *Collector
	emitter         Emitter
	log             *slog.Logger
	lastUnavailable string // last "unavailable" set logged (DPR-061)
}

// New builds the runtime with the real platform collectors (per-OS WiFi reader,
// system traceroute, hardened HTTP session) and the bus emitter.
func New(cfg *Config, b bus.Bus, log *slog.Logger) (*Runtime, error) {
	collector := NewCollector(cfg,
		newPlatformWiFiCollector(),
		newPlatformLastMileCollector(cfg.Probes, cfg.MaxHops),
		NewHTTPSessionCollector(cfg.SessionTimeout),
	)
	emitter, eerr := NewNamespacedBusEmitter(b, cfg.TenantID, cfg.AgentID, cfg.Bus.Namespace)
	if eerr != nil {
		return nil, eerr // RED-006: malformed silo namespace refuses start
	}
	return &Runtime{
		cfg:       cfg,
		collector: collector,
		emitter:   emitter,
		log:       log,
	}, nil
}

// newWith builds a runtime from an explicit collector + emitter (the test seam).
func newWith(cfg *Config, collector *Collector, emitter Emitter, log *slog.Logger) *Runtime {
	return &Runtime{cfg: cfg, collector: collector, emitter: emitter, log: log}
}

// Run collects + emits on the configured interval until ctx is canceled. A
// collection or emit error is logged and the loop continues (one bad sample must
// not stop monitoring).
func (r *Runtime) Run(ctx context.Context) error {
	r.discloseCollection()
	topic, _ := bus.TopicFor(r.cfg.Bus.Namespace, bus.EndpointResultsTopic) // validated when the emitter was built
	r.log.Info("endpoint agent starting",
		"tenant", r.cfg.TenantID, "agent", r.cfg.AgentID,
		"interval", r.cfg.Interval.String(), "topic", topic,
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
	r.noteUnavailable(s.Unavailable)
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

// noteUnavailable warns once whenever the set of signals a sample could not
// collect changes, and says when every layer is measured again (DPR-061): a
// device that silently never traces its last mile reports "no impairment"
// forever otherwise.
func (r *Runtime) noteUnavailable(unavailable []string) {
	joined := strings.Join(unavailable, "; ")
	if joined == r.lastUnavailable {
		return
	}
	if joined == "" {
		r.log.Info("endpoint signals recovered: every layer is measured again")
	} else {
		r.log.Warn("endpoint signals unavailable: the verdict covers the measured layers only", "unavailable", joined)
	}
	r.lastUnavailable = joined
}
