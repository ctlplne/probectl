// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Stats are the collector's monotonic counters (probectl observes probectl).
type Stats struct {
	Polls         atomic.Uint64
	PollErrors    atomic.Uint64
	Metrics       atomic.Uint64
	EmitErrors    atomic.Uint64
	GNMIStreams   atomic.Uint64
	CounterResets atomic.Uint64 // CORRECT-001: counter resets detected and dropped
	// CredErrors counts per-cycle credential re-resolutions that failed (S41:
	// the cycle is SKIPPED — fail closed, never poll with stale material).
	CredErrors atomic.Uint64
}

// counterKey uniquely identifies one cumulative counter series within a device poll.
type counterKey struct {
	device  string
	ifIndex uint32
	name    string
}

// Runtime drives one collector process: an SNMP poll loop per SNMP device and
// a gNMI subscription loop per gNMI device, all feeding one Emitter and one
// Correlator.
type Runtime struct {
	cfg   *Config
	creds CredentialSource
	emit  Emitter
	log   *slog.Logger

	correlator *Correlator
	stats      Stats

	// counterCache tracks the last emitted value of each cumulative counter
	// (CORRECT-001). When a device reboots, counters wrap to zero, producing a
	// huge apparent decrease. We detect this (current < previous) and drop the
	// reset cycle's counter metrics — the TSDB then sees a gap instead of a
	// huge negative rate spike. The cache is keyed per (device, ifIndex, metric)
	// and lives for the lifetime of the Runtime (one per device loop).
	counterMu    sync.Mutex
	counterCache map[counterKey]float64

	// dialSNMP/gnmiDialOpts are test seams (canned SNMP conns, bufconn gNMI).
	dialSNMP func(Target, Credential) (snmpConn, error)
}

// New validates cfg and builds the runtime. creds defaults to the env source
// (the pre-S41 default); S41 swaps in Vault/CyberArk behind the same seam.
func New(cfg *Config, em Emitter, creds CredentialSource, log *slog.Logger) (*Runtime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if em == nil {
		return nil, errors.New("device: emitter is required")
	}
	if creds == nil {
		creds = NewEnvCredentials(nil)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Runtime{
		cfg:          cfg,
		creds:        creds,
		emit:         em,
		log:          log,
		correlator:   NewCorrelator(),
		counterCache: make(map[counterKey]float64),
		dialSNMP:     dialSNMP,
	}, nil
}

// Correlator exposes the path/flow correlation index built from SNMP polls.
func (r *Runtime) Correlator() *Correlator { return r.correlator }

// StatsSnapshot returns a copy of the counters.
func (r *Runtime) StatsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"polls":          r.stats.Polls.Load(),
		"poll_errors":    r.stats.PollErrors.Load(),
		"metrics":        r.stats.Metrics.Load(),
		"emit_errors":    r.stats.EmitErrors.Load(),
		"gnmi_streams":   r.stats.GNMIStreams.Load(),
		"cred_errors":    r.stats.CredErrors.Load(),
		"counter_resets": r.stats.CounterResets.Load(),
	}
}

// Run blocks until ctx is canceled, supervising one loop per device.
func (r *Runtime) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, dev := range r.cfg.Devices {
		dev := dev
		if _, err := r.creds.Resolve(dev.Credential); err != nil {
			// A typo'd credential reference must surface immediately, not poll
			// unauthenticated forever (guardrail 6 / fail closed).
			return err
		}
		// Re-resolve per cycle/connection (S41): the secrets backend's lease
		// cache makes this cheap, and rotated credentials are picked up
		// without an agent restart. A failing backend skips the cycle — fail
		// closed, never a stale credential.
		credFn := func() (Credential, error) { return r.creds.Resolve(dev.Credential) }
		wg.Add(1)
		switch dev.Transport {
		case TransportGNMI:
			go func() {
				defer wg.Done()
				r.stats.GNMIStreams.Add(1)
				c := &gnmiCollector{dev: dev, credFn: credFn, tenant: r.cfg.TenantID,
					agent: r.cfg.AgentID, emit: r.emit, log: r.log}
				c.run(ctx)
			}()
		default: // snmpv2c | snmpv3 (validated)
			go func() {
				defer wg.Done()
				r.pollLoop(ctx, dev, credFn)
			}()
		}
	}
	r.log.Info("device collector running", "devices", len(r.cfg.Devices), "tenant", r.cfg.TenantID)

	statsTicker := time.NewTicker(60 * time.Second)
	defer statsTicker.Stop()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for {
		select {
		case <-ctx.Done():
			<-done
			return nil
		case <-done:
			return nil
		case <-statsTicker.C:
			r.log.Info("device collector stats", "stats", r.StatsSnapshot(),
				"correlated_devices", r.correlator.Devices())
		}
	}
}

// pollLoop polls one SNMP device on its interval: re-resolve credential ->
// dial -> poll -> emit -> correlate, redialing on every cycle (devices
// reboot; sessions go stale; credentials rotate — S41).
func (r *Runtime) pollLoop(ctx context.Context, dev Target, credFn func() (Credential, error)) {
	ticker := time.NewTicker(dev.Interval)
	defer ticker.Stop()
	for {
		if cred, err := credFn(); err != nil {
			r.stats.CredErrors.Add(1)
			r.log.Warn("device credential resolve failed; skipping cycle",
				"device", dev.Address, "error", err.Error())
		} else {
			r.pollOnce(ctx, dev, cred)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pollOnce performs one dial+poll cycle.
func (r *Runtime) pollOnce(ctx context.Context, dev Target, cred Credential) {
	r.stats.Polls.Add(1)
	conn, err := r.dialSNMP(dev, cred)
	if err != nil {
		r.stats.PollErrors.Add(1)
		r.log.Warn("snmp dial failed", "device", dev.Address, "error", err.Error())
		return
	}
	defer conn.Close()

	metrics, inv, err := pollSNMP(conn, dev, r.cfg.TenantID, r.cfg.AgentID, time.Now())
	if err != nil {
		r.stats.PollErrors.Add(1)
		r.log.Warn("snmp poll failed", "device", dev.Address, "error", err.Error())
		return
	}
	r.correlator.Update(inv)

	// CORRECT-001: apply counter-reset detection before emitting. Cumulative
	// counters (octets, errors, discards) must never decrease between polls —
	// a drop (current < previous) means the device rebooted and the 64-bit
	// counter wrapped to zero. Emitting the wrap-to-zero value would let the
	// TSDB's rate() produce a huge negative spike, corrupting capacity and SLO
	// data. We detect the reset, log it, drop the affected counter metrics for
	// this cycle (emitting a gap instead), and update the cache to the new
	// post-reset baseline so the next cycle is clean.
	metrics = r.filterCounterResets(metrics)

	if err := r.emit.Emit(ctx, metrics); err != nil {
		r.stats.EmitErrors.Add(1)
		r.log.Error("device emit failed", "device", dev.Address, "metrics", len(metrics), "error", err.Error())
		return
	}
	r.stats.Metrics.Add(uint64(len(metrics)))
}

// filterCounterResets inspects cumulative counter metrics, drops any that show
// a decrease vs the previous cycle (counter wrap on device reboot), and updates
// the cache. Non-counter metrics pass through unchanged.
func (r *Runtime) filterCounterResets(metrics []Metric) []Metric {
	out := metrics[:0:len(metrics)] // reuse backing array; capacity unchanged
	r.counterMu.Lock()
	defer r.counterMu.Unlock()
	for _, m := range metrics {
		if !isCounter(m.Name) {
			out = append(out, m)
			continue
		}
		k := counterKey{device: m.Device, ifIndex: m.IfIndex, name: m.Name}
		prev, seen := r.counterCache[k]
		r.counterCache[k] = m.Value
		if seen && m.Value < prev {
			// Counter decreased: device reset or counter wrapped. Drop this
			// sample — the TSDB will see a gap, not a negative rate spike.
			// Log at Warn (one line per reset counter) so operators can
			// correlate the gap with a device reboot event.
			r.stats.CounterResets.Add(1)
			r.log.Warn("snmp counter reset detected — dropping sample (device reboot?)",
				"device", m.Device, "if", m.IfName, "metric", m.Name,
				"prev", fmt.Sprintf("%.0f", prev), "current", fmt.Sprintf("%.0f", m.Value))
			continue
		}
		out = append(out, m)
	}
	return out
}

// isCounter reports whether a metric name is a cumulative counter (vs a gauge
// or status). Only counters can exhibit reset-wrap; gauges (CPU %, oper-status,
// speed, temperature) are immune and must pass through unchanged.
func isCounter(name string) bool {
	switch name {
	case MetricIfInOctets, MetricIfOutOctets,
		MetricIfInErrors, MetricIfOutErrors,
		MetricIfInDiscards, MetricIfOutDiscards:
		return true
	}
	return false
}
