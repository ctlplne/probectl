package device

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Stats are the collector's monotonic counters (probectl observes probectl).
type Stats struct {
	Polls       atomic.Uint64
	PollErrors  atomic.Uint64
	Metrics     atomic.Uint64
	EmitErrors  atomic.Uint64
	GNMIStreams atomic.Uint64
	// CredErrors counts per-cycle credential re-resolutions that failed (S41:
	// the cycle is SKIPPED — fail closed, never poll with stale material).
	CredErrors atomic.Uint64
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
		cfg:        cfg,
		creds:      creds,
		emit:       em,
		log:        log,
		correlator: NewCorrelator(),
		dialSNMP:   dialSNMP,
	}, nil
}

// Correlator exposes the path/flow correlation index built from SNMP polls.
func (r *Runtime) Correlator() *Correlator { return r.correlator }

// StatsSnapshot returns a copy of the counters.
func (r *Runtime) StatsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"polls":        r.stats.Polls.Load(),
		"poll_errors":  r.stats.PollErrors.Load(),
		"metrics":      r.stats.Metrics.Load(),
		"emit_errors":  r.stats.EmitErrors.Load(),
		"gnmi_streams": r.stats.GNMIStreams.Load(),
		"cred_errors":  r.stats.CredErrors.Load(),
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
	if err := r.emit.Emit(ctx, metrics); err != nil {
		r.stats.EmitErrors.Add(1)
		r.log.Error("device emit failed", "device", dev.Address, "metrics", len(metrics), "error", err.Error())
		return
	}
	r.stats.Metrics.Add(uint64(len(metrics)))
}
