// SPDX-License-Identifier: LicenseRef-probectl-TBD

package slo

// The SLI tracker + error-budget + multi-window burn-rate engine. Burn rate
// is the Google SRE method: burn = errorRate(window) / (1 - target), so
// burn 1 consumes exactly the budget over the SLO window. Alerts require BOTH
// a long and a short window to exceed the threshold (the multi-window AND):
// the long window proves it's sustained (kills noise), the short window
// proves it's still happening (kills slow/stale alerts) — the S45 watch-out.
//
//	page (critical): burn ≥ 14.4 over 1h AND 5m   — budget gone in ~2 days
//	                 burn ≥  6   over 6h AND 30m  — budget gone in ~5 days
//	ticket (warning): burn ≥ 1   over 3d AND 6h   — budget exactly on empty
//
// Cold start (the other watch-out): an SLO with fewer than MinEvents total
// events in its long alert window never alerts and reports cold_start=true —
// an empty baseline is not an outage.

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// MinEvents is the cold-start floor: below this many events in the longest
// alert window, burn alerts stay quiet and the status says so.
const MinEvents = 50

// burnWindow pairs a long and short window with a threshold and severity.
type burnWindow struct {
	name     string
	long     time.Duration
	short    time.Duration
	burn     float64
	severity incident.Severity
}

// The Google SRE multi-window multi-burn-rate ladder.
var burnWindows = []burnWindow{
	{name: "fast", long: time.Hour, short: 5 * time.Minute, burn: 14.4, severity: incident.SeverityCritical},
	{name: "medium", long: 6 * time.Hour, short: 30 * time.Minute, burn: 6, severity: incident.SeverityCritical},
	{name: "slow", long: 3 * 24 * time.Hour, short: 6 * time.Hour, burn: 1, severity: incident.SeverityWarning},
}

// minuteBucket aggregates one minute of SLI events.
type minuteBucket struct {
	good  uint64
	total uint64
}

// sloState is one SLO's per-tenant event window + alert latching.
type sloState struct {
	buckets map[int64]*minuteBucket // unix-minute → counts (pruned to window)
	firing  map[string]bool         // burn-window name → currently firing
}

// BurnRate is one window's current burn (status payload).
type BurnRate struct {
	Window string  `json:"window"` // fast | medium | slow
	Long   string  `json:"long"`
	Short  string  `json:"short"`
	Burn   float64 `json:"burn"`   // observed long-window burn
	Limit  float64 `json:"limit"`  // the threshold
	Firing bool    `json:"firing"` // both windows over the limit
}

// Status is one SLO's tenant-scoped state (the /v1/slos payload).
type Status struct {
	Name                 string     `json:"name"`
	DisplayName          string     `json:"display_name,omitempty"`
	Service              string     `json:"service"`
	Team                 string     `json:"team,omitempty"`
	Objective            float64    `json:"objective"`
	Window               string     `json:"window"`
	Attainment           float64    `json:"attainment"` // good/total over the SLO window
	ErrorBudgetRemaining float64    `json:"error_budget_remaining"`
	TotalEvents          uint64     `json:"total_events"`
	ColdStart            bool       `json:"cold_start"`
	BurnRates            []BurnRate `json:"burn_rates"`
}

// Engine evaluates the loaded SLOs over the result stream, per tenant.
type Engine struct {
	mu      sync.Mutex
	slos    []SLO
	tenants map[string]map[string]*sloState // tenant → slo name → state
	clock   func() time.Time
}

// NewEngine builds the engine over validated SLOs.
func NewEngine(slos []SLO) *Engine {
	return &Engine{
		slos:    append([]SLO(nil), slos...),
		tenants: map[string]map[string]*sloState{},
		clock:   time.Now,
	}
}

// WithClock overrides the engine's time source and returns the engine.
// Deterministic tests need it: evaluation windows are anchored at "now", so a
// test that feeds fixed-timestamp events but evaluates against the wall clock
// is a time bomb — it fails the day its events age past the SLO window (the
// sloapi tests did exactly that). Production code never calls this; the
// default is time.Now.
func (e *Engine) WithClock(now func() time.Time) *Engine {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clock = now
	return e
}

// SLOs returns the loaded definitions (sorted by name).
func (e *Engine) SLOs() []SLO {
	out := append([]SLO(nil), e.slos...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (e *Engine) state(tenant, name string) *sloState {
	ts, ok := e.tenants[tenant]
	if !ok {
		ts = map[string]*sloState{}
		e.tenants[tenant] = ts
	}
	st, ok := ts[name]
	if !ok {
		st = &sloState{buckets: map[int64]*minuteBucket{}, firing: map[string]bool{}}
		ts[name] = st
	}
	return st
}

// ObserveResult feeds one synthetic result into every matching SLI and
// returns burn-rate signals raised by the transition into a firing state
// (latched: one signal per window per episode, re-armed when it clears).
func (e *Engine) ObserveResult(tenant, canaryType, target string, success bool, at time.Time) []incident.Signal {
	if tenant == "" || target == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	var sigs []incident.Signal
	for _, s := range e.slos {
		if !s.Matches(canaryType, target) {
			continue
		}
		st := e.state(tenant, s.Name)
		minute := at.UTC().Truncate(time.Minute).Unix()
		b, ok := st.buckets[minute]
		if !ok {
			b = &minuteBucket{}
			st.buckets[minute] = b
			st.prune(s.Window, at)
		}
		b.total++
		if success {
			b.good++
		}
		sigs = append(sigs, e.evaluateLocked(tenant, s, st, at)...)
	}
	return sigs
}

// prune drops buckets older than the SLO window (the budget window bounds
// retention; alert windows are always shorter).
func (st *sloState) prune(window time.Duration, now time.Time) {
	cutoff := now.Add(-window).UTC().Truncate(time.Minute).Unix()
	for m := range st.buckets {
		if m < cutoff {
			delete(st.buckets, m)
		}
	}
}

// rates returns (good, total) over the trailing window ending at now.
func (st *sloState) rates(window time.Duration, now time.Time) (good, total uint64) {
	from := now.Add(-window).UTC().Truncate(time.Minute).Unix()
	to := now.UTC().Truncate(time.Minute).Unix()
	for m, b := range st.buckets {
		if m >= from && m <= to {
			good += b.good
			total += b.total
		}
	}
	return good, total
}

// burn computes errorRate(window)/(1-target); ok=false with no events.
func (st *sloState) burn(window time.Duration, objective float64, now time.Time) (float64, uint64, bool) {
	good, total := st.rates(window, now)
	if total == 0 {
		return 0, 0, false
	}
	errRate := 1 - float64(good)/float64(total)
	return errRate / (1 - objective), total, true
}

// evaluateLocked checks the burn ladder, latching per-window firing state.
func (e *Engine) evaluateLocked(tenant string, s SLO, st *sloState, at time.Time) []incident.Signal {
	// Cold start gates on the SLO's FULL window history (is this SLO new or
	// quiet overall?), not on per-alert-window density — otherwise a
	// low-cadence probe (e.g. one every 5 minutes) could never accumulate
	// enough events inside the 1h fast window and fast alerts would be
	// permanently dead.
	if _, fullTotal := st.rates(s.Window, at); fullTotal < MinEvents {
		return nil
	}
	var sigs []incident.Signal
	for _, w := range burnWindows {
		longBurn, _, okL := st.burn(minDur(w.long, s.Window), s.Objective, at)
		shortBurn, _, okS := st.burn(w.short, s.Objective, at)
		if !okL || !okS {
			continue // no events in a window: nothing to judge
		}
		firing := longBurn >= w.burn && shortBurn >= w.burn
		switch {
		case firing && !st.firing[w.name]:
			st.firing[w.name] = true
			sigs = append(sigs, incident.Signal{
				TenantID: tenant,
				Plane:    "slo",
				Kind:     "slo.burn_rate",
				Severity: w.severity,
				Title:    fmt.Sprintf("SLO %s burning %.1fx (%s window)", s.Name, longBurn, w.name),
				Summary: fmt.Sprintf("%s (service %s) is burning error budget at %.1fx over %s and %.1fx over %s — threshold %.1fx",
					s.Name, s.Service, longBurn, minDur(w.long, s.Window), shortBurn, w.short, w.burn),
				Target: s.Service,
				Attributes: map[string]string{
					"slo.name":       s.Name,
					"slo.service":    s.Service,
					"slo.team":       s.Team,
					"slo.window":     w.name,
					"slo.burn_long":  fmt.Sprintf("%.2f", longBurn),
					"slo.burn_short": fmt.Sprintf("%.2f", shortBurn),
					"slo.burn_limit": fmt.Sprintf("%.2f", w.burn),
					"slo.objective":  fmt.Sprintf("%.4f", s.Objective),
				},
				OccurredAt: at,
			})
		case !firing && st.firing[w.name] && longBurn < w.burn:
			// Hysteresis: clear on the LONG window so the episode doesn't
			// flap on short-window noise.
			st.firing[w.name] = false
		}
	}
	return sigs
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// Statuses returns the tenant's SLO statuses (sorted by name).
func (e *Engine) Statuses(tenant string) []Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock()

	out := make([]Status, 0, len(e.slos))
	for _, s := range e.SLOs() {
		st := e.state(tenant, s.Name)
		good, total := st.rates(s.Window, now)
		attainment := 1.0
		if total > 0 {
			attainment = float64(good) / float64(total)
		}
		budgetRemaining := 1.0
		if total > 0 {
			budgetRemaining = 1 - (1-attainment)/(1-s.Objective)
			if budgetRemaining < 0 {
				budgetRemaining = 0
			}
		}
		status := Status{
			Name:                 s.Name,
			DisplayName:          s.DisplayName,
			Service:              s.Service,
			Team:                 s.Team,
			Objective:            s.Objective,
			Window:               s.doc.Spec.TimeWindow[0].Duration,
			Attainment:           attainment,
			ErrorBudgetRemaining: budgetRemaining,
			TotalEvents:          total,
			ColdStart:            total < MinEvents,
		}
		for _, w := range burnWindows {
			longBurn, _, okL := st.burn(minDur(w.long, s.Window), s.Objective, now)
			if !okL {
				longBurn = 0
			}
			status.BurnRates = append(status.BurnRates, BurnRate{
				Window: w.name,
				Long:   minDur(w.long, s.Window).String(),
				Short:  w.short.String(),
				Burn:   longBurn,
				Limit:  w.burn,
				Firing: st.firing[w.name],
			})
		}
		out = append(out, status)
	}
	return out
}

// ImpactedSLOs implements topology.SLOSource (S43's what-if seam): SLOs whose
// service or probe target matches the impacted node ids.
func (e *Engine) ImpactedSLOs(tenant string, serviceIDs, hostIDs []string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = tenant // definitions are deployment-level; status is tenant-scoped

	names := map[string]bool{}
	for _, s := range e.slos {
		for _, id := range serviceIDs {
			if trimPrefix(id, "service:") == s.Service {
				names[s.Name] = true
			}
		}
		for _, id := range hostIDs {
			if s.TargetMatches(trimPrefix(id, "host:")) {
				names[s.Name] = true
			}
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
