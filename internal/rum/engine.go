// SPDX-License-Identifier: LicenseRef-probectl-TBD

package rum

import (
	"fmt"
	"sort"
	"sync"
	"time"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// Verdict is the synthetic↔RUM convergence call for one (app, host) — the
// point of S47b. Wording is deliberate: "no user impact OBSERVED" and
// "synthetics never noticed" are claims about what probectl saw, not about
// the world.
type Verdict string

const (
	VerdictHealthy Verdict = "healthy"
	// Both planes degraded — the confirmed, page-worthy case.
	VerdictUserImpactConfirmed Verdict = "user_impact_confirmed"
	// Synthetics degraded, real users fine — don't wake anyone for a canary.
	VerdictSyntheticOnly Verdict = "synthetic_only_no_user_impact"
	// Real users degraded, synthetics green — the coverage blind spot.
	VerdictUserOnly Verdict = "user_only_synthetic_blind"
)

// Aggregation tuning. Conservative thresholds, all documented in docs/rum.md.
const (
	window           = 15 * time.Minute
	minViews         = 20   // views in window before RUM may be called degraded
	errRateDegraded  = 0.10 // ≥10% erroring views = degraded
	lcpPoorMs        = 4000 // web-vitals "poor" LCP
	maxAppsPerTenant = 64
	maxPagesPerApp   = 256
	maxHostsPerTen   = 256
	ringSize         = 128 // per-page LCP/TTFB reservoir for p75
	maxSyntheticObs  = 64  // per-host synthetic outcome window
)

// PageStats is one page group's window aggregate.
type PageStats struct {
	Page      string  `json:"page"`
	Views     int     `json:"views"`
	ErrorRate float64 `json:"error_rate"`
	P75LCPms  float64 `json:"p75_lcp_ms,omitempty"`
	P75TTFBms float64 `json:"p75_ttfb_ms,omitempty"`
}

// AppStatus is the convergence view for one (app, host).
type AppStatus struct {
	App               string      `json:"app"`
	Host              string      `json:"host"`
	WindowViews       int         `json:"window_views"`
	ErrorRate         float64     `json:"error_rate"`
	P75LCPms          float64     `json:"p75_lcp_ms,omitempty"`
	P75TTFBms         float64     `json:"p75_ttfb_ms,omitempty"`
	RUMDegraded       bool        `json:"rum_degraded"`
	SyntheticObserved bool        `json:"synthetic_observed"` // any synthetic covers this host
	SyntheticDegraded bool        `json:"synthetic_degraded"`
	Verdict           Verdict     `json:"verdict"`
	EvidenceTrust     string      `json:"evidence_trust"`
	Pages             []PageStats `json:"pages"`
}

// Privacy is the served privacy posture + rejection honesty counters.
type Privacy struct {
	ConsentRequired   bool `json:"consent_required"`
	URLRedaction      bool `json:"url_redaction"`
	IPStored          bool `json:"ip_stored"` // always false — structural
	RejectedNoConsent int  `json:"rejected_no_consent"`
	RejectedMalformed int  `json:"rejected_malformed"`
	RejectedBadField  int  `json:"rejected_invalid_field"`
	AcceptedPageViews int  `json:"accepted_page_views"`
}

// Snapshot is one tenant's RUM convergence view (the /v1/rum payload).
type Snapshot struct {
	Apps    []AppStatus `json:"apps"`
	Privacy Privacy     `json:"privacy"`
}

// Engine aggregates RUM page views and synthetic outcomes per tenant and
// renders the convergence verdicts. All state is tenant-partitioned
// (guardrail 1) and bounded.
type Engine struct {
	mu      sync.Mutex
	tenants map[string]*tenantState
	clock   func() time.Time
}

type tenantState struct {
	apps      map[string]*appAgg   // app|host → aggregate
	synthetic map[string]*hostObs  // host → synthetic outcome window
	rejects   map[RejectReason]int // honesty counters
	accepted  int
	alerted   map[string]Verdict // app|host → last signaled verdict (latched)
}

type appAgg struct {
	app, host string
	pages     map[string]*pageAgg
}

type pageAgg struct {
	views []viewSample // pruned to window, bounded
}

type viewSample struct {
	at     time.Time
	errors bool
	lcpMs  float64
	ttfbMs float64
}

type hostObs struct {
	samples []synthSample
}

type synthSample struct {
	at time.Time
	ok bool
}

// NewEngine builds the engine.
func NewEngine() *Engine {
	return &Engine{tenants: map[string]*tenantState{}, clock: time.Now}
}

func (e *Engine) tenant(id string) *tenantState {
	ts, ok := e.tenants[id]
	if !ok {
		ts = &tenantState{
			apps:      map[string]*appAgg{},
			synthetic: map[string]*hostObs{},
			rejects:   map[RejectReason]int{},
			alerted:   map[string]Verdict{},
		}
		e.tenants[id] = ts
	}
	return ts
}

// RecordReject counts a refused beacon (the served honesty counters).
func (e *Engine) RecordReject(tenant string, reason RejectReason) {
	if tenant == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tenant(tenant).rejects[reason]++
}

// ObserveRUM folds one normalized RUM result (canary_type "rum") into the
// tenant's aggregates and returns any verdict-transition signals.
func (e *Engine) ObserveRUM(r *resultv1.Result) []incident.Signal {
	tenant := r.GetTenantId()
	host := r.GetServerAddress()
	if tenant == "" || host == "" || r.GetCanaryType() != "rum" {
		return nil // unscoped or mis-typed records are dropped (guardrail 1)
	}
	app := r.GetAttributes()["rum.app"]
	if app == "" {
		app = "(unattributed)"
	}
	page := r.GetAttributes()["url.path"]
	if page == "" {
		page = "/"
	}
	at := time.Unix(0, r.GetStartTimeUnixNano())

	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)
	key := app + "|" + host
	agg, ok := ts.apps[key]
	if !ok {
		if len(ts.apps) >= maxAppsPerTenant {
			return nil // bounded
		}
		agg = &appAgg{app: app, host: host, pages: map[string]*pageAgg{}}
		ts.apps[key] = agg
	}
	pg, ok := agg.pages[page]
	if !ok {
		if len(agg.pages) >= maxPagesPerApp {
			page = "(other)"
			if pg, ok = agg.pages[page]; !ok {
				pg = &pageAgg{}
				agg.pages[page] = pg
			}
		} else {
			pg = &pageAgg{}
			agg.pages[page] = pg
		}
	}
	pg.views = append(pg.views, viewSample{
		at:     at,
		errors: !r.GetSuccess(),
		lcpMs:  r.GetMetrics()["rum.lcp_ms"],
		ttfbMs: r.GetMetrics()["rum.ttfb_ms"],
	})
	pg.prune(at)
	ts.accepted++

	return e.evaluateLocked(tenant, ts, agg, at)
}

// ObserveSynthetic folds one web-facing synthetic outcome (the consumer
// filters to http/https/browser types — see rumapi.go) into the host's
// window — the other half of convergence.
func (e *Engine) ObserveSynthetic(tenant, host string, success bool, at time.Time) []incident.Signal {
	if tenant == "" || host == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)
	obs, ok := ts.synthetic[host]
	if !ok {
		if len(ts.synthetic) >= maxHostsPerTen {
			return nil
		}
		obs = &hostObs{}
		ts.synthetic[host] = obs
	}
	obs.samples = append(obs.samples, synthSample{at: at, ok: success})
	obs.prune(at)

	var sigs []incident.Signal
	for _, agg := range ts.apps {
		if agg.host == host {
			sigs = append(sigs, e.evaluateLocked(tenant, ts, agg, at)...)
		}
	}
	return sigs
}

func (p *pageAgg) prune(now time.Time) {
	cutoff := now.Add(-window)
	i := 0
	for ; i < len(p.views); i++ {
		if !p.views[i].at.Before(cutoff) {
			break
		}
	}
	p.views = p.views[i:]
	if len(p.views) > ringSize {
		p.views = p.views[len(p.views)-ringSize:]
	}
}

func (h *hostObs) prune(now time.Time) {
	cutoff := now.Add(-window)
	i := 0
	for ; i < len(h.samples); i++ {
		if !h.samples[i].at.Before(cutoff) {
			break
		}
	}
	h.samples = h.samples[i:]
	if len(h.samples) > maxSyntheticObs {
		h.samples = h.samples[len(h.samples)-maxSyntheticObs:]
	}
}

// syntheticState summarizes a host's synthetic window: observed at all, and
// degraded (≥50% failures over ≥2 samples — the outage-engine bar).
func (ts *tenantState) syntheticState(host string, now time.Time) (observed, degraded bool) {
	obs, ok := ts.synthetic[host]
	if !ok {
		return false, false
	}
	cutoff := now.Add(-window)
	total, fails := 0, 0
	for _, s := range obs.samples {
		if s.at.Before(cutoff) {
			continue
		}
		total++
		if !s.ok {
			fails++
		}
	}
	return total > 0, total >= 2 && float64(fails)/float64(total) >= 0.5
}

// rumState aggregates an app's window: views, error rate, p75 vitals, and
// the degraded call (enough views AND bad errors or poor p75 LCP).
func (a *appAgg) rumState(now time.Time) (views int, errRate, p75lcp, p75ttfb float64, degraded bool) {
	var errs int
	var lcps, ttfbs []float64
	cutoff := now.Add(-window)
	for _, pg := range a.pages {
		for _, v := range pg.views {
			if v.at.Before(cutoff) {
				continue
			}
			views++
			if v.errors {
				errs++
			}
			if v.lcpMs > 0 {
				lcps = append(lcps, v.lcpMs)
			}
			if v.ttfbMs > 0 {
				ttfbs = append(ttfbs, v.ttfbMs)
			}
		}
	}
	if views > 0 {
		errRate = float64(errs) / float64(views)
	}
	p75lcp = p75(lcps)
	p75ttfb = p75(ttfbs)
	degraded = views >= minViews && (errRate >= errRateDegraded || p75lcp >= lcpPoorMs)
	return views, errRate, p75lcp, p75ttfb, degraded
}

func p75(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sort.Float64s(vals)
	idx := (len(vals) * 3) / 4
	if idx >= len(vals) {
		idx = len(vals) - 1
	}
	return vals[idx]
}

// verdict computes the convergence call from the two planes' states.
func verdict(rumDegraded, synObserved, synDegraded bool) Verdict {
	switch {
	case rumDegraded && synDegraded:
		return VerdictUserImpactConfirmed
	case rumDegraded:
		return VerdictUserOnly
	case synObserved && synDegraded:
		return VerdictSyntheticOnly
	default:
		return VerdictHealthy
	}
}

// evaluateLocked re-scores one app and raises a signal on a transition INTO
// a corroborated noteworthy verdict (latched per verdict; healthy re-arms).
func (e *Engine) evaluateLocked(tenant string, ts *tenantState, agg *appAgg, now time.Time) []incident.Signal {
	views, errRate, _, _, rumDeg := agg.rumState(now)
	synObs, synDeg := ts.syntheticState(agg.host, now)
	v := verdict(rumDeg, synObs, synDeg)
	key := agg.app + "|" + agg.host

	if v == VerdictHealthy || v == VerdictSyntheticOnly {
		// SyntheticOnly is the SLO/alerting planes' story — RUM's contribution
		// is the "no user impact observed" annotation, not another page.
		if ts.alerted[key] != "" && v == VerdictHealthy {
			delete(ts.alerted, key) // recovery re-arms
		}
		return nil
	}
	if v == VerdictUserOnly {
		// RUM app keys are public page identifiers, so RUM-only degradation is
		// useful evidence in the RUM view but not enough proof to open a paging
		// incident. Keep the blind-spot verdict visible in Snapshot; require the
		// independent synthetic plane before emitting a correlator signal.
		return nil
	}
	if ts.alerted[key] == v {
		return nil // latched
	}
	ts.alerted[key] = v

	kind, title := "rum.user_impact_correlated",
		fmt.Sprintf("Real-user impact confirmed: %s (%s)", agg.app, agg.host)
	return []incident.Signal{{
		TenantID: tenant,
		Plane:    "rum",
		Kind:     kind,
		Severity: incident.SeverityWarning,
		Title:    title,
		Summary: fmt.Sprintf("%d real-user views in %s: %.0f%% erroring; synthetic coverage %s",
			views, window, errRate*100, describeSynthetic(synObs, synDeg)),
		Target: agg.host,
		Attributes: map[string]string{
			"rum.app":            agg.app,
			"rum.host":           agg.host,
			"rum.verdict":        string(v),
			"rum.window_views":   fmt.Sprintf("%d", views),
			"rum.error_rate":     fmt.Sprintf("%.3f", errRate),
			"rum.synthetic_seen": fmt.Sprintf("%t", synObs),
			"rum.signal_trust":   "synthetic_corroborated",
		},
		OccurredAt: now,
	}}
}

func describeSynthetic(observed, degraded bool) string {
	switch {
	case degraded:
		return "also degraded"
	case observed:
		return "green (blind spot)"
	default:
		return "absent for this host"
	}
}

func evidenceTrust(v Verdict) string {
	switch v {
	case VerdictUserImpactConfirmed:
		return "synthetic_corroborated"
	case VerdictUserOnly:
		return "rum_only_low_trust"
	case VerdictSyntheticOnly:
		return "synthetic_only_annotation"
	default:
		return "observed"
	}
}

// Snapshot renders ONE tenant's convergence view. Nothing from any other
// tenant is reachable from here.
func (e *Engine) Snapshot(tenant string) Snapshot {
	now := e.clock()
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)

	snap := Snapshot{
		Apps: []AppStatus{},
		Privacy: Privacy{
			ConsentRequired:   true,
			URLRedaction:      true,
			IPStored:          false,
			RejectedNoConsent: ts.rejects[RejectNoConsent],
			RejectedMalformed: ts.rejects[RejectMalformed],
			RejectedBadField:  ts.rejects[RejectBadField],
			AcceptedPageViews: ts.accepted,
		},
	}
	for _, agg := range ts.apps {
		views, errRate, p75lcp, p75ttfb, rumDeg := agg.rumState(now)
		if views == 0 {
			continue // window empty — nothing honest to show
		}
		synObs, synDeg := ts.syntheticState(agg.host, now)
		st := AppStatus{
			App: agg.app, Host: agg.host,
			WindowViews: views, ErrorRate: round3(errRate),
			P75LCPms: p75lcp, P75TTFBms: p75ttfb,
			RUMDegraded: rumDeg, SyntheticObserved: synObs, SyntheticDegraded: synDeg,
			Verdict:       verdict(rumDeg, synObs, synDeg),
			EvidenceTrust: evidenceTrust(verdict(rumDeg, synObs, synDeg)),
			Pages:         agg.pageStats(now),
		}
		snap.Apps = append(snap.Apps, st)
	}
	sort.Slice(snap.Apps, func(i, j int) bool {
		if snap.Apps[i].App != snap.Apps[j].App {
			return snap.Apps[i].App < snap.Apps[j].App
		}
		return snap.Apps[i].Host < snap.Apps[j].Host
	})
	return snap
}

func (a *appAgg) pageStats(now time.Time) []PageStats {
	var out []PageStats
	for page, pg := range a.pages {
		var views, errs int
		var lcps, ttfbs []float64
		cutoff := now.Add(-window)
		for _, v := range pg.views {
			if v.at.Before(cutoff) {
				continue
			}
			views++
			if v.errors {
				errs++
			}
			if v.lcpMs > 0 {
				lcps = append(lcps, v.lcpMs)
			}
			if v.ttfbMs > 0 {
				ttfbs = append(ttfbs, v.ttfbMs)
			}
		}
		if views == 0 {
			continue
		}
		out = append(out, PageStats{
			Page: page, Views: views,
			ErrorRate: round3(float64(errs) / float64(views)),
			P75LCPms:  p75(lcps), P75TTFBms: p75(ttfbs),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Views != out[j].Views {
			return out[i].Views > out[j].Views
		}
		return out[i].Page < out[j].Page
	})
	return out
}

func round3(f float64) float64 { return float64(int(f*1000+0.5)) / 1000 }
