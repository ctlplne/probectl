// SPDX-License-Identifier: LicenseRef-probectl-TBD

package threat

// The NDR-lite behavioral detection engine (S42, F37): stateful, tenant-
// scoped detectors over the signal substrate probectl already collects —
// DNS lookups (S12 canaries + S21 eBPF L7), flow records (S38), eBPF flows
// (S20), TLS posture (S27, via the existing posture pipeline), threat-intel
// (S28) and the topology service map (S30).
//
// Design constraints (the S42 watch-outs, in order of importance):
//
//   - SIGNALS, NEVER BLOCKS (guardrail 9). The engine emits incident.Signal
//     values; there is no enforcement surface anywhere in this package.
//   - False-positive management is first-class: every detector has tunable
//     thresholds (rules.go), confidence scoring with evidence attributes
//     (the analyst sees WHY), per-(rule, entity) suppression windows, and
//     cold-start minimum-sample guards so empty baselines never fire.
//   - Tenant isolation: all state is partitioned by tenant_id; an entity in
//     one tenant can never influence another's detections (guardrail 1).
//   - Bounded memory: per-tenant entity maps cap out and evict the stalest
//     entry; windows are rings. The engine is rebuildable from the stream.

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

// IntelSource scores an IP against threat intel (satisfied by
// *opendata.IOCStore). nil disables intel-backed detections gracefully.
type IntelSource interface {
	ScoreIP(ip string) []opendata.IOCMatch
}

// NeighborSource exposes the tenant-bound topology service map (S30): known
// service relationships of a node. The lateral detector treats known neighbors
// as EXPECTED traffic — they never count toward fan-out (false-positive
// control). nil means no exclusions.
type NeighborSource interface {
	ForTenant(tenant string) (topology.TenantStore, error)
}

// DNSObservation is one resolved name: from a DNS canary result (S12) or an
// eBPF L7 DNS call (S21). Source is the looking-up entity (agent/host/IP).
type DNSObservation struct {
	Source string
	QName  string
	At     time.Time
}

// FlowObservation is one normalized flow/edge sample: from a flow record
// (S38) or an eBPF flow (S20). DstASN may be zero (unenriched).
type FlowObservation struct {
	Src     string
	Dst     string
	DstPort uint16
	DstASN  uint32
	Bytes   uint64
	At      time.Time
}

// Engine evaluates the rule set over observations and emits threat-plane
// signals. Safe for concurrent use.
type Engine struct {
	mu      sync.Mutex
	rules   map[RuleKind][]DetectionRule
	intel   IntelSource
	topo    NeighborSource
	tenants map[string]*tenantState
	clock   func() time.Time

	// maxEntities bounds each detector's per-tenant entity map.
	maxEntities int
}

// DefaultMaxEntitiesPerTenant bounds each detector's tracked entities per
// tenant (stalest evicted) — bounded memory under cardinality attacks.
const DefaultMaxEntitiesPerTenant = 4096

// NewEngine builds the engine over the loaded rules. intel and topo are
// optional context sources (nil degrades the respective detections, never
// errors — graceful degradation, guardrail 10).
func NewEngine(rules []DetectionRule, intel IntelSource, topo NeighborSource) *Engine {
	byKind := map[RuleKind][]DetectionRule{}
	for _, r := range rules {
		if r.On() {
			byKind[r.Kind] = append(byKind[r.Kind], r)
		}
	}
	return &Engine{
		rules:       byKind,
		intel:       intel,
		topo:        topo,
		tenants:     map[string]*tenantState{},
		clock:       time.Now,
		maxEntities: DefaultMaxEntitiesPerTenant,
	}
}

// Rules returns the active (enabled) rules, sorted by ID — the engine's
// effective configuration for logs/docs.
func (e *Engine) Rules() []DetectionRule {
	var out []DetectionRule
	for _, rs := range e.rules {
		out = append(out, rs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// --- per-tenant state ---

type dnsEntry struct {
	at        time.Time
	name      string
	generated bool
}

type exfilEntry struct {
	at    time.Time
	sub   string
	bytes int
}

type beaconState struct {
	arrivals []time.Time // ring, newest last (cap beaconRing)
	touched  time.Time
}

type ewmaState struct {
	ewma    float64
	samples int
	touched time.Time
}

type lateralState struct {
	dsts    map[string]time.Time // internal destination -> last seen
	touched time.Time
}

type dnsState struct {
	entries []dnsEntry // pruned to the rule window
	touched time.Time
}

type exfilState struct {
	entries []exfilEntry
	touched time.Time
}

type tenantState struct {
	dga      map[string]*dnsState    // by source
	exfil    map[string]*exfilState  // by source|registered-domain
	beacon   map[string]*beaconState // by src|dst:port
	egress   map[string]*ewmaState   // by src
	lateral  map[string]*lateralState
	suppress map[string]time.Time // rule|entity -> quiet-until
}

const beaconRing = 32
const maxWindowEntries = 512

func (e *Engine) tenant(id string) *tenantState {
	ts, ok := e.tenants[id]
	if !ok {
		ts = &tenantState{
			dga:      map[string]*dnsState{},
			exfil:    map[string]*exfilState{},
			beacon:   map[string]*beaconState{},
			egress:   map[string]*ewmaState{},
			lateral:  map[string]*lateralState{},
			suppress: map[string]time.Time{},
		}
		e.tenants[id] = ts
	}
	return ts
}

// evictStalest keeps m under cap by dropping the least-recently-touched key.
func evictStalest[V any](m map[string]V, capacity int, touched func(V) time.Time) {
	if len(m) <= capacity {
		return
	}
	var oldestK string
	var oldestT time.Time
	first := true
	for k, v := range m {
		if t := touched(v); first || t.Before(oldestT) {
			oldestK, oldestT, first = k, t, false
		}
	}
	delete(m, oldestK)
}

// suppressed reports (and records) the per-(rule, entity) re-fire window.
// The first call for a quiet pair arms the window and returns false.
func (ts *tenantState) suppressed(rule DetectionRule, entity string, at time.Time) bool {
	key := rule.ID + "|" + entity
	if until, ok := ts.suppress[key]; ok && at.Before(until) {
		return true
	}
	ts.suppress[key] = at.Add(rule.Suppress)
	// Opportunistic pruning keeps the map bounded.
	if len(ts.suppress) > 4*DefaultMaxEntitiesPerTenant {
		for k, until := range ts.suppress {
			if at.After(until) {
				delete(ts.suppress, k)
			}
		}
	}
	return false
}

// --- signal construction ---

func clampConfidence(c int) int {
	if c > 100 {
		return 100
	}
	if c < 0 {
		return 0
	}
	return c
}

func (e *Engine) signal(tenant string, rule DetectionRule, entity, title, summary string,
	confidence int, at time.Time, evidence map[string]string) incident.Signal {
	attrs := map[string]string{
		"detector.rule":         rule.ID,
		"detector.rule_version": strconv.Itoa(rule.Version),
		"detector.kind":         string(rule.Kind),
		"detector.confidence":   strconv.Itoa(clampConfidence(confidence)),
	}
	for k, v := range evidence {
		attrs[k] = v
	}
	return incident.Signal{
		TenantID:   tenant,
		Plane:      "threat",
		Kind:       "ndr." + string(rule.Kind),
		Severity:   incident.Severity(rule.Severity),
		Title:      title,
		Summary:    summary,
		Target:     entity,
		Attributes: attrs,
		OccurredAt: at,
	}
}

// --- DNS detectors (DGA + exfil) ---

// ObserveDNS feeds one DNS lookup through the DGA and exfil detectors.
func (e *Engine) ObserveDNS(tenant string, obs DNSObservation) []incident.Signal {
	if tenant == "" || obs.QName == "" || obs.Source == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)
	var out []incident.Signal
	out = append(out, e.observeDGA(tenant, ts, obs)...)
	out = append(out, e.observeExfil(tenant, ts, obs)...)
	return out
}

func (e *Engine) observeDGA(tenant string, ts *tenantState, obs DNSObservation) []incident.Signal {
	var out []incident.Signal
	for _, rule := range e.rules[KindDNSDGA] {
		window := time.Duration(rule.Threshold("window_s", 600)) * time.Second
		st, ok := ts.dga[obs.Source]
		if !ok {
			st = &dnsState{}
			ts.dga[obs.Source] = st
			evictStalest(ts.dga, e.maxEntities, func(v *dnsState) time.Time { return v.touched })
		}
		st.touched = obs.At
		gen := shannonEntropy(firstLabel(obs.QName)) >= rule.Threshold("entropy", 3.8) &&
			len(firstLabel(obs.QName)) >= 10
		st.entries = appendPruned(st.entries, dnsEntry{at: obs.At, name: obs.QName, generated: gen},
			obs.At.Add(-window), func(en dnsEntry) time.Time { return en.at })

		distinct := map[string]bool{}
		generated := 0
		for _, en := range st.entries {
			if !distinct[en.name] {
				distinct[en.name] = true
				if en.generated {
					generated++
				}
			}
		}
		total := len(distinct)
		minNames := int(rule.Threshold("min_names", 20))
		ratio := rule.Threshold("ratio", 0.5)
		if total < minNames { // cold start: never judge a thin window
			continue
		}
		observed := float64(generated) / float64(total)
		if observed < ratio {
			continue
		}
		if ts.suppressed(rule, obs.Source, obs.At) {
			continue
		}
		conf := rule.BaseConfidence + int(40*observed)
		out = append(out, e.signal(tenant, rule, obs.Source,
			rule.Name,
			fmt.Sprintf("%s resolved %d distinct names in %s; %.0f%% look algorithmically generated (e.g. %s)",
				obs.Source, total, window, 100*observed, firstGenerated(st.entries)),
			conf, obs.At, map[string]string{
				"dns.names_distinct":  strconv.Itoa(total),
				"dns.generated_ratio": fmt.Sprintf("%.2f", observed),
				"dns.example":         firstGenerated(st.entries),
			}))
	}
	return out
}

func (e *Engine) observeExfil(tenant string, ts *tenantState, obs DNSObservation) []incident.Signal {
	var out []incident.Signal
	domain := registeredDomain(obs.QName)
	if domain == "" || domain == obs.QName {
		return nil // bare domain lookups carry no payload labels
	}
	sub := strings.TrimSuffix(obs.QName, "."+domain)
	for _, rule := range e.rules[KindDNSExfil] {
		window := time.Duration(rule.Threshold("window_s", 600)) * time.Second
		key := obs.Source + "|" + domain
		st, ok := ts.exfil[key]
		if !ok {
			st = &exfilState{}
			ts.exfil[key] = st
			evictStalest(ts.exfil, e.maxEntities, func(v *exfilState) time.Time { return v.touched })
		}
		st.touched = obs.At
		st.entries = appendPruned(st.entries, exfilEntry{at: obs.At, sub: sub, bytes: len(obs.QName)},
			obs.At.Add(-window), func(en exfilEntry) time.Time { return en.at })

		total := len(st.entries)
		if total < int(rule.Threshold("min_queries", 30)) {
			continue
		}
		bytes := 0
		distinct := map[string]bool{}
		for _, en := range st.entries {
			bytes += en.bytes
			distinct[en.sub] = true
		}
		uniqueRatio := float64(len(distinct)) / float64(total)
		if float64(bytes) < rule.Threshold("qname_bytes", 4096) ||
			uniqueRatio < rule.Threshold("unique_ratio", 0.9) {
			continue
		}
		if ts.suppressed(rule, obs.Source+"→"+domain, obs.At) {
			continue
		}
		conf := rule.BaseConfidence + int(30*uniqueRatio) + 10
		out = append(out, e.signal(tenant, rule, obs.Source,
			rule.Name,
			fmt.Sprintf("%s sent %d unique-subdomain queries (%d qname bytes) to *.%s in %s",
				obs.Source, len(distinct), bytes, domain, window),
			conf, obs.At, map[string]string{
				"dns.domain":       domain,
				"dns.queries":      strconv.Itoa(total),
				"dns.qname_bytes":  strconv.Itoa(bytes),
				"dns.unique_ratio": fmt.Sprintf("%.2f", uniqueRatio),
			}))
	}
	return out
}

// --- flow detectors (beaconing, egress volume, egress intel, lateral) ---

// ObserveFlow feeds one flow/edge sample through the beaconing, egress and
// lateral detectors.
func (e *Engine) ObserveFlow(tenant string, obs FlowObservation) []incident.Signal {
	if tenant == "" || obs.Src == "" || obs.Dst == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)
	var out []incident.Signal
	out = append(out, e.observeBeacon(tenant, ts, obs)...)
	out = append(out, e.observeEgressVolume(tenant, ts, obs)...)
	out = append(out, e.observeEgressIntel(tenant, ts, obs)...)
	out = append(out, e.observeLateral(tenant, ts, obs)...)
	return out
}

func (e *Engine) observeBeacon(tenant string, ts *tenantState, obs FlowObservation) []incident.Signal {
	var out []incident.Signal
	key := obs.Src + "→" + obs.Dst + ":" + strconv.Itoa(int(obs.DstPort))
	for _, rule := range e.rules[KindBeaconing] {
		st, ok := ts.beacon[key]
		if !ok {
			st = &beaconState{}
			ts.beacon[key] = st
			evictStalest(ts.beacon, e.maxEntities, func(v *beaconState) time.Time { return v.touched })
		}
		st.touched = obs.At
		st.arrivals = append(st.arrivals, obs.At)
		if len(st.arrivals) > beaconRing {
			st.arrivals = st.arrivals[len(st.arrivals)-beaconRing:]
		}
		minSamples := int(rule.Threshold("min_samples", 8))
		if len(st.arrivals) < minSamples+1 { // need minSamples INTERVALS
			continue
		}
		mean, jitter := intervalStats(st.arrivals)
		if mean < rule.Threshold("min_interval_s", 5) || mean > rule.Threshold("max_interval_s", 3600) {
			continue
		}
		maxJitter := rule.Threshold("max_jitter", 0.12)
		if jitter > maxJitter {
			continue
		}
		if ts.suppressed(rule, key, obs.At) {
			continue
		}
		// Confidence: regularity evidence + threat-intel reputation boost.
		conf := rule.BaseConfidence + int(25*(1-jitter/maxJitter))
		evidence := map[string]string{
			"beacon.interval_s": fmt.Sprintf("%.1f", mean),
			"beacon.jitter":     fmt.Sprintf("%.3f", jitter),
			"beacon.samples":    strconv.Itoa(len(st.arrivals) - 1),
		}
		if m := e.bestIntel(obs.Dst); m != nil {
			conf += 20
			evidence["intel.source"] = m.Source
			evidence["intel.category"] = m.Category
			evidence["intel.indicator"] = m.Indicator
			evidence["intel.confidence"] = strconv.Itoa(m.Confidence)
		}
		out = append(out, e.signal(tenant, rule, key, rule.Name,
			fmt.Sprintf("%s calls %s:%d every %.0fs (jitter %.1f%%) — C2-heartbeat pattern",
				obs.Src, obs.Dst, obs.DstPort, mean, 100*jitter),
			conf, obs.At, evidence))
	}
	return out
}

func (e *Engine) observeEgressVolume(tenant string, ts *tenantState, obs FlowObservation) []incident.Signal {
	var out []incident.Signal
	if isInternal(obs.Dst) { // egress only
		return nil
	}
	for _, rule := range e.rules[KindEgressVolume] {
		st, ok := ts.egress[obs.Src]
		if !ok {
			st = &ewmaState{}
			ts.egress[obs.Src] = st
			evictStalest(ts.egress, e.maxEntities, func(v *ewmaState) time.Time { return v.touched })
		}
		st.touched = obs.At
		baseline := st.ewma
		samples := st.samples
		// Update the baseline AFTER judging (a spike must not raise its own bar).
		const alpha = 0.2
		if st.samples == 0 {
			st.ewma = float64(obs.Bytes)
		} else {
			st.ewma = alpha*float64(obs.Bytes) + (1-alpha)*st.ewma
		}
		st.samples++

		if samples < int(rule.Threshold("min_samples", 12)) { // cold start
			continue
		}
		if float64(obs.Bytes) < rule.Threshold("min_bytes", 10*1024*1024) {
			continue
		}
		factor := rule.Threshold("spike_factor", 10)
		if baseline <= 0 || float64(obs.Bytes) < factor*baseline {
			continue
		}
		if ts.suppressed(rule, obs.Src, obs.At) {
			continue
		}
		ratio := float64(obs.Bytes) / baseline
		conf := rule.BaseConfidence + int(math.Min(30, 3*ratio))
		out = append(out, e.signal(tenant, rule, obs.Src, rule.Name,
			fmt.Sprintf("%s pushed %d bytes to %s — %.0fx its own egress baseline",
				obs.Src, obs.Bytes, obs.Dst, ratio),
			conf, obs.At, map[string]string{
				"egress.bytes":          strconv.FormatUint(obs.Bytes, 10),
				"egress.baseline_bytes": fmt.Sprintf("%.0f", baseline),
				"egress.ratio":          fmt.Sprintf("%.1f", ratio),
				"egress.destination":    obs.Dst,
			}))
	}
	return out
}

func (e *Engine) observeEgressIntel(tenant string, ts *tenantState, obs FlowObservation) []incident.Signal {
	var out []incident.Signal
	if isInternal(obs.Dst) {
		return nil
	}
	for _, rule := range e.rules[KindEgressIntel] {
		var (
			conf     int
			category string
			evidence = map[string]string{"egress.destination": obs.Dst}
			hit      bool
		)
		if m := e.bestIntel(obs.Dst); m != nil && float64(m.Confidence) >= rule.Threshold("min_confidence", 50) {
			hit = true
			category = m.Category
			conf = rule.BaseConfidence + m.Confidence/3
			evidence["intel.source"] = m.Source
			evidence["intel.category"] = m.Category
			evidence["intel.indicator"] = m.Indicator
			evidence["intel.confidence"] = strconv.Itoa(m.Confidence)
		}
		if !hit && obs.DstASN != 0 {
			for _, asn := range rule.Lists["bad_asns"] {
				if asn == strconv.FormatUint(uint64(obs.DstASN), 10) {
					hit = true
					category = "bad_asn"
					conf = rule.BaseConfidence + 20
					evidence["egress.asn"] = asn
					break
				}
			}
		}
		if !hit {
			continue
		}
		if ts.suppressed(rule, obs.Src+"→"+obs.Dst, obs.At) {
			continue
		}
		out = append(out, e.signal(tenant, rule, obs.Src+"→"+obs.Dst, rule.Name,
			fmt.Sprintf("%s sends traffic to hostile infrastructure %s (%s)", obs.Src, obs.Dst, category),
			conf, obs.At, evidence))
	}
	return out
}

func (e *Engine) observeLateral(tenant string, ts *tenantState, obs FlowObservation) []incident.Signal {
	var out []incident.Signal
	if !isInternal(obs.Src) || !isInternal(obs.Dst) || obs.Src == obs.Dst {
		return nil
	}
	for _, rule := range e.rules[KindLateral] {
		if !portWatched(rule, obs.DstPort) {
			continue
		}
		window := time.Duration(rule.Threshold("window_s", 300)) * time.Second
		st, ok := ts.lateral[obs.Src]
		if !ok {
			st = &lateralState{dsts: map[string]time.Time{}}
			ts.lateral[obs.Src] = st
			evictStalest(ts.lateral, e.maxEntities, func(v *lateralState) time.Time { return v.touched })
		}
		st.touched = obs.At
		st.dsts[obs.Dst] = obs.At
		for d, at := range st.dsts { // prune the window
			if at.Before(obs.At.Add(-window)) {
				delete(st.dsts, d)
			}
		}
		// Known service relationships (S30 topology) are EXPECTED — exclude them.
		known := map[string]bool{}
		if e.topo != nil {
			if graph, err := e.topo.ForTenant(tenant); err == nil {
				for _, n := range graph.Neighbors(obs.Src, obs.At) {
					known[n] = true
				}
			}
		}
		fanout := 0
		for d := range st.dsts {
			if !known[d] {
				fanout++
			}
		}
		if fanout < int(rule.Threshold("fanout", 10)) {
			continue
		}
		if ts.suppressed(rule, obs.Src, obs.At) {
			continue
		}
		conf := rule.BaseConfidence + int(math.Min(30, float64(fanout)-rule.Threshold("fanout", 10)+10))
		out = append(out, e.signal(tenant, rule, obs.Src, rule.Name,
			fmt.Sprintf("%s reached %d distinct internal hosts on east-west ports within %s",
				obs.Src, fanout, window),
			conf, obs.At, map[string]string{
				"lateral.fanout":   strconv.Itoa(fanout),
				"lateral.port":     strconv.Itoa(int(obs.DstPort)),
				"lateral.excluded": strconv.Itoa(len(known)),
			}))
	}
	return out
}

// --- helpers ---

func (e *Engine) bestIntel(dst string) *opendata.IOCMatch {
	if e.intel == nil {
		return nil
	}
	matches := e.intel.ScoreIP(dst)
	if len(matches) == 0 {
		return nil
	}
	best := matches[0]
	for _, m := range matches[1:] {
		if m.Confidence > best.Confidence {
			best = m
		}
	}
	return &best
}

func portWatched(rule DetectionRule, port uint16) bool {
	ports := rule.Lists["ports"]
	if len(ports) == 0 {
		return true
	}
	p := strconv.Itoa(int(port))
	for _, w := range ports {
		if w == p {
			return true
		}
	}
	return false
}

// appendPruned appends en and drops entries older than cutoff (and caps the
// window so a single hot entity cannot grow unbounded).
func appendPruned[T any](entries []T, en T, cutoff time.Time, at func(T) time.Time) []T {
	entries = append(entries, en)
	keep := entries[:0]
	for _, x := range entries {
		if !at(x).Before(cutoff) {
			keep = append(keep, x)
		}
	}
	if len(keep) > maxWindowEntries {
		keep = keep[len(keep)-maxWindowEntries:]
	}
	return keep
}

// intervalStats returns the mean inter-arrival (seconds) and the jitter
// (stddev/mean — coefficient of variation) of consecutive arrivals.
func intervalStats(arrivals []time.Time) (mean, jitter float64) {
	if len(arrivals) < 2 {
		return 0, math.Inf(1)
	}
	intervals := make([]float64, 0, len(arrivals)-1)
	for i := 1; i < len(arrivals); i++ {
		intervals = append(intervals, arrivals[i].Sub(arrivals[i-1]).Seconds())
	}
	var sum float64
	for _, iv := range intervals {
		sum += iv
	}
	mean = sum / float64(len(intervals))
	if mean <= 0 {
		return 0, math.Inf(1)
	}
	var ss float64
	for _, iv := range intervals {
		d := iv - mean
		ss += d * d
	}
	return mean, math.Sqrt(ss/float64(len(intervals))) / mean
}

// shannonEntropy is bits/char over the string's bytes.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func firstLabel(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return name
}

// registeredDomain naively takes the last two labels ("x.y.evil.example" →
// "evil.example"). A public-suffix list is deliberately out of scope for
// NDR-lite v1 (documented); thresholds absorb the imprecision.
func registeredDomain(name string) string {
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return ""
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// cgnatPrefix is RFC 6598 carrier-grade NAT space (100.64.0.0/10). netip's
// IsPrivate() does NOT include it, but a CGNAT host is INTERNAL (carrier /
// cloud-NAT addressing) — omitting it misclassified those hosts as external, a
// lateral-movement blind spot in the NDR signals (THREAT-001). IPv6 ULA
// (fc00::/7) is already covered by IsPrivate.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isInternal reports whether addr is private/loopback/link-local/ULA/CGNAT.
// Non-IP entities (hostnames from eBPF edges) are treated as internal —
// they are resolved service names inside the cluster.
func isInternal(addr string) bool {
	host := addr
	if h, _, ok := strings.Cut(addr, ":"); ok && !strings.Contains(addr, "::") {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return true
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnatPrefix.Contains(ip.Unmap())
}

func firstGenerated(entries []dnsEntry) string {
	for _, en := range entries {
		if en.generated {
			return en.name
		}
	}
	return ""
}
