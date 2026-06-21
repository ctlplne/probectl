// SPDX-License-Identifier: LicenseRef-probectl-TBD

package threat

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

func mustRules(t *testing.T) []DetectionRule {
	t.Helper()
	rules, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func testEngine(t *testing.T, intel IntelSource, topo NeighborSource) *Engine {
	t.Helper()
	return NewEngine(mustRules(t), intel, topo)
}

var t0 = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

// --- DGA ---

// dgaNames simulates a malware DGA: long, high-entropy, base32-flavored
// labels (the sprint's "DGA set" fixture).
func dgaNames(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("xq%dk7vz0my%dwt3hjb%dfp8c.evil-rendezvous.example", i*7+13, i*31+5, i*17+3))
	}
	return out
}

func TestDGADetection(t *testing.T) {
	e := testEngine(t, nil, nil)
	var fired []incident.Signal
	for i, name := range dgaNames(25) {
		fired = append(fired, e.ObserveDNS("t1", DNSObservation{
			Source: "10.0.0.7", QName: name, At: t0.Add(time.Duration(i) * time.Second)})...)
	}
	var dga []incident.Signal
	for _, s := range fired {
		if s.Kind == "ndr.dns_dga" {
			dga = append(dga, s)
		}
	}
	if len(dga) != 1 {
		t.Fatalf("want exactly 1 DGA detection (suppression after the first), got %d (%+v)", len(dga), fired)
	}
	s := dga[0]
	if s.TenantID != "t1" || s.Target != "10.0.0.7" || s.Plane != "threat" {
		t.Fatalf("signal = %+v", s)
	}
	conf, _ := strconv.Atoi(s.Attributes["detector.confidence"])
	if conf < 50 {
		t.Fatalf("confidence = %d, want >= base", conf)
	}
	if s.Attributes["detector.rule"] != "ndr-dns-dga-default" || s.Attributes["dns.example"] == "" {
		t.Fatalf("evidence attrs = %+v", s.Attributes)
	}
}

func TestDGANormalNamesDoNotFire(t *testing.T) {
	e := testEngine(t, nil, nil)
	normal := []string{"www.example.com", "mail.example.com", "api.acme.example", "cdn.assets.example",
		"login.corp.example", "docs.example.com", "shop.example.com", "blog.example.com"}
	var fired []incident.Signal
	for i := 0; i < 30; i++ {
		fired = append(fired, e.ObserveDNS("t1", DNSObservation{
			Source: "10.0.0.7", QName: normal[i%len(normal)], At: t0.Add(time.Duration(i) * time.Second)})...)
	}
	for _, s := range fired {
		if s.Kind == "ndr.dns_dga" {
			t.Fatalf("normal lookups raised DGA: %+v", s)
		}
	}
}

// --- DNS exfil ---

func TestDNSExfilDetection(t *testing.T) {
	e := testEngine(t, nil, nil)
	var fired []incident.Signal
	// 40 unique long subdomains under one domain — encoded payload chunks
	// (~135 qname bytes each; 40 × 135 ≫ the 4096-byte threshold).
	for i := 0; i < 40; i++ {
		q := fmt.Sprintf("%0120d.tunnel.example", i) // 120-byte payload label
		fired = append(fired, e.ObserveDNS("t1", DNSObservation{
			Source: "10.0.0.9", QName: q, At: t0.Add(time.Duration(i) * time.Second)})...)
	}
	var hits []incident.Signal
	for _, s := range fired {
		if s.Kind == "ndr.dns_exfil" {
			hits = append(hits, s)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 exfil detection, got %d", len(hits))
	}
	if hits[0].Severity != incident.Severity("critical") {
		t.Fatalf("severity = %s", hits[0].Severity)
	}
	if hits[0].Attributes["dns.domain"] != "tunnel.example" {
		t.Fatalf("attrs = %+v", hits[0].Attributes)
	}
	// Tenant isolation: the same behavior in another tenant starts cold.
	if got := e.ObserveDNS("t2", DNSObservation{Source: "10.0.0.9",
		QName: "0001.tunnel.example", At: t0}); len(got) != 0 {
		t.Fatalf("cross-tenant state leak: %+v", got)
	}
}

// --- beaconing ---

func TestBeaconingDetectionAndIntelBoost(t *testing.T) {
	intel := opendata.NewIOCStore()
	intel.Load([]opendata.IOC{{Type: opendata.IOCTypeIP, Value: "203.0.113.66",
		Source: "feodo_tracker", Category: opendata.CategoryBotnetC2, Confidence: 90}})

	plain := testEngine(t, nil, nil)
	boosted := testEngine(t, intel, nil)

	fire := func(e *Engine) []incident.Signal {
		var out []incident.Signal
		for i := 0; i < 12; i++ { // metronome: every 30s exactly
			out = append(out, e.ObserveFlow("t1", FlowObservation{
				Src: "10.0.0.5", Dst: "203.0.113.66", DstPort: 443, Bytes: 512,
				At: t0.Add(time.Duration(i) * 30 * time.Second)})...)
		}
		return out
	}
	confOf := func(sigs []incident.Signal) int {
		for _, s := range sigs {
			if s.Kind == "ndr.beaconing" {
				c, _ := strconv.Atoi(s.Attributes["detector.confidence"])
				return c
			}
		}
		return -1
	}
	plainConf, boostedConf := confOf(fire(plain)), confOf(fire(boosted))
	if plainConf < 0 || boostedConf < 0 {
		t.Fatal("beaconing did not fire")
	}
	if boostedConf <= plainConf {
		t.Fatalf("intel-listed destination must boost confidence: plain=%d boosted=%d", plainConf, boostedConf)
	}
	// The boosted signal carries the intel provenance.
	sigs := fire(testEngine(t, intel, nil))
	for _, s := range sigs {
		if s.Kind == "ndr.beaconing" && s.Attributes["intel.source"] != "feodo_tracker" {
			t.Fatalf("missing intel evidence: %+v", s.Attributes)
		}
	}
}

func TestJitteredTrafficDoesNotBeacon(t *testing.T) {
	e := testEngine(t, nil, nil)
	// Human-ish traffic: irregular gaps (5s..50min, wild swings).
	gaps := []time.Duration{5 * time.Second, 3 * time.Minute, 11 * time.Second, 40 * time.Minute,
		90 * time.Second, 7 * time.Second, 25 * time.Minute, 2 * time.Second, 14 * time.Minute,
		33 * time.Second, 48 * time.Minute, 6 * time.Second}
	at := t0
	for _, g := range gaps {
		at = at.Add(g)
		for _, s := range e.ObserveFlow("t1", FlowObservation{
			Src: "10.0.0.5", Dst: "198.51.100.10", DstPort: 443, Bytes: 2048, At: at}) {
			if s.Kind == "ndr.beaconing" {
				t.Fatalf("jittered traffic raised beaconing: %+v", s)
			}
		}
	}
}

// --- egress volume ---

func TestEgressVolumeSpike(t *testing.T) {
	e := testEngine(t, nil, nil)
	var fired []incident.Signal
	// Baseline: ~1 MiB per observation, 15 samples (past cold start).
	for i := 0; i < 15; i++ {
		fired = append(fired, e.ObserveFlow("t1", FlowObservation{
			Src: "10.0.0.8", Dst: "198.51.100.20", DstPort: 443, Bytes: 1 << 20,
			At: t0.Add(time.Duration(i) * time.Minute)})...)
	}
	for _, s := range fired {
		if s.Kind == "ndr.egress_volume" {
			t.Fatalf("baseline raised a spike: %+v", s)
		}
	}
	// The spike: 64 MiB — 64x baseline, over min_bytes.
	spike := e.ObserveFlow("t1", FlowObservation{
		Src: "10.0.0.8", Dst: "198.51.100.20", DstPort: 443, Bytes: 64 << 20,
		At: t0.Add(20 * time.Minute)})
	var hit *incident.Signal
	for i := range spike {
		if spike[i].Kind == "ndr.egress_volume" {
			hit = &spike[i]
		}
	}
	if hit == nil {
		t.Fatal("64x egress spike did not fire")
	}
	if hit.Attributes["egress.ratio"] == "" || hit.Attributes["egress.baseline_bytes"] == "" {
		t.Fatalf("evidence = %+v", hit.Attributes)
	}
}

func TestEgressColdStartNeverFires(t *testing.T) {
	e := testEngine(t, nil, nil)
	// First-ever observation is huge — but with no baseline it must NOT fire.
	for _, s := range e.ObserveFlow("t1", FlowObservation{
		Src: "10.0.0.99", Dst: "198.51.100.20", DstPort: 443, Bytes: 1 << 30, At: t0}) {
		if s.Kind == "ndr.egress_volume" {
			t.Fatalf("cold start fired: %+v", s)
		}
	}
}

// --- egress intel (Tor / bad ASN) ---

func TestTorEgressDetection(t *testing.T) {
	intel := opendata.NewIOCStore()
	intel.Load([]opendata.IOC{{Type: opendata.IOCTypeIP, Value: "192.0.2.5",
		Source: "tor_exit", Category: opendata.CategoryTorExit, Confidence: 60}})
	e := testEngine(t, intel, nil)

	sigs := e.ObserveFlow("t1", FlowObservation{
		Src: "10.0.0.4", Dst: "192.0.2.5", DstPort: 9001, Bytes: 4096, At: t0})
	var hit *incident.Signal
	for i := range sigs {
		if sigs[i].Kind == "ndr.egress_intel" {
			hit = &sigs[i]
		}
	}
	if hit == nil {
		t.Fatal("Tor egress did not fire")
	}
	if hit.Attributes["intel.category"] != "tor_exit" || hit.Attributes["intel.source"] != "tor_exit" {
		t.Fatalf("attrs = %+v", hit.Attributes)
	}
	if hit.Severity != incident.Severity("critical") {
		t.Fatalf("severity = %s", hit.Severity)
	}
}

func TestBadASNEgressViaRuleOverride(t *testing.T) {
	dir := t.TempDir()
	override := `rules:
  - id: ndr-egress-intel-default
    version: 2
    kind: egress_intel
    name: Egress to hostile infrastructure
    severity: critical
    base_confidence: 60
    suppress: 30m
    thresholds: { min_confidence: 50 }
    lists: { bad_asns: ["64496"] }
`
	if err := writeFile(dir+"/override.yaml", override); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(rules, nil, nil)
	sigs := e.ObserveFlow("t1", FlowObservation{
		Src: "10.0.0.4", Dst: "198.51.100.30", DstPort: 443, DstASN: 64496, Bytes: 1024, At: t0})
	var hit *incident.Signal
	for i := range sigs {
		if sigs[i].Kind == "ndr.egress_intel" {
			hit = &sigs[i]
		}
	}
	if hit == nil {
		t.Fatal("bad-ASN egress did not fire")
	}
	if hit.Attributes["egress.asn"] != "64496" || hit.Attributes["detector.rule_version"] != "2" {
		t.Fatalf("attrs = %+v", hit.Attributes)
	}
}

// --- lateral movement ---

type fakeTopo struct{ known []string }

func (f fakeTopo) ForTenant(string) (topology.TenantStore, error) {
	return fakeTenantTopo(f), nil
}

type fakeTenantTopo struct{ known []string }

func (f fakeTenantTopo) ObservePath(topology.PathInput, time.Time)               {}
func (f fakeTenantTopo) ObserveServiceEdge(topology.ServiceEdgeInput, time.Time) {}
func (f fakeTenantTopo) ObserveRouting(topology.RoutingInput, time.Time)         {}
func (f fakeTenantTopo) ObserveDevice(topology.DeviceInput, time.Time)           {}
func (f fakeTenantTopo) SnapshotAt(at time.Time) topology.Snapshot               { return topology.Snapshot{At: at} }
func (f fakeTenantTopo) Latest() topology.Snapshot                               { return topology.Snapshot{} }
func (f fakeTenantTopo) Neighbors(string, time.Time) []string                    { return f.known }
func (f fakeTenantTopo) Traverse(string, string, time.Time) []string             { return nil }

func TestLateralFanoutWithTopologyExclusion(t *testing.T) {
	// 11 distinct internal SMB destinations; 2 are KNOWN service neighbors
	// (S30) and must not count: effective fanout 9 < 10 → quiet. A 12th and
	// 13th unknown destination push it to 11 → fires.
	e := testEngine(t, nil, fakeTopo{known: []string{"10.0.1.1", "10.0.1.2"}})
	var fired []incident.Signal
	for i := 1; i <= 13; i++ {
		fired = append(fired, e.ObserveFlow("t1", FlowObservation{
			Src: "10.0.0.66", Dst: fmt.Sprintf("10.0.1.%d", i), DstPort: 445, Bytes: 100,
			At: t0.Add(time.Duration(i) * time.Second)})...)
	}
	var hits []incident.Signal
	for _, s := range fired {
		if s.Kind == "ndr.lateral" {
			hits = append(hits, s)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 lateral detection, got %d", len(hits))
	}
	if hits[0].Attributes["lateral.excluded"] != "2" {
		t.Fatalf("topology exclusion not applied: %+v", hits[0].Attributes)
	}
	fan, _ := strconv.Atoi(hits[0].Attributes["lateral.fanout"])
	if fan < 10 {
		t.Fatalf("fanout = %d", fan)
	}
}

func TestLateralIgnoresUnwatchedPortsAndEgress(t *testing.T) {
	e := testEngine(t, nil, nil)
	for i := 1; i <= 20; i++ {
		// Port 80 isn't in the watched east-west list; dst 198.x is egress.
		for _, s := range append(
			e.ObserveFlow("t1", FlowObservation{Src: "10.0.0.66", Dst: fmt.Sprintf("10.0.2.%d", i), DstPort: 80, At: t0.Add(time.Duration(i) * time.Second)}),
			e.ObserveFlow("t1", FlowObservation{Src: "10.0.0.66", Dst: fmt.Sprintf("198.51.100.%d", i), DstPort: 445, At: t0.Add(time.Duration(i) * time.Second)})...) {
			if s.Kind == "ndr.lateral" {
				t.Fatalf("unwatched/egress traffic raised lateral: %+v", s)
			}
		}
	}
}

// --- suppression + tunability ---

func TestSuppressionWindowAndReFire(t *testing.T) {
	intel := opendata.NewIOCStore()
	intel.Load([]opendata.IOC{{Type: opendata.IOCTypeIP, Value: "192.0.2.5",
		Source: "tor_exit", Category: opendata.CategoryTorExit, Confidence: 60}})
	e := testEngine(t, intel, nil)

	count := func(sigs []incident.Signal) int {
		n := 0
		for _, s := range sigs {
			if s.Kind == "ndr.egress_intel" {
				n++
			}
		}
		return n
	}
	flow := func(at time.Time) []incident.Signal {
		return e.ObserveFlow("t1", FlowObservation{Src: "10.0.0.4", Dst: "192.0.2.5", DstPort: 9001, At: at})
	}
	if count(flow(t0)) != 1 {
		t.Fatal("first observation must fire")
	}
	// Within the 30m suppress window: quiet, however many times it recurs.
	for i := 1; i <= 10; i++ {
		if count(flow(t0.Add(time.Duration(i)*time.Minute))) != 0 {
			t.Fatal("suppression window violated")
		}
	}
	// After the window: it fires again (the behavior persisted).
	if count(flow(t0.Add(31*time.Minute))) != 1 {
		t.Fatal("did not re-fire after the suppression window")
	}
}

func TestDisabledRuleIsSilent(t *testing.T) {
	dir := t.TempDir()
	off := `rules:
  - id: ndr-egress-intel-default
    version: 2
    kind: egress_intel
    name: Egress to hostile infrastructure
    severity: critical
    base_confidence: 60
    suppress: 30m
    enabled: false
`
	if err := writeFile(dir+"/off.yaml", off); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	intel := opendata.NewIOCStore()
	intel.Load([]opendata.IOC{{Type: opendata.IOCTypeIP, Value: "192.0.2.5",
		Source: "tor_exit", Category: opendata.CategoryTorExit, Confidence: 60}})
	e := NewEngine(rules, intel, nil)
	for _, s := range e.ObserveFlow("t1", FlowObservation{Src: "10.0.0.4", Dst: "192.0.2.5", DstPort: 9001, At: t0}) {
		if s.Kind == "ndr.egress_intel" {
			t.Fatalf("disabled rule fired: %+v", s)
		}
	}
}

// --- detection recognizer + signals-only guarantee ---

func TestNDRSignalBecomesDetection(t *testing.T) {
	e := testEngine(t, nil, nil)
	var sig *incident.Signal
	for i, name := range dgaNames(25) {
		for _, s := range e.ObserveDNS("t1", DNSObservation{Source: "10.0.0.7", QName: name,
			At: t0.Add(time.Duration(i) * time.Second)}) {
			if s.Kind == "ndr.dns_dga" {
				s := s
				sig = &s
			}
		}
	}
	if sig == nil {
		t.Fatal("no DGA signal")
	}
	d, ok := DetectionFromSignal(*sig, "inc-7")
	if !ok {
		t.Fatal("NDR signal not recognized as a detection")
	}
	if d.Source != "ndr-dns-dga-default" || d.Category != "dns_dga" || d.IncidentID != "inc-7" {
		t.Fatalf("detection = %+v", d)
	}
	if d.Confidence < 50 {
		t.Fatalf("confidence = %d", d.Confidence)
	}
}

// The engine emits SIGNALS only: its outputs are incident.Signal values and
// nothing in the package exposes an enforcement/block surface (guardrail 9).
// This is a compile-time property; the test documents the wire contract.
func TestSignalsCarryNoActionFields(t *testing.T) {
	e := testEngine(t, nil, nil)
	sigs := e.ObserveFlow("t1", FlowObservation{Src: "10.0.0.1", Dst: "10.0.0.2", DstPort: 445, At: t0})
	for _, s := range sigs {
		for k := range s.Attributes {
			if strings.HasPrefix(k, "action") || strings.HasPrefix(k, "block") {
				t.Fatalf("signal carries an action-like attribute %q", k)
			}
		}
	}
}
