// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var cT = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

const pciPolicy = `name: pci-segmentation
zones:
  - name: cde
    cidrs: ["10.10.0.0/16"]
  - name: corp
    cidrs: ["10.20.0.0/16"]
  - name: dmz
    cidrs: ["192.0.2.0/24"]
rules:
  - id: corp-to-cde
    description: Corporate systems must never reach the cardholder data environment.
    from: corp
    to: cde
    bidirectional: true
    frameworks:
      pci-dss: "Req 1.3 — network segmentation of the CDE"
      nist-800-207: "ZT tenet 3 — per-session least-privilege access"
  - id: dmz-to-cde-db
    description: DMZ may never reach CDE database ports.
    from: dmz
    to: cde
    ports: [5432, 3306]
    frameworks:
      pci-dss: "Req 1.3.6 — no untrusted access to CHD storage"
`

func testEngine(t *testing.T) *Engine {
	t.Helper()
	p, err := ParsePolicy([]byte(pciPolicy))
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine([]Policy{p})
}

// The sprint's named validation test: declared boundary + fixture flows →
// correct allowed/violation verdicts.
func TestValidationVerdicts(t *testing.T) {
	e := testEngine(t)

	// corp → cde on any port: VIOLATION (bidirectional rule).
	sigs := e.Observe("t1", FlowObs{Src: "10.20.1.5", Dst: "10.10.2.9", DstPort: 443, Bytes: 1024, Source: "flow", At: cT})
	if len(sigs) != 1 {
		t.Fatalf("corp→cde signals = %d", len(sigs))
	}
	sig := sigs[0]
	if sig.Plane != "compliance" || sig.Kind != "compliance.segmentation_violation" ||
		sig.Attributes["compliance.rule"] != "corp-to-cde" {
		t.Fatalf("signal = %+v", sig)
	}
	// The reverse direction violates too (bidirectional), but only alerts once
	// per rule episode — counts still accrue.
	if got := e.Observe("t1", FlowObs{Src: "10.10.2.9", Dst: "10.20.1.5", DstPort: 8080, Source: "ebpf", At: cT.Add(time.Minute)}); len(got) != 0 {
		t.Fatalf("re-alerted within the episode: %+v", got)
	}

	// dmz → cde on 443: NOT in the forbidden port scope → observed_clean.
	if got := e.Observe("t1", FlowObs{Src: "192.0.2.7", Dst: "10.10.2.9", DstPort: 443, Source: "flow", At: cT}); len(got) != 0 {
		t.Fatalf("port-scoped rule fired out of scope: %+v", got)
	}

	results := e.Results("t1")
	if len(results) != 2 {
		t.Fatalf("results = %d", len(results))
	}
	byID := map[string]RuleResult{}
	for _, r := range results {
		byID[r.RuleID] = r
	}
	corp := byID["corp-to-cde"]
	if corp.Verdict != VerdictViolation || corp.Violations != 2 || len(corp.Samples) != 2 {
		t.Fatalf("corp-to-cde = %+v", corp)
	}
	if corp.FirstViolated == nil || corp.LastViolated == nil || !corp.LastViolated.After(*corp.FirstViolated) {
		t.Fatalf("violation timestamps = %+v %+v", corp.FirstViolated, corp.LastViolated)
	}
	dmz := byID["dmz-to-cde-db"]
	if dmz.Verdict != VerdictObservedClean || dmz.Violations != 0 || dmz.ObservedPairs != 1 {
		t.Fatalf("dmz-to-cde-db = %+v", dmz)
	}

	// dmz → cde on 5432: the scoped violation fires.
	if got := e.Observe("t1", FlowObs{Src: "192.0.2.7", Dst: "10.10.2.9", DstPort: 5432, Source: "flow", At: cT}); len(got) != 1 {
		t.Fatalf("scoped violation signals = %d", len(got))
	}

	// Tenant isolation: another tenant's results are untouched (all not_observed).
	for _, r := range e.Results("t2") {
		if r.Verdict != VerdictNotObserved {
			t.Fatalf("cross-tenant verdict: %+v", r)
		}
	}
}

// The sprint's named coverage test: never conclude beyond what's observed.
func TestCoverageGapReporting(t *testing.T) {
	e := testEngine(t)

	// Nothing observed: every rule is not_observed and coverage says so.
	for _, r := range e.Results("t1") {
		if r.Verdict != VerdictNotObserved {
			t.Fatalf("verdict before observation = %+v", r)
		}
	}
	cov := e.CoverageFor("t1")
	if cov.Observations != 0 || cov.ZonesSeen != 0 || cov.ZonesTotal != 3 {
		t.Fatalf("coverage = %+v", cov)
	}
	joined := strings.Join(cov.Notes, " | ")
	for _, want := range []string{"no flow-plane", "no eBPF-plane", "quiet zones are NOT proven isolated", "absence of traffic is not proof"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("coverage notes missing %q: %v", want, cov.Notes)
		}
	}

	// One flow-plane observation between corp and dmz: zones seen, ebpf still flagged.
	e.Observe("t1", FlowObs{Src: "10.20.1.5", Dst: "192.0.2.7", DstPort: 443, Source: "flow", At: cT})
	cov = e.CoverageFor("t1")
	if !cov.FlowObserved || cov.EBPFObserved || cov.ZonesSeen != 2 {
		t.Fatalf("coverage after flow = %+v", cov)
	}
	if !strings.Contains(strings.Join(cov.Notes, " "), "2 of 3 declared zones") {
		t.Fatalf("zone gap note missing: %v", cov.Notes)
	}
	// The word "compliant" never appears anywhere in results or coverage.
	raw, _ := json.Marshal(struct {
		R []RuleResult
		C Coverage
	}{e.Results("t1"), cov})
	if strings.Contains(strings.ToLower(string(raw)), `"compliant"`) {
		t.Fatalf("the engine claimed compliance: %s", raw)
	}
}

// The sprint's named evidence test: format + tamper-evidence.
func TestEvidenceExportFormatAndTamperProof(t *testing.T) {
	e := testEngine(t)
	e.clock = func() time.Time { return cT }
	e.Observe("t1", FlowObs{Src: "10.20.1.5", Dst: "10.10.2.9", DstPort: 443, Source: "flow", At: cT})

	ev, err := e.Export("t1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Version != EvidenceFormatVersion || ev.Tenant != "t1" || !ev.GeneratedAt.Equal(cT) {
		t.Fatalf("evidence header = %+v", ev)
	}
	if len(ev.Records) != 2 || ev.ChainHead == "" {
		t.Fatalf("records = %d head=%q", len(ev.Records), ev.ChainHead)
	}
	// Framework mappings ride the records (PCI + NIST language for auditors).
	raw, _ := json.Marshal(ev)
	for _, want := range []string{"pci-dss", "Req 1.3", "nist-800-207", "coverage", "not proof"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("evidence missing %q", want)
		}
	}
	// The chain verifies…
	if err := VerifyEvidence(ev); err != nil {
		t.Fatal(err)
	}
	// …and any tampering breaks it (audit-grade immutability).
	tampered := ev
	tampered.Records = append([]EvidenceRecord(nil), ev.Records...)
	tampered.Records[0].Result.Violations = 0 // "clean up" the violation
	if err := VerifyEvidence(tampered); err == nil {
		t.Fatal("tampered evidence verified")
	}
	// Round-trip through JSON (the export is self-contained).
	var back Evidence
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidence(back); err != nil {
		t.Fatalf("re-imported evidence failed verification: %v", err)
	}
}

func TestPolicyParsingFailClosed(t *testing.T) {
	cases := map[string]string{
		"no rules":       strings.Split(pciPolicy, "rules:")[0],
		"unknown zone":   strings.Replace(pciPolicy, "from: corp", "from: nonexistent", 1),
		"same from/to":   strings.Replace(pciPolicy, "to: cde\n    bidirectional: true", "to: corp\n    bidirectional: true", 1),
		"bad cidr":       strings.Replace(pciPolicy, "10.10.0.0/16", "not-a-cidr", 1),
		"unknown field":  pciPolicy + "\nenforce: true\n",
		"duplicate rule": strings.Replace(pciPolicy, "id: dmz-to-cde-db", "id: corp-to-cde", 1),
	}
	for name, doc := range cases {
		if _, err := ParsePolicy([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadDirFailClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pci.yaml"), []byte(pciPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := LoadDir(dir)
	if err != nil || len(ps) != 1 {
		t.Fatalf("load: %v %d", err, len(ps))
	}
	if err := os.WriteFile(filepath.Join(dir, "dup.yaml"), []byte(pciPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("duplicate policy accepted")
	}
	if _, err := LoadDir("/does/not/exist"); err == nil {
		t.Fatal("missing dir accepted")
	}
	if ps, err := LoadDir(""); err != nil || ps != nil {
		t.Fatalf("empty config: %v %v", ps, err)
	}
}

func TestLoadDirBoundsPolicyFile(t *testing.T) {
	policyAtSize := func(t *testing.T, size int) []byte {
		t.Helper()
		if size < len(pciPolicy)+2 {
			t.Fatalf("policy fixture size %d is too small", size)
		}
		return []byte(pciPolicy + "\n#" + strings.Repeat("x", size-len(pciPolicy)-2))
	}

	t.Run("maximum valid", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(dir, "maximum.yaml"),
			policyAtSize(t, maxPolicyFileBytes),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		policies, err := LoadDir(dir)
		if err != nil || len(policies) != 1 {
			t.Fatalf("maximum-valid policy: policies=%d err=%v", len(policies), err)
		}
	})

	t.Run("one past", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(dir, "oversized.yaml"),
			policyAtSize(t, maxPolicyFileBytes+1),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDir(dir); err == nil ||
			!strings.Contains(err.Error(), "exceeds 1048576-byte limit") {
			t.Fatalf("one-past policy error = %v, want explicit size refusal", err)
		}
	})
}
