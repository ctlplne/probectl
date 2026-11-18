// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

import (
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestTenantBoundPoliciesKeepOverlappingNetworksEvidenceAndMutableInputsIsolated(t *testing.T) {
	policy := func(name string, port uint16) Policy {
		p, err := ParsePolicy([]byte(pciPolicy))
		if err != nil {
			t.Fatal(err)
		}
		p.Name = name
		p.Rules = p.Rules[:1]
		p.Rules[0].ID = name + "-boundary"
		p.Rules[0].Ports = []uint16{port}
		return p
	}
	red, blue := policy("red-policy", 443), policy("blue-policy", 8443)
	input := map[string][]Policy{"red": {red}, "blue": {blue}}
	engine, err := NewTenantEngine(input)
	if err != nil {
		t.Fatal(err)
	}
	observation := FlowObs{Src: "10.20.1.1", Dst: "10.10.1.1", DstPort: 443, Bytes: 101, Source: "flow", At: time.Now().UTC()}
	if len(engine.Observe("red", observation)) != 1 || len(engine.Observe("blue", observation)) != 0 {
		t.Fatal("overlapping tenant addresses applied another tenant's rule")
	}
	for _, tenant := range []string{"red", "blue"} {
		rows := engine.Results(tenant)
		if len(rows) != 1 || rows[0].Policy != tenant+"-policy" || rows[0].RuleID != tenant+"-policy-boundary" {
			t.Fatal("policy storage/query boundary returned another tenant's rule", tenant, rows)
		}
		want := VerdictObservedClean
		if tenant == "red" {
			want = VerdictViolation
		}
		if rows[0].Verdict != want || rows[0].ObservedPairs != 1 {
			t.Fatal("own declared port scope or measured coverage changed", tenant, rows)
		}
		coverage := engine.CoverageFor(tenant)
		if coverage.Observations != 1 || coverage.ZonesTotal != 3 || coverage.ZonesSeen != 2 {
			t.Fatal("coverage counted another tenant's policies or traffic", tenant, coverage)
		}
		private, _, err := crypto.GenerateEd25519KeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := engine.Export(tenant)
		if err != nil || evidence.Tenant != tenant || len(evidence.Policies) != 1 || evidence.Policies[0] != tenant+"-policy" || len(evidence.Records) != 1 {
			t.Fatal("signed evidence input crossed the policy boundary", tenant, evidence, err)
		}
		raw, err := SignEvidence(evidence, private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySignedEvidence(raw); err != nil {
			t.Fatal("own policy evidence cannot verify offline", err)
		}
	}
	red.Rules[0].Ports[0] = 8443
	red.Rules[0].Frameworks["pci-dss"] = "caller mutation"
	input["red"] = []Policy{blue}
	rows := engine.Results("red")
	rows[0].Frameworks["pci-dss"] = "result mutation"
	engine.Observe("red", observation)
	rows = engine.Results("red")
	if rows[0].Violations != 2 || rows[0].Frameworks["pci-dss"] != "Req 1.3 — network segmentation of the CDE" || engine.Results("blue")[0].Violations != 0 {
		t.Fatal("mutable caller/result storage poisoned a bound policy", rows)
	}
	engine.Observe("unbound", observation)
	if len(engine.Results("unbound")) != 0 || engine.CoverageFor("unbound").Observations != 0 || engine.CoverageFor("unbound").ZonesTotal != 0 {
		t.Fatal("unbound tenant inherited a deployment policy")
	}
	if _, err := NewTenantEngine(map[string][]Policy{"": {red}}); err == nil {
		t.Fatal("empty tenant binding accepted")
	}
}

func TestTenantEvidenceCoverageAndVerdictsUseTheSameSnapshot(t *testing.T) {
	policies := make(map[string][]Policy)
	for _, tenant := range []string{"red", "blue"} {
		p, err := ParsePolicy([]byte(pciPolicy))
		if err != nil {
			t.Fatal(err)
		}
		p.Name = tenant + "-policy"
		p.Rules = p.Rules[:1]
		p.Rules[0].Ports = []uint16{443}
		policies[tenant] = []Policy{p}
	}
	engine, err := NewTenantEngine(policies)
	if err != nil {
		t.Fatal(err)
	}
	red := FlowObs{Src: "10.20.1.1", Dst: "10.10.1.1", DstPort: 443, Source: "flow", At: time.Now().UTC()}
	blue := red
	blue.DstPort = 8443
	engine.Observe("red", red)
	engine.Observe("blue", blue)
	stop := make(chan struct{})
	var writers sync.WaitGroup
	for tenant, sample := range map[string]FlowObs{"red": red, "blue": blue} {
		writers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					engine.Observe(tenant, sample)
				}
			}
		})
	}
	defer func() {
		close(stop)
		writers.Wait()
	}()
	for range 1000 {
		for _, tenant := range []string{"red", "blue"} {
			evidence, err := engine.Export(tenant)
			if err != nil || evidence.Tenant != tenant || len(evidence.Records) != 1 {
				t.Fatal("tenant evidence unavailable", tenant, err)
			}
			rule := evidence.Records[0].Result
			if rule.ObservedPairs != evidence.Coverage.Observations {
				t.Fatalf("tenant %s has %d rule observations but %d coverage observations", tenant, rule.ObservedPairs, evidence.Coverage.Observations)
			}
			want := VerdictObservedClean
			if tenant == "red" {
				want = VerdictViolation
			}
			if rule.Policy != tenant+"-policy" || rule.Verdict != want || rule.ObservedPairs == 0 {
				t.Fatal("concurrent export lost its tenant's verdict", tenant, rule.Policy, rule.Verdict)
			}
		}
	}
}
