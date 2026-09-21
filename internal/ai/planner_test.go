// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"testing"
	"time"
)

func domainsOf(qs []Query) map[Domain]bool {
	m := map[Domain]bool{}
	for _, q := range qs {
		m[q.Domain] = true
	}
	return m
}

func TestPlannerSelectsPlanesByLanguage(t *testing.T) {
	p := HeuristicPlanner{}

	// "slow" → metrics + topology (+ entities always), but not events.
	d := domainsOf(p.Plan(Question{Text: "why is api.example.com slow?"}))
	if !d[DomainEntities] || !d[DomainMetrics] || !d[DomainTopology] {
		t.Errorf("slow-question domains = %v", d)
	}
	if d[DomainEvents] {
		t.Errorf("slow question should not gather events: %v", d)
	}

	// routing language → events.
	if !domainsOf(p.Plan(Question{Text: "any bgp route withdrawal for 10.0.0.0/24?"}))[DomainEvents] {
		t.Error("routing question should gather events")
	}
}

func TestPlannerExtractsSubject(t *testing.T) {
	p := HeuristicPlanner{}

	if qs := p.Plan(Question{Text: "is 192.168.1.0/24 being hijacked?"}); qs[0].Selector["prefix"] != "192.168.1.0/24" {
		t.Errorf("prefix not extracted: %+v", qs[0].Selector)
	}

	qs := p.Plan(Question{Text: "why is shop.example.com slow?"})
	if qs[0].Selector["target"] != "shop.example.com" {
		t.Errorf("host not extracted: %+v", qs[0].Selector)
	}
	var topo *Query
	for i := range qs {
		if qs[i].Domain == DomainTopology {
			topo = &qs[i]
		}
	}
	if topo == nil || topo.NodeID != "service:shop.example.com" {
		t.Errorf("topology should anchor on the subject, got %+v", topo)
	}
}

func TestPlannerTopologySkippedWithoutSubject(t *testing.T) {
	// "topology" language but no subject anchor → no topology query (no graph dump).
	if domainsOf(HeuristicPlanner{}.Plan(Question{Text: "show me the dependency topology"}))[DomainTopology] {
		t.Error("topology without a subject anchor should be skipped")
	}
}

func TestPlannerHonorsExplicitSubject(t *testing.T) {
	qs := HeuristicPlanner{}.Plan(Question{Text: "why slow?", Subject: map[string]string{"target": "db-1"}})
	if qs[0].Selector["target"] != "db-1" {
		t.Errorf("explicit subject ignored: %+v", qs[0].Selector)
	}
}

func TestPlannerIncidentSubjectDoesNotBroaden(t *testing.T) {
	queries := (HeuristicPlanner{}).Plan(Question{
		Text:    "explain this copied incident",
		Subject: map[string]string{"incident_id": "inc-foreign-or-stale"},
	})
	if len(queries) != 1 || queries[0].Domain != DomainEntities {
		t.Fatalf("incident-only subject must resolve only through tenant-scoped entities, got %+v", queries)
	}
	if queries[0].Selector["incident_id"] != "inc-foreign-or-stale" {
		t.Fatalf("incident selector lost: %+v", queries[0].Selector)
	}
}

func TestPlannerLeavesTopologyAtAsLatestUnlessExplicit(t *testing.T) {
	qs := HeuristicPlanner{}.Plan(Question{Text: "why is 192.0.2.0/24 slow?"})
	var topo *Query
	for i := range qs {
		if qs[i].Domain == DomainTopology {
			topo = &qs[i]
			break
		}
	}
	if topo == nil {
		t.Fatal("expected a topology query")
	}
	if !topo.Range.At.IsZero() {
		t.Fatalf("ordinary RCA should query latest topology, got At=%s", topo.Range.At)
	}

	at := time.Unix(123, 0)
	qs = HeuristicPlanner{}.Plan(Question{
		Text:  "why is 192.0.2.0/24 slow?",
		Range: TimeRange{At: at},
	})
	topo = nil
	for i := range qs {
		if qs[i].Domain == DomainTopology {
			topo = &qs[i]
			break
		}
	}
	if topo == nil || !topo.Range.At.Equal(at) {
		t.Fatalf("explicit topology At was not preserved: %+v", topo)
	}
}

func TestInvestigationPlanIsBoundedAndReadOnly(t *testing.T) {
	queries := []Query{
		{Domain: DomainEntities, Selector: map[string]string{"target": "checkout"}, Limit: 50},
		{Domain: DomainMetrics, Selector: map[string]string{"target": "checkout"}, Limit: 50},
		{Domain: DomainEvents, Selector: map[string]string{"target": "checkout"}, Limit: 50},
		{Domain: DomainTopology, NodeID: "service:checkout", Limit: 50},
		{Domain: DomainMetrics, Selector: map[string]string{"target": "db"}, Limit: 50},
		{Domain: DomainEvents, Selector: map[string]string{"target": "db"}, Limit: 50},
	}
	steps := HeuristicPlanner{}.InvestigationPlan(Question{}, queries)
	if len(steps) != MaxInvestigationSteps {
		t.Fatalf("steps = %d, want cap %d", len(steps), MaxInvestigationSteps)
	}
	for i, step := range steps {
		if step.Step != i+1 || !step.ReadOnly || step.Status != InvestigationPlanned {
			t.Fatalf("step %d = %+v", i, step)
		}
		if step.Goal == "" {
			t.Fatalf("step %d has empty goal", i)
		}
	}
	if steps[0].Selector["target"] != "checkout" {
		t.Fatalf("selector was not copied: %+v", steps[0].Selector)
	}
	queries[0].Selector["target"] = "mutated"
	if steps[0].Selector["target"] != "checkout" {
		t.Fatalf("plan selector aliases query map: %+v", steps[0].Selector)
	}
}

// DPR-069: signals carry the host, so a URL subject (pasted from a test
// definition) or a URL in the question must resolve to that host.
func TestSubjectURLIsReducedToItsHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		q    Question
		want string
	}{
		{"url subject", Question{Text: "why is checkout failing?", Subject: map[string]string{"target": "https://example.com/checkout"}}, "example.com"},
		{"host:port subject", Question{Text: "why?", Subject: map[string]string{"target": "example.com:443"}}, "example.com"},
		{"host subject unchanged", Question{Text: "why?", Subject: map[string]string{"target": "checkout.eu.acme.example"}}, "checkout.eu.acme.example"},
		{"url in the question", Question{Text: "why is https://api.example/health slow?"}, "api.example"},
	} {
		if got := extractSubject(tc.q)["target"]; got != tc.want {
			t.Errorf("%s: target = %q, want %q", tc.name, got, tc.want)
		}
	}
}
