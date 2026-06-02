package ai

import "testing"

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
