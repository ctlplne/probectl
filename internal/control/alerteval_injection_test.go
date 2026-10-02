// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// capturingPromQ records the PromQL the evaluator sends upstream.
type capturingPromQ struct{ last string }

func (c *capturingPromQ) InstantVector(_ context.Context, promql string) ([]tsdb.LabeledSample, error) {
	c.last = promql
	return nil, nil
}

// An alert rule's metric name and match keys must never escape the tenant_id
// pin. The in-memory source must not let a match{tenant_id:...} override the
// pin, and the Prometheus source must build a selector with exactly one
// tenant_id="<own>" matcher and no injected second selector (G7-1).
func TestAlertEvaluatorResistsTenantInjection(t *testing.T) {
	t.Run("memory match cannot override tenant", func(t *testing.T) {
		rows := []tsdb.Series{
			{Metric: "m", Labels: map[string]string{"tenant_id": "t1", "server_address": "a"}, Value: 1},
			{Metric: "m", Labels: map[string]string{"tenant_id": "victim", "server_address": "secret"}, Value: 9},
		}
		src := metricSource{q: fakeQuerier{rows: rows}, tenant: "t1"}
		samples, err := src.Current(context.Background(), "m", map[string]string{"tenant_id": "victim"})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range samples {
			if s.Labels["tenant_id"] != "t1" {
				t.Fatalf("match{tenant_id} overrode the pin: %+v", s.Labels)
			}
		}
	})

	t.Run("prometheus selector pins exactly one tenant, no breakout", func(t *testing.T) {
		q := &capturingPromQ{}
		src := promMetricSource{q: q, tenant: "t1"}
		// A metric name crafted to break out of the selector must be refused
		// before any query is sent.
		if _, err := src.Current(context.Background(), `m} or m{tenant_id="victim"`, nil); err == nil {
			t.Fatalf("injected metric name accepted; query=%q", q.last)
		}
		if q.last != "" {
			t.Fatalf("a query was sent for an injected metric: %q", q.last)
		}
		// A legitimate query pins exactly one tenant_id and carries no operators.
		if _, err := src.Current(context.Background(), "m", map[string]string{"server_address": "a", "tenant_id": "victim"}); err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(q.last, `tenant_id=`); n != 1 {
			t.Fatalf("want exactly one tenant_id matcher, got %d: %q", n, q.last)
		}
		if !strings.Contains(q.last, `tenant_id="t1"`) || strings.Contains(q.last, "victim") {
			t.Fatalf("query not pinned to own tenant: %q", q.last)
		}
		if strings.Contains(q.last, " or ") || strings.Contains(q.last, "}{") {
			t.Fatalf("query contains a second selector / operator: %q", q.last)
		}
	})
}

// Rule.Validate must reject an injected metric name or match key so a poisoned
// rule never reaches the evaluator.
func TestAlertRuleValidateRejectsInjection(t *testing.T) {
	base := alert.Rule{Name: "r", Type: alert.Threshold, Comparison: "gt"}
	for _, tc := range []struct {
		name   string
		mutate func(*alert.Rule)
	}{
		{"metric breakout", func(r *alert.Rule) { r.Metric = `m} or up{foo="bar"` }},
		{"metric space", func(r *alert.Rule) { r.Metric = "m or up" }},
		{"match tenant_id", func(r *alert.Rule) { r.Metric = "m"; r.Match = map[string]string{"tenant_id": "victim"} }},
		{"match __name__", func(r *alert.Rule) { r.Metric = "m"; r.Match = map[string]string{"__name__": "up"} }},
		{"match key breakout", func(r *alert.Rule) { r.Metric = "m"; r.Match = map[string]string{`x="1"} or up{y`: "z"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatalf("Validate accepted injected rule: %+v", r)
			}
		})
	}
	// A clean rule still validates.
	ok := base
	ok.Metric = "probectl_probe_success"
	ok.Match = map[string]string{"server_address": "a"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("clean rule rejected: %v", err)
	}
}
