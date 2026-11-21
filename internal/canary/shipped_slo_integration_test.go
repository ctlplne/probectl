// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package canary_test

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

const sloReceiptService = "checkout-reliability"

type shippedSLOLane struct {
	tenant, cookie, token string
	name, display, team   string
	selected, distractor  string
	observed, noise       string
	agents                []string
	startedAt             time.Time
}

type shippedSLOStatus struct {
	Running   bool         `json:"slo_running"`
	DataSince *time.Time   `json:"data_since,omitempty"`
	Items     []slo.Status `json:"items"`
}

type shippedSLOCounts struct {
	selected uint64
	good     uint64
	noise    uint64
	noiseBad uint64
}

// The targets are local HTTPS health endpoints. Only the selected checkout
// endpoint changes status. A continuously failing, same-host test in the
// other tenant demonstrates that OpenSLO selects the original configured test.
func TestSLOFromShippedHTTPRuns(t *testing.T) {
	var degraded atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/west/selected":
			if degraded.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/east/distractor":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/west/distractor", "/east/selected":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	t.Setenv("PROBECTL_AGENT_CANARY_CA_DIR", dir)
	ca := filepath.Join(dir, "local-target.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	definitions := filepath.Join(dir, "objectives")
	if err := os.Mkdir(definitions, 0o700); err != nil {
		t.Fatal(err)
	}
	stack := shipped.Start(t, shipped.Options{Name: "slo-observed-budget", TenantBand: 3, Env: map[string]string{
		"PROBECTL_SLO_ENABLED": "true",
		"PROBECTL_SLO_DIR":     definitions,
	}})
	operator := stack.OnboardOperator(t, "root@msp-slo.example")
	lanes := []shippedSLOLane{
		{name: "checkout-west", display: "Checkout western objective", team: "west-payments", observed: server.URL + "/west/selected", noise: server.URL + "/west/distractor"},
		{name: "checkout-east", display: "Checkout eastern objective", team: "east-payments", observed: server.URL + "/east/selected", noise: server.URL + "/east/distractor"},
	}
	for i := range lanes {
		lane := &lanes[i]
		lane.provision(t, stack, operator, ca, i)
		if err := os.WriteFile(filepath.Join(definitions, lane.name+".yaml"), lane.definition(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stack.RestartControl(t, "slo-configured", nil)
	for i := range lanes {
		lane := &lanes[i]
		assertEmptySLOWindows(t, lane.read(t, stack))
		lane.startedAt = time.Now()
		lane.runShippedAgents(t, stack, ca)
	}
	for i := range lanes {
		lane := &lanes[i]
		shipped.Await(t, "enrolled HTTPS results cross the cold-start floor", 215*time.Second, func() bool {
			state := lane.read(t, stack)
			return len(state.Items) == 1 && !state.Items[0].ColdStart && state.Items[0].TotalEvents >= slo.MinEvents
		})
		state := lane.read(t, stack)
		if got := state.Items[0]; got.Attainment != 1 || got.ErrorBudgetRemaining != 1 || !got.WindowFilling {
			t.Fatal("a same-host distractor or foreign result changed the healthy budget", lane.name, got)
		}
	}
	degraded.Store(true)
	shipped.Await(t, "real failed checkout probes fire all three burn tiers", 92*time.Second, func() bool {
		states := lanes[0].read(t, stack).Items
		if len(states) != 1 || len(states[0].BurnRates) != 3 {
			return false
		}
		for _, window := range states[0].BurnRates {
			if !window.Firing {
				return false
			}
		}
		return states[0].ErrorBudgetRemaining == 0
	})

	for i := range lanes {
		for _, agentName := range lanes[i].agents {
			stack.Stop(t, "agent-"+agentName)
		}
	}
	var captures [2]shippedSLOStatus
	var counts [2]shippedSLOCounts
	for i := range lanes {
		lane, sibling := &lanes[i], &lanes[1-i]
		var preceding shippedSLOCounts
		var stableSince time.Time
		shipped.Await(t, "status and retained original probe results agree after delivery", 25*time.Second, func() bool {
			captures[i] = lane.read(t, stack)
			counts[i] = lane.history(t, stack, sibling)
			if len(captures[i].Items) != 1 || captures[i].Items[0].TotalEvents != counts[i].selected || counts[i].noise == 0 {
				stableSince = time.Time{}
				return false
			}
			if stableSince.IsZero() || preceding != counts[i] {
				preceding, stableSince = counts[i], time.Now()
			}
			return time.Since(stableSince) >= time.Second
		})
		assertSLOPollBudget(t, lane, captures[i], counts[i], i == 0)
		lane.verifyCLIAndOpenSLO(t, stack, captures[i], sibling)
		lane.verifyRenderedBudget(t, stack, sibling, i == 0)
	}
	inc := waitShippedSLOBurn(t, stack, &lanes[0])
	assertShippedSLOIsolation(t, stack, &lanes[1], inc.ID)
	stack.RestartControl(t, "slo-after-budget-restart", nil)
	for i := range lanes {
		assertEmptySLOWindows(t, lanes[i].read(t, stack))
	}
	retained := waitShippedSLOBurn(t, stack, &lanes[0])
	if retained.ID != inc.ID || retained.SignalCount != inc.SignalCount {
		t.Fatal("the persistent burn incident changed when the in-memory budget restarted")
	}
	assertShippedSLOIsolation(t, stack, &lanes[1], retained.ID)
}

func (lane *shippedSLOLane) provision(t *testing.T, stack *shipped.Stack, operator, ca string, index int) {
	t.Helper()
	var tenant struct{ ID string }
	slug := fmt.Sprintf("%s-%d", lane.name, time.Now().UnixNano())
	stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant,
		"provider", "create-tenant", "--body", fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, slug, lane.display))
	lane.tenant = tenant.ID
	email := [2]string{"ada@acme.example", "bob@globex.example"}[index]
	lane.cookie = stack.SignIn(t, lane.tenant, email, lane.display)
	lane.token = stack.APIToken(t, lane.cookie, "metrics.read")
	create := func(name, target string) string {
		t.Helper()
		var test struct{ ID string }
		lane.call(t, stack, http.MethodPost, "/v1/tests", http.StatusCreated, map[string]any{
			"name": name, "type": "http", "target": target, "enabled": true,
			"interval_seconds": 10, "timeout_seconds": 5,
			"params": map[string]string{"allow_private_targets": "true", "ca_file": ca},
		}, &test)
		if test.ID == "" {
			t.Fatal("the configured test has no canonical identity")
		}
		return test.ID
	}
	lane.selected = create(lane.name+"-selected", lane.observed)
	lane.distractor = create(lane.name+"-distractor", lane.noise)
}

func (lane *shippedSLOLane) runShippedAgents(t *testing.T, stack *shipped.Stack, ca string) {
	t.Helper()
	for index := range 3 {
		name := fmt.Sprintf("%s-vantage-%d", lane.name, index)
		agentID, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		dir := stack.EnrollAgent(t, lane.tenant, agentID, name)
		stack.StartAgent(t, dir, name, []string{"http"}, fmt.Sprintf(`canaries:
  - test_id: %q
    type: http
    target: %q
    interval: 10s
    timeout: 5s
    params:
      allow_private_targets: "true"
      ca_file: %q
  - test_id: %q
    type: http
    target: %q
    interval: 10s
    timeout: 5s
    params:
      allow_private_targets: "true"
      ca_file: %q
`, lane.selected, lane.observed, ca, lane.distractor, lane.noise, ca))
		lane.agents = append(lane.agents, name)
	}
}

func (lane *shippedSLOLane) definition() []byte {
	return []byte(fmt.Sprintf(`apiVersion: openslo/v1
kind: SLO
metadata:
  name: %s
  displayName: %q
  labels:
    tenant: %q
    team: %q
spec:
  service: %s
  indicator:
    metadata: {name: selected-checkout}
    spec:
      ratioMetric:
        good:
          metricSource:
            type: probectl
            spec: {canary_type: http, test_id: %q, outcome: success}
        total:
          metricSource:
            type: probectl
            spec: {canary_type: http, test_id: %q}
  timeWindow: [{duration: 30d, isRolling: true}]
  budgetingMethod: Occurrences
  objectives: [{target: 0.99}]
`, lane.name, lane.display, lane.tenant, lane.team, sloReceiptService, lane.selected, lane.selected))
}

func (lane *shippedSLOLane) call(t *testing.T, stack *shipped.Stack, method, path string, want int, input, output any) []byte {
	t.Helper()
	code, raw := stack.Do(t, lane.cookie, method, path, input)
	if code != want {
		t.Fatal("unexpected scoped SLO endpoint status", lane.name, method, path, code, want)
	}
	if output != nil {
		if err := json.Unmarshal(raw, output); err != nil {
			t.Fatal(err)
		}
	}
	return raw
}

func (lane *shippedSLOLane) read(t *testing.T, stack *shipped.Stack) shippedSLOStatus {
	t.Helper()
	var result shippedSLOStatus
	lane.call(t, stack, http.MethodGet, "/v1/slos", http.StatusOK, nil, &result)
	return result
}

func (lane *shippedSLOLane) history(t *testing.T, stack *shipped.Stack, sibling *shippedSLOLane) shippedSLOCounts {
	t.Helper()
	var history struct {
		Items []struct {
			ID         string            `json:"result_id"`
			Attributes map[string]string `json:"attributes"`
			Success    bool              `json:"success"`
			Target     string            `json:"target"`
		} `json:"items"`
	}
	lane.call(t, stack, http.MethodGet, "/v1/results/history?window=1h", http.StatusOK, nil, &history)
	var counts shippedSLOCounts
	seen := make(map[string]bool)
	for _, row := range history.Items {
		testID := row.Attributes[otel.AttrTestID]
		var target string
		switch testID {
		case lane.selected:
			target = lane.observed
		case lane.distractor:
			target = lane.noise
		case sibling.selected, sibling.distractor:
			t.Fatal("retained original result escaped its tenant", lane.name)
		default:
			continue
		}
		statusCode := "503"
		if row.Success {
			statusCode = "200"
		}
		if row.Target != target || row.Attributes[otel.AttrHTTPResponseStatusCode] != statusCode || row.ID == "" || seen[row.ID] {
			t.Fatal("the shipped probe history lost its original target, HTTP response or unique result identity", lane.name, testID)
		}
		seen[row.ID] = true
		if testID == lane.selected {
			counts.selected++
			if row.Success {
				counts.good++
			}
		} else {
			counts.noise++
			if !row.Success {
				counts.noiseBad++
			}
		}
	}
	return counts
}

func assertSLOPollBudget(t *testing.T, lane *shippedSLOLane, state shippedSLOStatus, counts shippedSLOCounts, degraded bool) {
	t.Helper()
	item := state.Items[0]
	want := float64(counts.good) / float64(counts.selected)
	wantBudget := math.Max(0, 1-(1-want)/(1-0.99))
	if !state.Running || state.DataSince == nil || !item.DataSince.Equal(*state.DataSince) ||
		item.DataSince.Before(lane.startedAt) || item.DataSince.After(time.Now()) ||
		item.Name != lane.name || item.Service != sloReceiptService || item.Team != lane.team ||
		item.Objective != 0.99 || item.TotalEvents < slo.MinEvents || item.ColdStart || !item.WindowFilling ||
		math.Abs(item.Attainment-want) > 1e-9 || math.Abs(item.ErrorBudgetRemaining-wantBudget) > 1e-9 {
		t.Fatal("objective status did not measure the exact original configured-test cohort", lane.name, item, counts)
	}
	if (degraded && (want <= 0 || want >= 1 || item.ErrorBudgetRemaining != 0 || counts.noiseBad != 0)) ||
		(!degraded && (counts.noiseBad != counts.noise || want != 1 || item.ErrorBudgetRemaining != 1)) {
		t.Fatal("the selected failure or same-host distractor changed the wrong budget", lane.name, item, counts)
	}
	for _, rate := range item.BurnRates {
		if rate.Firing != degraded {
			t.Fatal("two-window state did not match the original results", lane.name, rate)
		}
	}
}

func assertEmptySLOWindows(t *testing.T, status shippedSLOStatus) {
	t.Helper()
	if !status.Running || status.DataSince != nil || len(status.Items) != 1 {
		t.Fatal("an empty engine returned a known tenant evaluation clock", status)
	}
	item := status.Items[0]
	if item.TotalEvents != 0 || !item.DataSince.IsZero() || !item.ColdStart || !item.WindowFilling {
		t.Fatal("an unobserved objective claimed coverage before its own probes", item)
	}
}

func (lane *shippedSLOLane) verifyCLIAndOpenSLO(t *testing.T, stack *shipped.Stack, state shippedSLOStatus, sibling *shippedSLOLane) {
	t.Helper()
	env := map[string]string{"PROBECTL_API_TOKEN": lane.token}
	var cli shippedSLOStatus
	stack.MustCLI(t, env, &cli, "slo", "list")
	if len(cli.Items) != 1 || cli.Items[0].TotalEvents != state.Items[0].TotalEvents ||
		cli.Items[0].Attainment != state.Items[0].Attainment || cli.Items[0].Name != lane.name {
		t.Fatal("CLI lost the scored result or returned a foreign SLO", lane.name)
	}
	raw := lane.call(t, stack, http.MethodGet, "/v1/slos/openslo", http.StatusOK, nil, nil)
	definition, err := slo.Parse(raw)
	if err != nil || definition.TenantID != lane.tenant || definition.TestID != lane.selected ||
		definition.Name != lane.name || definition.Team != lane.team || bytes.Contains(raw, []byte(sibling.selected)) {
		t.Fatal("the OpenSLO source omitted or mixed original tenant definitions", lane.name, err)
	}
	stdout, _, code := stack.CLI(env, "slo", "export")
	if code != 0 || strings.TrimSpace(stdout) != strings.TrimSpace(string(raw)) {
		t.Fatal("the CLI changed the tenant's exported OpenSLO document")
	}
}

func (lane *shippedSLOLane) verifyRenderedBudget(t *testing.T, stack *shipped.Stack, sibling *shippedSLOLane, degraded bool) {
	t.Helper()
	remaining := "100.000% of the error budget remains"
	if degraded {
		remaining = "0.00% of the error budget remains"
	}
	for _, theme := range []string{"light", "dark"} {
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL:            stack.BaseURL + "/ui/slos",
			Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
			TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile, Theme: theme, Accessibility: true,
			Expect: []string{lane.display, lane.team}, Absent: []string{sibling.display, sibling.team},
			Controls: []testsupport.RenderControl{{Role: "table", Name: "SLO statuses"}, {Role: "img", Name: remaining}},
		})
	}
}

func waitShippedSLOBurn(t *testing.T, stack *shipped.Stack, lane *shippedSLOLane) incident.Incident {
	t.Helper()
	var matched incident.Incident
	shipped.Await(t, "one durable incident for the three burn tiers", 25*time.Second, func() bool {
		var page struct{ Items []incident.Incident }
		lane.call(t, stack, http.MethodGet, "/v1/incidents", http.StatusOK, nil, &page)
		for _, item := range page.Items {
			if item.Target == sloReceiptService && item.SignalCount >= 3 {
				lane.call(t, stack, http.MethodGet, "/v1/incidents/"+item.ID, http.StatusOK, nil, &matched)
				return len(matched.Signals) >= 3
			}
		}
		return false
	})
	var tiers []string
	for _, signal := range matched.Signals {
		if signal.Kind != "slo.burn_rate" || signal.Attributes["slo.name"] != lane.name ||
			signal.Attributes["slo.service"] != sloReceiptService || signal.Attributes["slo.team"] != lane.team {
			t.Fatal("the business-impact signal lost its exact objective and team", signal)
		}
		tiers = append(tiers, signal.Attributes["slo.window"])
	}
	sort.Strings(tiers)
	if matched.TenantID != lane.tenant || matched.SignalCount != 3 || strings.Join(tiers, ",") != "fast,medium,slow" {
		t.Fatal("the original burn episode did not latch exactly once at each tier", matched.ID, tiers)
	}
	return matched
}

func assertShippedSLOIsolation(t *testing.T, stack *shipped.Stack, lane *shippedSLOLane, foreignID string) {
	t.Helper()
	lane.call(t, stack, http.MethodGet, "/v1/incidents/"+foreignID, http.StatusNotFound, nil, nil)
	var page struct{ Items []incident.Incident }
	lane.call(t, stack, http.MethodGet, "/v1/incidents", http.StatusOK, nil, &page)
	for _, candidate := range page.Items {
		if candidate.Target == sloReceiptService {
			t.Fatal("the healthy sibling acquired an SLO incident from another source")
		}
	}
}
