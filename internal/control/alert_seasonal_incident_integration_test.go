// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestSeasonalMetricRuleCreatesOneCitedTenantIncident(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	memory := tsdb.NewMemory()
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(memory).WithFairness(gate)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "seasonal-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	input := alert.SeasonalBaselineInput{Timezone: "UTC", MinimumChange: 5}
	model, err := input.Model()
	if err != nil {
		t.Fatal(err)
	}
	const metric = "known_interface_receive_rate"
	directions := [2]alert.SeasonalDirection{alert.SeasonalAbove, alert.SeasonalBelow}
	var paths [2]string
	var ruleIDs [2]string
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAlertRead, permAlertWrite, "incident.read"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		var rule alert.Rule
		if err := json.Unmarshal(callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/alerts", map[string]any{
			"name": "Weekly interface rate", "metric": metric, "type": "baseline", "window": 20, "sensitivity": 3,
		}, http.StatusCreated), &rule); err != nil || rule.ID == "" || rule.HasSeasonalSource {
			t.Fatal("ordinary baseline was not created with its prior default", err)
		}
		ruleIDs[lane] = rule.ID
		paths[lane] = "/v1/alerts/rules/" + rule.ID + "/seasonal-source"
		var selected alertSeasonalState
		owned := input
		owned.Direction = directions[lane]
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, paths[lane], owned, http.StatusOK)
		if err := json.Unmarshal(raw, &selected); err != nil || !selected.Configured || selected.Source == nil || !selected.Enabled || selected.Source.Direction != directions[lane] ||
			bytes.Contains(raw, []byte("owner_user_id")) || bytes.Contains(raw, []byte("read_grants")) {
			t.Fatal("seasonal selection was not stored or exposed an internal grant", err)
		}
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		state, err := client.GetAlertSeasonalSource(t.Context(), sdk.GetAlertSeasonalSourceRequest{Id: rule.ID})
		if err != nil || state.RuleId != rule.ID || state.Source == nil || state.Source.Timezone != input.Timezone || state.Source.MinimumChange != input.MinimumChange || string(state.Source.Direction) != string(directions[lane]) {
			t.Fatal("generated client lost the tenant's seasonal source", err)
		}
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		if code := cli.RunWithStdin([]string{"--json", "alert", "seasonal-source", rule.ID}, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
			t.Fatal("verified HTTPS seasonal CLI read failed", code, stderr.String())
		}
		var cliState alertSeasonalState
		if err := json.Unmarshal(stdout.Bytes(), &cliState); err != nil || cliState.RuleID != rule.ID || cliState.Source == nil || cliState.Source.MinimumChange != input.MinimumChange || cliState.Source.Direction != directions[lane] {
			t.Fatal("CLI lost the tenant's seasonal source", err)
		}
	}
	for lane, tenant := range f.tenants {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			var payload any
			if method == http.MethodPut {
				payload = input
			}
			callSeasonalAPI(t, socket, f.tokens[tenant], method, paths[1-lane], payload, http.StatusNotFound)
		}
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, "/v1/alerts/"+ruleIDs[1-lane]+"/evaluations", nil, http.StatusNotFound)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	for lane, tenant := range f.tenants {
		point := func(at time.Time, value float64) tsdb.Series {
			return tsdb.Series{Metric: metric, Labels: map[string]string{tsdb.TenantLabel: tenant, "node": "same-port-name"}, TimeMillis: at.UnixMilli(), Value: value}
		}
		var samples []tsdb.Series
		for _, window := range model.ComparableWindows(now) {
			samples = append(samples, point(window.Start, 50+float64(lane)*100))
		}
		samples = append(samples, point(now, []float64{75, 175}[lane]))
		if err := memory.Write(t.Context(), samples); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range f.tenants {
		eval, ok := BuildAlertEvaluator(f.pool, memory, alert.ChannelDeps{}, time.Minute, tenancy.ID(tenant), nil, f.server.log,
			AlertTagDependencies{Gate: gate, Queries: f.server, IncidentWindow: 5 * time.Minute})
		if !ok {
			t.Fatal("production alert build seam is unavailable")
		}
		for range 2 {
			if err := eval.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		active := eval.Engine().Active()
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			var last *string
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),max(attributes->>'probectl.alert.seasonal.evidence')
 FROM incident_signals WHERE tenant_id=$1 AND attributes->>'rule_id'=$2`, tenant, ruleIDs[lane]).Scan(&count, &last); err != nil {
				return err
			}
			if lane == 1 {
				if count != 0 || len(active) != 0 {
					t.Fatal("the below-only sibling fired on its upper-band crossing")
				}
				return nil
			}
			var evidence alert.SeasonalEvaluationEvidence
			if count != 1 || last == nil || len(active) != 1 || active[0].IncidentID == "" || json.Unmarshal([]byte(*last), &evidence) != nil ||
				evidence.Direction != alert.SeasonalAbove || len(evidence.Citations) != 3 || (evidence.Calendar.Lower == nil || *evidence.Calendar.Lower != 45) || (evidence.Calendar.Upper == nil || *evidence.Calendar.Upper != 55) || !evidence.ObservedAt.Equal(now) {
				t.Fatalf("wanted one complete cited incident, count %d", count)
			}
			var ownsSignal bool
			err := sc.Q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2
AND attributes->>'rule_id'=$3)`, tenant, active[0].IncidentID, ruleIDs[lane]).Scan(&ownsSignal)
			if err == nil && !ownsSignal {
				t.Fatal("active alert is linked to an incident without its cited signal")
			}
			return err
		})
		var ledger alert.EvaluationsResult
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, "/v1/alerts/"+ruleIDs[lane]+"/evaluations", nil, http.StatusOK)
		if err := json.Unmarshal(raw, &ledger); err != nil || len(ledger.Items) != 1 || ledger.Items[0].Expectation.Seasonal == nil {
			t.Fatal("the bounded evaluation ledger lost the seasonal evidence", err)
		}
		cited := ledger.Items[0].Expectation.Seasonal
		if cited.Direction != directions[lane] || (lane == 1 && (ledger.Items[0].State != alert.EvaluationNormal || cited.Calendar.Upper == nil || *cited.Calendar.Upper != 155)) {
			t.Fatal("the receipt did not preserve the selected direction and measured band")
		}
		if (lane == 0 && (cited.IncidentID != active[0].IncidentID || len(cited.Citations) != 3)) || (lane == 1 && cited.IncidentID != "") {
			t.Fatal("the stored evaluation does not point to its exact owned incident")
		}
		if lane == 0 {
			replacement := input
			replacement.MinimumChange = 1_000_000
			callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, paths[lane], replacement, http.StatusOK)
			if err := eval.Tick(t.Context()); err != nil || len(eval.Engine().Active()) != 0 {
				t.Fatal("active episode survived a superseding source revision", err)
			}
		}
		var cleared alertSeasonalState
		raw = callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodDelete, paths[lane], nil, http.StatusOK)
		if err := json.Unmarshal(raw, &cleared); err != nil || cleared.Configured || cleared.Enabled {
			t.Fatal("clearing a seasonal source silently enabled the rolling detector", err)
		}
		if err := eval.Tick(t.Context()); err != nil || len(eval.Engine().Active()) != 0 {
			t.Fatal("withdrawn seasonal selection remained active", err)
		}
	}
}

func callSeasonalAPI(t *testing.T, socket *httptest.Server, token, method, path string, payload any, want int) []byte {
	t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(t.Context(), method, socket.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := socket.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || response.StatusCode != want {
		t.Fatalf("%s %s got %d, want %d: %.450s (%v)", method, path, response.StatusCode, want, raw, err)
	}
	return raw
}
