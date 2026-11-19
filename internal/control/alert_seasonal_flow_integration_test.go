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
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

const seasonalFlowExactCurrent = "36893488147419103228"

// The evaluator, incident, receipt and two tenant source authority paths are
// real; the historical flow records are a controlled replay in Explorer memory.
func TestSeasonalSavedFlowCommitsExactCitedReceiptAndKeepsTenant(t *testing.T) {
	provePairedSeasonalFlow(t, "", 6)
}

func TestSavedFlowCadencesKeepCompleteExactEvidenceInEachTenant(t *testing.T) {
	for _, profile := range []struct {
		cadence  anomaly.SeasonalCadence
		training int
	}{
		{anomaly.SeasonalDaily, 42},
		{anomaly.SeasonalWeeklyEarly, 6},
	} {
		t.Run(string(profile.cadence), func(t *testing.T) {
			provePairedSeasonalFlow(t, profile.cadence, profile.training)
		})
	}
}

func provePairedSeasonalFlow(t *testing.T, cadence anomaly.SeasonalCadence, trained int) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	flowRows := flowstore.NewMemory()
	metrics := tsdb.NewMemory()
	queries := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(metrics).WithFlowStore(flowRows).WithFlowQueryViews(queries).WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(f.pool, 0, audit.TenantRecord)).WithFairness(gate)
	seedInterfaceRoleMCPConsent(f)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	at := time.Now().UTC()
	input := alert.SeasonalBaselineInput{Timezone: "UTC", MinimumChange: 1, Cadence: cadence}
	if at.Minute() >= 30 {
		input.Timezone = "Asia/Kolkata" // keep isolated replay away from a clock rollover
	}
	model, err := input.Model()
	if err != nil {
		t.Fatal(err)
	}
	observed, end := model.LatestCompletedSlot(at)
	var views [2]flow.SavedQueryView
	var rules [2]alert.Rule
	for i, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		view := seedSeasonalFlowView(ctx, t, queries, tenant, f.users[tenant], end)
		views[i] = view
		seedSeasonalFlowRows(t, flowRows, tenant, model, observed, end, i == 0)
		rules[i] = createSeasonalFlowFixture(t, socket, f.tokens[tenant], view, input, http.StatusCreated)
	}
	createSeasonalFlowFixture(t, socket, f.tokens[f.tenants[0]], views[1], input, http.StatusNotFound)

	for i, tenant := range f.tenants {
		evaluator, ok := BuildAlertEvaluator(f.pool, metrics, alert.ChannelDeps{}, time.Minute, tenancy.ID(tenant), nil, f.server.log, AlertTagDependencies{Gate: gate, Queries: f.server, IncidentWindow: time.Minute})
		if !ok {
			t.Fatal("production alert evaluation is unavailable")
		}
		for range 2 {
			if err := evaluator.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		active := evaluator.Engine().Active()
		if i == 0 {
			if len(active) != 1 || active[0].IncidentID == "" || !active[0].ValueWithheld {
				t.Fatal("owned replay did not publish a cited active incident")
			}
			checkSeasonalFlowIncident(f, tenant, rules[i].ID, active[0])
		} else if len(active) != 0 {
			t.Fatal("normal sibling borrowed the other tenant's change")
		}
		owned := getSeasonalFlowReceipts(t, socket, f.tokens[tenant], rules[i].ID)
		if len(owned.Items) != 1 {
			t.Fatal("the completed window produced duplicate or missing receipts")
		}
		evidence := owned.Items[0].Expectation.Seasonal
		if evidence == nil || evidence.Exact == nil || evidence.Calendar.Cadence != cadence ||
			evidence.TrainingWindow.Samples != trained || !evidence.ObservedAt.Equal(observed) || evidence.Calendar.Provisional {
			t.Fatalf("wrong owned seasonal training population for %s: %+v", cadence, evidence)
		}
		if i == 0 {
			assertSeasonalExactFlow(t, owned, observed, active[0].IncidentID)
			if cadence == "" {
				exactSeasonalFlowClients(t, f, socket, rules[i].ID, observed, active[0].IncidentID)
			}
		}
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, "/v1/alerts/"+rules[1-i].ID+"/evaluations", nil, http.StatusNotFound)
	}
	checkSeasonalFlowRestrictedCredential(t, f, socket, rules[0].ID)
	checkSeasonalFlowViewSupersession(t, f, socket, queries, views[0], rules[0])
}

func grantSeasonalFlowFixture(f *roleExplanationAPIFixture, tenant string) {
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		for _, permission := range []string{permAIQuery, permFlowRead, permAlertRead, permAlertWrite, "incident.read"} {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
				return err
			}
		}
		return nil
	})
}

func seedSeasonalFlowView(ctx context.Context, t *testing.T, queries *flow.PostgresQueryViewStore, tenant, user string, end time.Time) flow.SavedQueryView {
	t.Helper()
	view, err := queries.SaveQueryView(ctx, tenant, user, flow.SaveQueryView{Definition: flow.QueryViewDefinition{
		Name: "Owned protocol volume", Visibility: "private", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 600},
		Plan: flow.QueryPlan{From: end.Add(-10 * time.Minute), To: end, View: "table", GroupBy: []string{"protocol"},
			Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func seedSeasonalFlowRows(t *testing.T, rows *flowstore.Memory, tenant string, model anomaly.WeeklySeasonalModel, observed, end time.Time, change bool) {
	t.Helper()
	periods := append(model.ComparableCompleteEnds(observed), end)
	population := make([]flowstore.Row, 0, 2*len(periods))
	for _, period := range periods {
		var octets uint64 = math.MaxUint64 - 2
		if change && period.Equal(end) {
			octets++
		}
		for i := range 2 {
			clock := period.Add(-time.Duration(30+i) * time.Second)
			population = append(population, flowstore.Row{TenantID: tenant, AgentID: "seeded-flow", Exporter: "192.0.2.10", Protocol: "ipfix", TS: clock,
				StartTS: clock.Add(-time.Second), SrcAddr: "192.0.2.1", DstAddr: "198.51.100.1", Transport: "tcp", Sampling: 1,
				Bytes: octets, BytesScaled: octets, Packets: 1, PacketsScaled: 1})
		}
	}
	if err := rows.Insert(t.Context(), population); err != nil {
		t.Fatal(err)
	}
}

func createSeasonalFlowFixture(t *testing.T, socket *httptest.Server, token string, view flow.SavedQueryView, input alert.SeasonalBaselineInput, want int) alert.Rule {
	t.Helper()
	input.Flow = &alert.SeasonalFlowInput{ViewID: view.ID, ViewVersion: view.Version, Measure: "bytes:total"}
	body := map[string]any{"name": "Seasonal protocol volume", "seasonal_source": input}
	raw := callSeasonalAPI(t, socket, token, http.MethodPost, "/v1/alerts", body, want)
	var rule alert.Rule
	if want == http.StatusCreated && (json.Unmarshal(raw, &rule) != nil || !rule.HasSeasonalSource || !rule.Enabled || rule.Metric != alert.SeasonalFlowMetric) {
		t.Fatal("the complete selected flow source and rule did not commit together")
	}
	return rule
}

func getSeasonalFlowReceipts(t *testing.T, socket *httptest.Server, token, ruleID string) alert.EvaluationsResult {
	t.Helper()
	raw := callSeasonalAPI(t, socket, token, http.MethodGet, "/v1/alerts/"+ruleID+"/evaluations", nil, http.StatusOK)
	var result alert.EvaluationsResult
	if json.Unmarshal(raw, &result) != nil || bytes.Contains(raw, []byte("seasonal_flow_scope")) || bytes.Contains(raw, []byte("source_generation")) {
		t.Fatal("the public receipt contained private source authority")
	}
	return result
}

func assertSeasonalExactFlow(t *testing.T, result alert.EvaluationsResult, at time.Time, incidentID string) {
	t.Helper()
	if len(result.Items) != 1 {
		t.Fatal("missing or duplicate flow transition")
	}
	item := result.Items[0]
	evidence := item.Expectation.Seasonal
	if item.State != alert.EvaluationFiring || item.ObservedValue != nil || evidence == nil || evidence.Exact == nil ||
		evidence.Exact.Current != seasonalFlowExactCurrent || evidence.Exact.Median != "36893488147419103226" ||
		evidence.Exact.Lower != "36893488147419103225" || evidence.Exact.Upper != "36893488147419103227" ||
		evidence.IncidentID != incidentID || !evidence.ObservedAt.Equal(at) || len(evidence.Citations) != 3 {
		t.Fatal("the exact owned change, window or incident was lost")
	}
}

func checkSeasonalFlowIncident(f *roleExplanationAPIFixture, tenant, ruleID string, active alert.ActiveAlert) {
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		var receipt, evidence string
		if err := sc.Q.QueryRow(ctx, `SELECT count(*),max(attributes->>'probectl.alert.seasonal.receipt_fingerprint'),max(attributes->>'probectl.alert.seasonal.evidence')
 FROM incident_signals WHERE tenant_id=$1 AND attributes->>'rule_id'=$2`, tenant, ruleID).Scan(&count, &receipt, &evidence); err != nil {
			return err
		}
		if count != 1 || receipt != active.EvaluationFingerprint || bytes.Contains([]byte(evidence), []byte(seasonalFlowExactCurrent)) {
			f.t.Fatal("the incident lacked its exact source receipt or carried restricted values")
		}
		return nil
	})
}

func exactSeasonalFlowClients(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, ruleID string, at time.Time, incidentID string) {
	t.Helper()
	tenant := f.tenants[0]
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	got, err := client.ListAlertEvaluations(t.Context(), sdk.ListAlertEvaluationsRequest{Id: ruleID})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got)
	if err != nil || !bytes.Contains(raw, []byte(seasonalFlowExactCurrent)) {
		t.Fatal("generated SDK lost the exact saved-flow value", err)
	}
	ca := filepath.Join(t.TempDir(), "seasonal-flow-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
	}
	if code := cli.RunWithStdin([]string{"--json", "alert", "evaluations", ruleID}, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 || !bytes.Contains(stdout.Bytes(), []byte(seasonalFlowExactCurrent)) {
		t.Fatal("verified CLI lost the exact saved-flow receipt", code, stderr.String())
	}
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		var native alert.EvaluationsResult
		args := map[string]any{"rule_id": ruleID}
		interfaceRoleNativeTLSCaller(t, f, wire)(tenant, "alert_evaluations", args, &native, true)
		assertSeasonalExactFlow(t, native, at, incidentID)
		openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire).call(t, wire, "alert_evaluations", args, &native, true)
		assertSeasonalExactFlow(t, native, at, incidentID)
	}
}

func checkSeasonalFlowRestrictedCredential(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, ruleID string) {
	t.Helper()
	tenant := f.tenants[0]
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(f.pool).CreateWithLifetime(t.Context(), tenant, f.users[tenant], "alert receipt read only",
		crypto.Hash([]byte(token)), time.Now().Add(time.Hour), []string{permAlertRead, permAIQuery}); err != nil {
		t.Fatal(err)
	}
	got := getSeasonalFlowReceipts(t, socket, token, ruleID)
	if len(got.Items) != 1 || got.Items[0].State != alert.EvaluationFiring || got.Items[0].Expectation.Seasonal != nil || got.Items[0].ObservedValue != nil {
		t.Fatal("a narrowed credential widened to the owner's original flow access")
	}
}

func checkSeasonalFlowViewSupersession(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, queries *flow.PostgresQueryViewStore, view flow.SavedQueryView, rule alert.Rule) {
	t.Helper()
	tenant := f.tenants[0]
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	definition := view.Definition
	definition.Description = "A new saved revision"
	if _, err := queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{ID: view.ID, Version: view.Version, Definition: definition}); err != nil {
		t.Fatal(err)
	}
	var state alert.SeasonalSourceState
	raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, "/v1/alerts/rules/"+rule.ID+"/seasonal-source", nil, http.StatusOK)
	if json.Unmarshal(raw, &state) != nil || !state.StaleRevision || state.Source == nil || state.Source.Flow == nil || state.Source.Flow.ViewVersion != view.Version {
		t.Fatal("the superseded owner could not see its required configuration update")
	}
	got := getSeasonalFlowReceipts(t, socket, f.tokens[tenant], rule.ID)
	if len(got.Items) != 1 || got.Items[0].State != alert.EvaluationFiring || got.Items[0].Expectation.Seasonal != nil || got.Items[0].ObservedValue != nil {
		t.Fatal("the superseded view still supplied its restricted original values")
	}
}

func TestSeasonalFlowNativeCreationKeepsCurrentViewAndTenant(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFlowQueryViews(views)
	seedInterfaceRoleMCPConsent(f)
	var selections [2]flow.SavedQueryView
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		selections[lane] = seedSeasonalFlowView(ctx, t, views, tenant, f.users[tenant], time.Now().UTC().Truncate(time.Hour))
	}
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	mcpServer := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	const modern, legacy = "2026-07-28", "2025-11-25"
	callHTTP := interfaceRoleNativeTLSCaller(t, f, modern)
	for lane, tenant := range f.tenants {
		own := selections[lane]
		other := selections[1-lane]
		var owned alert.SeasonalSourceState
		callHTTP(tenant, "alert_seasonal_flow_create", seasonalNativeCreateArgs(other, "HTTPS"), nil, false)
		callHTTP(tenant, "alert_seasonal_flow_create", seasonalNativeCreateArgs(own, "HTTPS"), &owned, true)
		assertSeasonalNativeFlowState(t, owned, own)
		stream := openInterfaceRoleStdio(t, mcpServer, authenticator, f.tokens[tenant], legacy)
		stream.call(t, legacy, "alert_seasonal_flow_create", seasonalNativeCreateArgs(other, "stdio"), nil, false)
		stream.call(t, legacy, "alert_seasonal_flow_create", seasonalNativeCreateArgs(own, "stdio"), &owned, true)
		assertSeasonalNativeFlowState(t, owned, own)
	}
}

func seasonalNativeCreateArgs(view flow.SavedQueryView, transport string) map[string]any {
	return map[string]any{"name": "Owned protocol seasonality via " + transport, "seasonal_source": alert.SeasonalBaselineInput{
		Cadence: anomaly.SeasonalDaily, Timezone: "UTC", MinimumChange: 1, Flow: &alert.SeasonalFlowInput{ViewID: view.ID, ViewVersion: view.Version, Measure: "bytes:total"},
	}}
}

func assertSeasonalNativeFlowState(t *testing.T, state alert.SeasonalSourceState, view flow.SavedQueryView) {
	t.Helper()
	if state.RuleID == "" || !state.Enabled || !state.Configured || state.Source == nil || state.Source.Flow == nil ||
		state.Source.Cadence != anomaly.SeasonalDaily || state.Source.Flow.ViewID != view.ID || state.Source.Flow.ViewVersion != view.Version || state.Source.Flow.Measure != "bytes:total" {
		t.Fatal("native create lost the current owned flow revision")
	}
}
