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
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestScheduledDDoSUsesAdjacentOwnedWindowsAndSuppressesOneBurst(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	metrics := tsdb.NewMemory()
	f.server.WithTSDB(metrics).WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(gate)
	seedInterfaceRoleMCPConsent(f)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)

	now := time.Now()
	last, err := anomaly.FlowFieldCompletedWindows(now, anomaly.FlowFieldPreviousWeek, 300)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := anomaly.FlowFieldCompletedWindows(now.Add(-5*time.Minute), anomaly.FlowFieldPreviousWeek, 300)
	if err != nil {
		t.Fatal(err)
	}

	var rules [2]alert.Rule
	var selections [2]flow.SavedQueryView
	for i, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition("Owned detector input")
		definition.Time.LookbackSeconds = 300
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{"203.0.113.15"}},
		}}
		view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		selections[i] = view
		seedDDoSAssessmentRows(t, rows, tenant, previous, i == 0)
		seedDDoSAssessmentRows(t, rows, tenant, last, true)
		input := flow.DDoSAssessmentInput{Version: view.Version, Prefix: "192.0.2.0/24", Direction: "ingress",
			PeriodSeconds: 300, BytesFloor: "10000000000000000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
			VectorShareBasisPoints: 6000, MinObservedRecords: 1, MinObservedAddresses: 2}
		source := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version,
			Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/alerts",
			map[string]any{"name": "Sustained traffic pressure", "query_source": source}, http.StatusCreated)
		if err := json.Unmarshal(raw, &rules[i]); err != nil || rules[i].ID == "" {
			t.Fatal("failed to bind the owned scheduled detector", err)
		}
	}
	observed := map[string]int{}
	observer := func(_ context.Context, item *incident.Incident, _ bool) { observed[item.TenantID]++ }
	for _, tenant := range f.tenants {
		for range 2 {
			evaluator, ok := BuildAlertEvaluator(f.pool, metrics, alert.ChannelDeps{}, time.Minute, tenancy.ID(tenant), nil, f.server.log,
				AlertTagDependencies{Gate: gate, Queries: f.server, IncidentWindow: time.Minute, IncidentObserver: observer})
			if !ok {
				t.Fatal("the scheduled traffic detector became unavailable")
			}
			if err := evaluator.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
	}
	owned, sibling := f.tenants[0], f.tenants[1]
	if observed[owned] != 1 || observed[sibling] != 0 {
		t.Fatal("retries duplicated the episode or the single sibling burst fired", observed)
	}
	var fingerprint string
	for i, tenant := range f.tenants {
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, "/v1/alerts/rules/"+rules[i].ID+"/query-source", nil, http.StatusOK)
		var state alert.QuerySourceState
		if err := json.Unmarshal(raw, &state); err != nil || state.NextAt == nil || !state.NextAt.Equal(last.After.End.Add(5*time.Minute)) {
			t.Fatal("the tenant schedule did not reach its exact next clock", err)
		}
		for _, item := range getSeasonalFlowReceipts(t, socket, f.tokens[tenant], rules[i].ID).Items {
			if item.Reason != "Sustained flow traffic pressure" {
				continue
			}
			if i != 0 || fingerprint != "" {
				t.Fatal("duplicate or sibling detector receipt")
			}
			fingerprint = item.Fingerprint
		}
	}
	if !alert.ValidFieldDigest(fingerprint) {
		t.Fatal("the incident has no exact detector evidence handle")
	}
	path := "/v1/alerts/rules/" + rules[0].ID + "/ddos-receipt?fingerprint=" + fingerprint
	decode := func(raw []byte) {
		t.Helper()
		var proof alert.DDoSEvaluationEvidence
		if err := json.Unmarshal(raw, &proof); err != nil || !reportRequirementUUID(proof.IncidentID) || !alert.ValidFieldDigest(proof.EpisodeID) ||
			bytes.Contains(raw, []byte("source_generation")) || bytes.Contains(raw, []byte("read_grants")) {
			t.Fatal("the authorized assessment lost its incident link or exposed private authorization metadata", err)
		}
		assertDDoSAssessment(t, encodeScheduledDDoSProof(t, proof.Previous), selections[0].ID, previous)
		assertDDoSAssessment(t, encodeScheduledDDoSProof(t, proof.Current), selections[0].ID, last)
	}
	decode(callSeasonalAPI(t, socket, f.tokens[owned], http.MethodGet, path, nil, http.StatusOK))
	callSeasonalAPI(t, socket, f.tokens[sibling], http.MethodGet, path, nil, http.StatusNotFound)
	assertScheduledDDoSClients(t, f, socket, rules[0].ID, fingerprint, decode)
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(f.pool).CreateWithLifetime(t.Context(), owned, f.users[owned], "traffic receipt narrowed scope",
		crypto.Hash([]byte(token)), time.Now().Add(time.Hour), []string{permAlertRead, permAIQuery}); err != nil {
		t.Fatal(err)
	}
	callSeasonalAPI(t, socket, token, http.MethodGet, path, nil, http.StatusForbidden)
	changed := selections[0].Definition
	changed.Description = "Replaced saved source"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owned))
	if _, err := views.SaveQueryView(ctx, owned, f.users[owned], flow.SaveQueryView{ID: selections[0].ID, Version: selections[0].Version, Definition: changed}); err != nil {
		t.Fatal(err)
	}
	refused := callSeasonalAPI(t, socket, f.tokens[owned], http.MethodGet, path, nil, http.StatusConflict)
	if bytes.Contains(refused, []byte(ddosFixtureAmount)) {
		t.Fatal("the superseded source yielded original traffic measurements")
	}
}

func encodeScheduledDDoSProof(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertScheduledDDoSClients(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, ruleID, fingerprint string, decode func([]byte)) {
	t.Helper()
	owner := f.tenants[0]
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[owner]))
	result, err := client.GetAlertDDoSReceipt(t.Context(), sdk.GetAlertDDoSReceiptRequest{Id: ruleID, Fingerprint: &fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	decode(encodeScheduledDDoSProof(t, result))
	ca := filepath.Join(t.TempDir(), "traffic-assessment-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[owner], "PROBECTL_CA_FILE": ca}[key]
	}
	if code := cli.RunWithStdin([]string{"--json", "alert", "ddos-receipt", ruleID, "--query", "fingerprint=" + fingerprint}, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
		t.Fatal("CLI traffic receipt failed", code, stderr.String())
	}
	decode(stdout.Bytes())
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil,
		f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	args := map[string]any{"rule_id": ruleID, "fingerprint": fingerprint}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		var native alert.DDoSEvaluationEvidence
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		call(owner, "alert_ddos_receipt_get", args, &native, true)
		decode(encodeScheduledDDoSProof(t, native))
		call(f.tenants[1], "alert_ddos_receipt_get", args, nil, false)
		openInterfaceRoleStdio(t, server, authenticator, f.tokens[owner], wire).call(t, wire, "alert_ddos_receipt_get", args, &native, true)
		decode(encodeScheduledDDoSProof(t, native))
	}
}
