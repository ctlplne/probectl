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

	"github.com/ctlplne/probectl/internal/ai/mcp"
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
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

const scheduledFieldAmount = "9007199254740993"

func TestScheduledFieldChangeCommitsOneCitedTenantEpisode(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	queries := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	metrics := tsdb.NewMemory()
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(metrics).WithFlowStore(rows).WithFlowQueryViews(queries).WithFairness(gate)
	seedInterfaceRoleMCPConsent(f)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	windows, err := anomaly.FlowFieldCompletedWindows(time.Now(), anomaly.FlowFieldCompleteWeek, 0)
	if err != nil {
		t.Fatal(err)
	}
	var views [2]flow.SavedQueryView
	var rules [2]alert.Rule
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		view, err := queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: fieldComparisonViewDefinition("Owned scheduled port ranks")})
		if err != nil {
			t.Fatal(err)
		}
		views[lane] = view
		seedScheduledFieldRows(t, rows, tenant, windows, lane == 0)
		input := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version,
			Condition: alert.QueryCondition{Mode: alert.FieldChangeCondition, Field: &flow.FieldComparisonInput{
				Version: view.Version, Mode: "rank", Measure: "bytes:total", Cadence: "complete_week", TopKeys: 2, MinimumChange: "50"}}}
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/alerts", map[string]any{"name": "New port", "query_source": input}, http.StatusCreated)
		if err := json.Unmarshal(raw, &rules[lane]); err != nil || rules[lane].ID == "" || rules[lane].Metric != alert.QueryMetric || !rules[lane].Enabled {
			t.Fatal("the field schedule did not bind to the active saved-query rule", err)
		}
	}
	observed := map[string]int{}
	observer := func(_ context.Context, event *incident.Incident, _ bool) { observed[event.TenantID]++ }
	sink := func(_ context.Context, sent alert.Alert) {
		t.Errorf("field comparison reached the generic incident sink: %s", sent.State)
	}
	for _, tenant := range f.tenants {
		for range 2 {
			evaluator, ok := BuildAlertEvaluator(f.pool, metrics, alert.ChannelDeps{}, time.Minute, tenancy.ID(tenant), sink, f.server.log,
				AlertTagDependencies{Gate: gate, Queries: f.server, IncidentWindow: time.Minute, IncidentObserver: observer})
			if !ok {
				t.Fatal("field scheduler is unavailable")
			}
			for range 2 {
				if err := evaluator.Tick(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	red, blue := f.tenants[0], f.tenants[1]
	if observed[red] != 1 || observed[blue] != 0 {
		t.Fatal("a retry emitted an extra episode or normal sibling data emitted one", observed)
	}
	fingerprint := scheduledFieldFingerprint(t, f, rules, windows.After.End)
	path := "/v1/alerts/rules/" + rules[0].ID + "/field-receipt?fingerprint=" + fingerprint
	decode := func(raw []byte) {
		t.Helper()
		var got alert.FieldEvaluationEvidence
		if err := json.Unmarshal(raw, &got); err != nil || bytes.Contains(raw, []byte("source_generation")) || bytes.Contains(raw, []byte("read_grants")) {
			t.Fatal("field receipt could not be read without private authorization metadata", err)
		}
		assertScheduledFieldEvidence(t, got, views[0].ID, windows)
	}
	decode(callSeasonalAPI(t, socket, f.tokens[red], http.MethodGet, path, nil, http.StatusOK))
	callSeasonalAPI(t, socket, f.tokens[blue], http.MethodGet, path, nil, http.StatusNotFound)
	assertScheduledFieldClients(t, f, socket, rules[0].ID, fingerprint, views[0].ID, windows, decode)
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(f.pool).CreateWithLifetime(t.Context(), red, f.users[red], "field receipt narrowed scope",
		crypto.Hash([]byte(token)), time.Now().Add(time.Hour), []string{permAlertRead, permAIQuery}); err != nil {
		t.Fatal(err)
	}
	callSeasonalAPI(t, socket, token, http.MethodGet, path, nil, http.StatusForbidden)
	changed := views[0].Definition
	changed.Description = "Renewed source version"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(red))
	if _, err := queries.SaveQueryView(ctx, red, f.users[red], flow.SaveQueryView{ID: views[0].ID, Version: views[0].Version, Definition: changed}); err != nil {
		t.Fatal(err)
	}
	refused := callSeasonalAPI(t, socket, f.tokens[red], http.MethodGet, path, nil, http.StatusConflict)
	if bytes.Contains(refused, []byte(scheduledFieldAmount)) {
		t.Fatal("the superseded history escaped its current source fence")
	}
}

func seedScheduledFieldRows(t *testing.T, rows flowstore.Store, tenant string, windows anomaly.FlowFieldComparisonClocks, changed bool) {
	t.Helper()
	var batch []flowstore.Row
	for period, window := range []anomaly.TrainingWindow{windows.Before, windows.After} {
		at := window.End.Add(-time.Minute)
		items := []struct {
			port   uint16
			amount uint64
		}{{443, 9007199254740995}, {53, 10}}
		if changed && period == 1 {
			items = append(items, struct {
				port   uint16
				amount uint64
			}{853, 9007199254740993})
		}
		for _, item := range items {
			batch = append(batch, flowstore.Row{TenantID: tenant, AgentID: "field-alert-replay", Exporter: "192.0.2.10", Protocol: "ipfix", TS: at,
				StartTS: at.Add(-time.Second), SrcAddr: "192.0.2.41", DstAddr: "198.51.100.42", DstPort: item.port, Transport: "tcp",
				Sampling: 1, Bytes: item.amount, BytesScaled: item.amount, Packets: 1, PacketsScaled: 1})
		}
	}
	if err := rows.Insert(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
}

func scheduledFieldFingerprint(t *testing.T, f *roleExplanationAPIFixture, rules [2]alert.Rule, end time.Time) string {
	t.Helper()
	var fingerprint string
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			var cited, public string
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),COALESCE(max(attributes->>'probectl.alert.field.receipt_fingerprint'),''),COALESCE(max(attributes::text),'')
 FROM incident_signals WHERE tenant_id=$1 AND attributes->>'rule_id'=$2`, tenant, rules[lane].ID).Scan(&count, &cited, &public); err != nil {
				return err
			}
			if lane == 0 {
				if count != 1 || !alert.ValidFieldDigest(cited) || bytes.Contains([]byte(public), []byte(scheduledFieldAmount)) || bytes.Contains([]byte(public), []byte("192.0.2.41")) {
					t.Fatal("incident publication duplicated, lost citation, or exposed exact sources")
				}
				fingerprint = cited
			} else if count != 0 {
				t.Fatal("the stable sibling got an incident")
			}
			var nextAt time.Time
			if err := sc.Q.QueryRow(ctx, `SELECT query_next_eval_at FROM alert_rules WHERE tenant_id=$1 AND id=$2`, tenant, rules[lane].ID).Scan(&nextAt); err != nil {
				return err
			}
			if !nextAt.Equal(end.AddDate(0, 0, 1)) {
				t.Fatal("the rule did not advance from its actual completed source window", nextAt)
			}
			return nil
		})
	}
	return fingerprint
}

func assertScheduledFieldEvidence(t *testing.T, got alert.FieldEvaluationEvidence, viewID string, windows anomaly.FlowFieldComparisonClocks) {
	t.Helper()
	comparison := got.Comparison
	if comparison.ViewID != viewID || !comparison.Before.From.Equal(windows.Before.Start) || !comparison.After.To.Equal(windows.After.End) || len(comparison.Changes) != 1 || len(got.Signals) != 1 {
		t.Fatal("scheduled receipt omitted its source windows, view or signal")
	}
	if windows.History.Samples > 0 && (comparison.History == nil || comparison.History.Hours != windows.History.Samples ||
		!comparison.History.From.Equal(windows.History.Start) || !comparison.History.To.Equal(windows.History.End)) {
		t.Fatal("scheduled receipt lost its original historical window population")
	}
	change, signal := comparison.Changes[0], got.Signals[0]
	if change.Kind != "entered_top_set" || change.Group["dst_port"] != "853" || change.Before != nil || change.After == nil ||
		change.After.Value != scheduledFieldAmount || change.After.Citation == "" || signal.ChangeKey != change.Key || signal.EpisodeID == "" || signal.IncidentID == "" {
		t.Fatal("scheduled receipt changed the exact paired evidence or incident link", change, signal)
	}
}

func assertScheduledFieldClients(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, ruleID, fingerprint, viewID string, windows anomaly.FlowFieldComparisonClocks, decode func([]byte)) {
	t.Helper()
	tenant := f.tenants[0]
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	result, err := client.GetAlertFieldReceipt(t.Context(), sdk.GetAlertFieldReceiptRequest{Id: ruleID, Fingerprint: &fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	decode(raw)
	ca := filepath.Join(t.TempDir(), "scheduled-field-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
	}
	if code := cli.RunWithStdin([]string{"--json", "alert", "field-receipt", ruleID, "--query", "fingerprint=" + fingerprint}, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
		t.Fatal("CLI field receipt failed", code, stderr.String())
	}
	decode(stdout.Bytes())
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	args := map[string]any{"rule_id": ruleID, "fingerprint": fingerprint}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		var native mcp.NativeAlertFieldReceipt
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		call(tenant, "alert_field_receipt_get", args, &native, true)
		comparison := fieldComparisonFromNative(t, native.Comparison)
		assertScheduledFieldEvidence(t, alert.FieldEvaluationEvidence{Comparison: comparison, Signals: native.Signals}, viewID, windows)
		if comparison.Changes[0].Group["src_addr"] == "192.0.2.41" {
			t.Fatal("native field receipt bypassed source redaction")
		}
		call(f.tenants[1], "alert_field_receipt_get", args, nil, false)
		openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire).call(t, wire, "alert_field_receipt_get", args, &native, true)
		assertScheduledFieldEvidence(t, alert.FieldEvaluationEvidence{Comparison: fieldComparisonFromNative(t, native.Comparison), Signals: native.Signals}, viewID, windows)
	}
}
