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

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestFieldComparisonReadsExactOwnedTopThreeHundred(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	queries := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithFlowStore(rows).WithFlowQueryViews(queries).WithFairness(gate)
	seedInterfaceRoleMCPConsent(f)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	windows, err := anomaly.FlowFieldCompletedWindows(time.Now(), anomaly.FlowFieldCompleteWeek, 0)
	if err != nil {
		t.Fatal(err)
	}
	var views [2]flow.SavedQueryView
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		view, err := queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: fieldComparisonViewDefinition("Owned protocol distribution")})
		if err != nil {
			t.Fatal(err)
		}
		views[lane] = view
		seedFieldComparisonRows(t, rows, tenant, windows, lane == 0)
	}
	input := flow.FieldComparisonInput{Mode: "rank", Cadence: "complete_week", Measure: "bytes:total", TopKeys: 300,
		Version: views[0].Version, SecondaryThresholds: []flow.FieldSecondaryThreshold{{Measure: "packets:total", Minimum: "1"}, {Measure: "flows:total", Minimum: "1"}}}
	read := func(tenant string, view flow.SavedQueryView, status int) []byte {
		t.Helper()
		return callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/explorer/flow-views/"+view.ID+"/field-comparison", input, status)
	}
	var owned, stable flow.FieldComparison
	red, blue := f.tenants[0], f.tenants[1]
	if err := json.Unmarshal(read(red, views[0], http.StatusOK), &owned); err != nil {
		t.Fatal(err)
	}
	assertFieldComparisonCutoff(t, owned, views[0].ID, windows)
	if err := json.Unmarshal(read(blue, views[1], http.StatusOK), &stable); err != nil || stable.ViewID != views[1].ID || stable.Changes == nil || len(stable.Changes) != 0 {
		t.Fatal("a stable sibling must have a complete comparison with no changes", err)
	}
	read(red, views[1], http.StatusNotFound)
	read(blue, views[0], http.StatusNotFound)
	assertFieldComparisonClients(t, f, socket, views[0], input, windows)

	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(red))
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/explorer/flow-views/"+views[0].ID+"/field-comparison", nil)
	request.Header.Set("Authorization", "Bearer "+f.tokens[red])
	actor := f.server.resolvePrincipal(request)
	admission, err := gate.BeginQuery(ctx, red)
	if err != nil {
		t.Fatal(err)
	}
	defer admission()
	var publish func(context.Context) error
	frozen, err := f.server.readFlowFieldComparison(ctx, actor, fieldComparisonSettings(views[0].ID, input), time.Now(),
		func(_ context.Context, check func(context.Context) error, release func()) error {
			publish = check
			t.Cleanup(release)
			return nil
		})
	if err != nil || publish == nil {
		t.Fatal("could not stage the owned comparison before publication", err)
	}
	assertFieldComparisonCutoff(t, frozen, views[0].ID, windows)

	changed := views[0].Definition
	changed.Description = "Publish next revision"
	if _, err := queries.SaveQueryView(ctx, red, f.users[red], flow.SaveQueryView{ID: views[0].ID, Version: views[0].Version, Definition: changed}); err != nil {
		t.Fatal(err)
	}
	if fault, ok := apierror.As(publish(ctx)); !ok || fault.Kind != apierror.KindConflict {
		t.Fatal("a saved view revision changed between capture and publication without withholding the source")
	}
	refused := read(red, views[0], http.StatusConflict)
	if bytes.Contains(refused, []byte("9007199254740993")) || bytes.Contains(refused, []byte("192.0.2.41")) {
		t.Fatal("a superseded query leaked its previous observations")
	}
}

func fieldComparisonViewDefinition(name string) flow.QueryViewDefinition {
	return flow.QueryViewDefinition{
		Name: name, Visibility: "private", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 604800},
		Plan: flow.QueryPlan{View: "table", GroupBy: []string{"src_addr", "dst_port"}, DataSeries: "raw", RowLimit: 1, PageSize: 1,
			Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"},
				{Measure: "packets", Calculation: "total", Role: "secondary"}, {Measure: "flows", Calculation: "total", Role: "secondary"}}},
	}
}

func seedFieldComparisonRows(t *testing.T, rows flowstore.Store, tenant string, windows anomaly.FlowFieldComparisonClocks, altered bool) {
	t.Helper()
	var population []flowstore.Row
	for period, window := range []anomaly.TrainingWindow{windows.Before, windows.After} {
		at := window.End.Add(-time.Minute)
		for group := range 301 {
			port := 1000 + group
			if altered && period == 1 && group == 299 {
				port = 1853
			}
			amount := 9007199254740993 + uint64(299) - uint64(group)
			population = append(population, flowstore.Row{TenantID: tenant, AgentID: "field-replay", Exporter: "192.0.2.10", Protocol: "ipfix",
				TS: at, StartTS: at.Add(-time.Second), SrcAddr: "192.0.2.41", DstAddr: "198.51.100.42", DstPort: uint16(port), Transport: "tcp",
				Sampling: 1, Bytes: amount, BytesScaled: amount, Packets: 1, PacketsScaled: 1})
		}
	}
	if err := rows.Insert(t.Context(), population); err != nil {
		t.Fatal(err)
	}
}

func assertFieldComparisonCutoff(t *testing.T, got flow.FieldComparison, id string, windows anomaly.FlowFieldComparisonClocks) {
	t.Helper()
	if got.ViewID != id || got.TopKeys != 300 || len(got.Changes) != 2 || got.Before.TotalGroups != 301 || got.After.TotalGroups != 301 ||
		!got.Before.From.Equal(windows.Before.Start) || !got.Before.To.Equal(windows.Before.End) ||
		!got.After.From.Equal(windows.After.Start) || !got.After.To.Equal(windows.After.End) {
		t.Fatal("comparison lost the pinned view, complete windows or original population")
	}
	for _, window := range []flow.FieldComparisonSlice{got.Before, got.After} {
		if window.LastIncluded != "9007199254740993" || window.FirstExcluded != "9007199254740992" {
			t.Fatal("receipt lost the exact original boundary amounts")
		}
	}
	entered, left := got.Changes[0], got.Changes[1]
	if entered.Kind != "entered_top_set" || entered.Group["dst_port"] != "1853" || entered.Before != nil || entered.After == nil ||
		entered.After.Value != "9007199254740993" || entered.After.Rank != 300 || entered.After.Citation == "" || entered.After.Secondary["flows:total"] != "1" ||
		left.Kind != "left_top_set" || left.Group["dst_port"] != "1299" || left.After != nil || left.Before == nil || left.Before.Value != entered.After.Value {
		t.Fatal("membership refused exact observations or invented missing amounts", entered, left)
	}
}

func assertFieldComparisonClients(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, view flow.SavedQueryView, input flow.FieldComparisonInput, windows anomaly.FlowFieldComparisonClocks) {
	t.Helper()
	decode := func(raw []byte) {
		t.Helper()
		var result flow.FieldComparison
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		assertFieldComparisonCutoff(t, result, view.ID, windows)
	}
	tenant := f.tenants[0]
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var body sdk.FlowFieldComparisonInput
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	got, err := client.CompareFlowViewFields(t.Context(), sdk.CompareFlowViewFieldsRequest{Id: view.ID, Body: &body})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	decode(raw)
	ca := filepath.Join(t.TempDir(), "field-flow-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
	}
	if code := cli.RunWithStdin([]string{"--json", "explorer", "field-compare", view.ID, "--body-file", "-"}, getenv, bytes.NewReader(payload), &stdout, &stderr); code != 0 {
		t.Fatal("CLI field comparison failed", code, stderr.String())
	}
	decode(stdout.Bytes())
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	args := map[string]any{"id": view.ID, "comparison": input}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		var native flow.FieldComparison
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		call(tenant, "flow_view_field_compare", args, &native, true)
		assertFieldComparisonCutoff(t, native, view.ID, windows)
		if native.Changes[0].Group["src_addr"] == "192.0.2.41" {
			t.Fatal("native tool let an address escape redaction")
		}
		call(f.tenants[1], "flow_view_field_compare", args, nil, false)
		openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire).call(t, wire, "flow_view_field_compare", args, &native, true)
		assertFieldComparisonCutoff(t, native, view.ID, windows)
	}
}
