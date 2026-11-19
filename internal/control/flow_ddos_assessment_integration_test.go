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
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

const ddosFixtureAmount = "9007199254741000"

func TestDDoSAssessmentUsesOnlyOriginalScopedTenantTraffic(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	queries := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithFlowStore(rows).WithFlowQueryViews(queries).WithFairness(gate)
	seedInterfaceRoleMCPConsent(f)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	windows, err := anomaly.FlowFieldCompletedWindows(time.Now(), anomaly.FlowFieldPreviousWeek, 300)
	if err != nil {
		t.Fatal(err)
	}
	var views [2]flow.SavedQueryView
	for i, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition("Owned five-minute flow evidence")
		definition.Time.LookbackSeconds = 300
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{"203.0.113.15"}},
		}}
		views[i], err = queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		seedDDoSAssessmentRows(t, rows, tenant, windows, i == 0)
	}
	input := flow.DDoSAssessmentInput{Version: views[0].Version, Prefix: "192.0.2.0/24", Direction: "ingress",
		PeriodSeconds: 300, BytesFloor: "10000000000000000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
		VectorShareBasisPoints: 6000, MinObservedRecords: 1, MinObservedAddresses: 2}
	endpoint := func(view flow.SavedQueryView) string {
		return "/v1/explorer/flow-views/" + view.ID + "/ddos-assessment"
	}
	owned, sibling := f.tenants[0], f.tenants[1]
	raw := callSeasonalAPI(t, socket, f.tokens[owned], http.MethodPost, endpoint(views[0]), input, http.StatusOK)
	assertDDoSAssessment(t, raw, views[0].ID, windows)
	raw = callSeasonalAPI(t, socket, f.tokens[sibling], http.MethodPost, endpoint(views[1]), input, http.StatusOK)
	var stable flow.DDoSAssessment
	if err := json.Unmarshal(raw, &stable); err != nil || stable.Detection != nil || stable.After.Packets != "1000" {
		t.Fatal("quiet evidence inherited another tenant's traffic", err)
	}
	callSeasonalAPI(t, socket, f.tokens[owned], http.MethodPost, endpoint(views[1]), input, http.StatusNotFound)
	callSeasonalAPI(t, socket, f.tokens[sibling], http.MethodPost, endpoint(views[0]), input, http.StatusNotFound)
	absent := input
	absent.Prefix = "198.51.100.0/24"
	callSeasonalAPI(t, socket, f.tokens[owned], http.MethodPost, endpoint(views[0]), absent, http.StatusConflict)
	assertDDoSAssessmentClients(t, f, socket, views[0], input, windows)
	verifyDDoSAssessmentCurrentGrants(t, f, socket, queries, gate, views[0], input, endpoint(views[0]))
}

func verifyDDoSAssessmentCurrentGrants(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server,
	queries *flow.PostgresQueryViewStore, gate *fairness.Gate, view flow.SavedQueryView, input flow.DDoSAssessmentInput, endpoint string) {
	t.Helper()
	tenant := f.tenants[0]
	restricted, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(f.pool).CreateWithLifetime(t.Context(), tenant, f.users[tenant], "restricted flow assessment",
		crypto.Hash([]byte(restricted)), time.Now().Add(time.Hour), []string{permAIQuery}); err != nil {
		t.Fatal(err)
	}
	callSeasonalAPI(t, socket, restricted, http.MethodPost, endpoint, input, http.StatusForbidden)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
	actor := f.server.resolvePrincipal(req)
	release, err := gate.BeginQuery(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	settings, err := normalizeDDoSAssessment(view.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	var publish func(context.Context) error
	_, err = f.server.readFlowDDoSAssessment(ctx, actor, settings, time.Now(), func(_ context.Context, check func(context.Context) error, done func()) error {
		publish = check
		t.Cleanup(done)
		return nil
	})
	if err != nil || publish == nil {
		t.Fatal("could not stage the owned assessment for publication", err)
	}
	changed := view.Definition
	changed.Description = "Current source revision"
	if _, err := queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{ID: view.ID, Version: view.Version, Definition: changed}); err != nil {
		t.Fatal(err)
	}
	if fault, ok := apierror.As(publish(ctx)); !ok || fault.Kind != apierror.KindConflict {
		t.Fatal("the changed saved query still authorized the staged assessment")
	}
	refused := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, endpoint, input, http.StatusConflict)
	if bytes.Contains(refused, []byte(ddosFixtureAmount)) {
		t.Fatal("the superseded source exposed an original measurement")
	}
}

func seedDDoSAssessmentRows(t *testing.T, rows flowstore.Store, tenant string, windows anomaly.FlowFieldComparisonClocks, changed bool) {
	t.Helper()
	for i, window := range []anomaly.TrainingWindow{windows.Before, windows.After} {
		at := window.Start.Add(time.Minute)
		row := flowstore.Row{TenantID: tenant, AgentID: "passive-assessment-source", Exporter: "203.0.113.15", Protocol: "ipfix",
			TS: at, StartTS: at.Add(-time.Second), SrcAddr: "198.51.100.42", DstAddr: "192.0.2.41", SrcPort: 42001, DstPort: 443,
			Transport: "tcp", TCPFlags: 16, Sampling: 10, Bytes: 100000, BytesScaled: 1000000, Packets: 100, PacketsScaled: 1000}
		if changed && i == 1 {
			row.TCPFlags = 2
			row.Bytes, row.BytesScaled, row.Packets, row.PacketsScaled = 900719925474100, 9007199254741000, 400, 4000
		}
		outsidePrefix := row
		outsidePrefix.DstAddr = "192.0.3.41"
		outsidePrefix.Bytes, outsidePrefix.BytesScaled = 1200000000000000, 12000000000000000
		outsideView := row
		outsideView.Exporter = "203.0.113.16"
		outsideView.Bytes, outsideView.BytesScaled = 1200000000000000, 12000000000000000
		if err := rows.Insert(t.Context(), []flowstore.Row{row, outsidePrefix, outsideView}); err != nil {
			t.Fatal(err)
		}
	}
}

func assertDDoSAssessment(t *testing.T, raw []byte, viewID string, windows anomaly.FlowFieldComparisonClocks) {
	t.Helper()
	var got flow.DDoSAssessment
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	finding := got.Detection
	if got.ViewID != viewID || got.Direction != "ingress" || !got.Before.From.Equal(windows.Before.Start) ||
		!got.After.To.Equal(windows.After.End) || !got.After.Sampled || got.After.ObservedRecords != 1 || got.After.ObservedAddresses != 1 ||
		got.After.Bytes != ddosFixtureAmount || got.After.Packets != "4000" || got.Before.Packets != "1000" ||
		finding == nil || finding.Class != anomaly.DDoSSYN || finding.ContributingPackets != "4000" || finding.Confidence != "corroborated" ||
		finding.CurrentCitation != got.After.Citation || finding.ReferenceCitation != got.Before.Citation {
		t.Fatal("assessment lost its original scoped counter, vector or source clock", got.After, finding)
	}
}

func assertDDoSAssessmentClients(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, view flow.SavedQueryView, input flow.DDoSAssessmentInput, windows anomaly.FlowFieldComparisonClocks) {
	t.Helper()
	owned := f.tenants[0]
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var body sdk.FlowDDoSAssessmentInput
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[owned]))
	result, err := client.AssessFlowViewDDoS(t.Context(), sdk.AssessFlowViewDDoSRequest{Id: view.ID, Body: &body})
	if err != nil {
		t.Fatal(err)
	}
	assert := func(v any) {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		assertDDoSAssessment(t, raw, view.ID, windows)
	}
	assert(result)
	ca := filepath.Join(t.TempDir(), "passive-assessment-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[owned], "PROBECTL_CA_FILE": ca}[key]
	}
	if code := cli.RunWithStdin([]string{"--json", "explorer", "ddos-assess", view.ID, "--body", string(payload)}, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
		t.Fatal("CLI traffic assessment failed", code, stderr.String())
	}
	assertDDoSAssessment(t, stdout.Bytes(), view.ID, windows)
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	args := map[string]any{"id": view.ID, "assessment": input}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		var native flow.DDoSAssessment
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		call(owned, "flow_view_ddos_assess", args, &native, true)
		assert(native)
		call(f.tenants[1], "flow_view_ddos_assess", args, nil, false)
		openInterfaceRoleStdio(t, server, authenticator, f.tokens[owned], wire).call(t, wire, "flow_view_ddos_assess", args, &native, true)
		assert(native)
	}
}
