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
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
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
	previewInput := prepareOriginalPrefixImpact(t, f, rows, views, selections[0], last.After.Start)
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
	previewInput.RuleID, previewInput.ReceiptFingerprint = rules[0].ID, fingerprint
	assertOriginalPrefixImpact(t, f, socket, previewInput, selections[0], last.After.Start)
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

// The core isolation fixture supplies the EE read seam without importing ee/.
type integrationPrefixPreview struct {
	remediation.Service
	server *Server
}

func (fixture integrationPrefixPreview) PreviewRTBH(ctx context.Context, tenant string, input remediation.RTBHPreviewInput,
	verify func(context.Context) error) (remediation.RTBHPreview, error) {
	impact, err := fixture.server.ObservePrefixImpact(ctx, tenant, input.PrefixImpactInput, verify)
	return remediation.RTBHPreview{Announcement: remediation.RTBHAnnouncement{Family: "ipv4", Prefix: impact.Prefix, Community: input.Community}, Impact: impact}, err
}

func prepareOriginalPrefixImpact(t *testing.T, f *roleExplanationAPIFixture, rows flowstore.Store,
	views *flow.PostgresQueryViewStore, filtered flow.SavedQueryView, at time.Time) remediation.RTBHPreviewInput {
	t.Helper()
	owned := f.tenants[0]
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permRemediationPropose, "entities.read", "events.read"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
	}
	input := remediation.RTBHPreviewInput{Community: "64512:100", RoutingPolicyAgreed: true}
	f.in(owned, func(ctx context.Context, sc tenancy.Scope) error {
		registry := store.NewEntityRegistry(f.pool)
		domain, err := registry.CreateEntityContext(ctx, sc, "Traffic review", "owned-edge")
		if err != nil {
			return err
		}
		protected, err := registry.CreateCanonicalEntityWithNetwork(ctx, sc, domain.ContextID, entity.Prefix, "Protected network", "192.0.2.0/24")
		if err != nil {
			return err
		}
		benign, err := registry.CreateCanonicalEntityWithNetwork(ctx, sc, domain.ContextID, entity.Prefix, "Known service", "198.51.101.0/24")
		if err != nil {
			return err
		}
		input.ContextID, input.ProtectedEntityID, input.BenignEntityID = domain.ContextID, protected.ID, benign.ID
		other, err := registry.CreateEntityContext(ctx, sc, "Other owned route", "overlapping-vrf")
		if err != nil {
			return err
		}
		for _, assignment := range []struct{ context, agent, exporter string }{
			{domain.ContextID, "passive-assessment-source", "203.0.113.15"},
			{domain.ContextID, "passive-assessment-source", "203.0.113.16"},
			{domain.ContextID, "known-benign-source", "203.0.113.17"},
			{other.ContextID, "other-rtbh-source", "203.0.113.17"},
		} {
			since := at.Add(-time.Hour)
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,context_id,agent_id,assigned_at)
			 VALUES($1,$2,$3,$4) ON CONFLICT (tenant_id,agent_id) DO NOTHING`, sc.Tenant.String(), assignment.context, assignment.agent, since); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,context_id,agent_id,source_kind,source_ref,assigned_at)
			 VALUES($1,$2,$3,'flow_exporter',$4,$5)`, sc.Tenant.String(), assignment.context, assignment.agent, assignment.exporter, since); err != nil {
				return err
			}
		}
		return nil
	})
	definition := filtered.Definition
	definition.Name, definition.Plan.Filter = "Whole protected view", nil
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owned))
	whole, err := views.SaveQueryView(ctx, owned, f.users[owned], flow.SaveQueryView{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	input.WholeViewID, input.WholeViewVersion = whole.ID, whole.Version
	measured := at.Add(time.Minute)
	benignRow := flowstore.Row{TenantID: owned, AgentID: "known-benign-source", Exporter: "203.0.113.17", Protocol: "ipfix",
		TS: measured, StartTS: measured.Add(-time.Second), SrcAddr: "198.51.101.42", DstAddr: "192.0.2.42", SrcPort: 42001, DstPort: 443,
		Transport: "tcp", Sampling: 1, Bytes: 1234, BytesScaled: 1234, Packets: 7, PacketsScaled: 7}
	otherVRF := benignRow
	otherVRF.AgentID, otherVRF.Bytes, otherVRF.BytesScaled = "other-rtbh-source", 50000000000000000, 50000000000000000
	if err := rows.Insert(ctx, []flowstore.Row{benignRow, otherVRF}); err != nil {
		t.Fatal(err)
	}
	return input
}

func assertOriginalPrefixImpact(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server,
	input remediation.RTBHPreviewInput, filtered flow.SavedQueryView, at time.Time) {
	t.Helper()
	owned, sibling := f.tenants[0], f.tenants[1]
	const path = "/v1/remediation/rtbh-preview"
	callSeasonalAPI(t, socket, f.tokens[owned], http.MethodPost, path, input, http.StatusNotFound)
	f.server.WithRemediation(integrationPrefixPreview{server: f.server})
	body := callSeasonalAPI(t, socket, f.tokens[owned], http.MethodPost, path, input, http.StatusOK)
	assertOwnedPrefixImpact(t, body, at)
	callSeasonalAPI(t, socket, f.tokens[sibling], http.MethodPost, path, input, http.StatusNotFound)
	bad := input
	bad.WholeViewID, bad.WholeViewVersion = filtered.ID, filtered.Version
	callSeasonalAPI(t, socket, f.tokens[owned], http.MethodPost, path, bad, http.StatusUnprocessableEntity)
	var sdkInput sdk.RemediationRTBHPreviewInput
	if err := json.Unmarshal(encodeScheduledDDoSProof(t, input), &sdkInput); err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[owned]))
	answer, err := client.PreviewRemediationRtbh(t.Context(), sdk.PreviewRemediationRtbhRequest{Body: &sdkInput})
	if err != nil {
		t.Fatal(err)
	}
	assertOwnedPrefixImpact(t, encodeScheduledDDoSProof(t, answer), at)
}

func assertOwnedPrefixImpact(t *testing.T, raw []byte, at time.Time) {
	t.Helper()
	var got remediation.RTBHPreview
	if err := json.Unmarshal(raw, &got); err != nil || got.Announcement.Prefix != "192.0.2.0/24" || got.Announcement.Family != "ipv4" ||
		got.Announcement.Community != "64512:100" || !got.Impact.From.Equal(at) || !got.Impact.To.Equal(at.Add(5*time.Minute)) || !got.Impact.Sampled ||
		got.Impact.Matched.Bytes != "21007199254742234" || got.Impact.Matched.Packets != "8007" || got.Impact.ObservedAddresses != 2 || got.Impact.ObservedRecords != 3 ||
		got.Impact.KnownBenign.Bytes != "1234" || got.Impact.KnownBenign.Packets != "7" ||
		got.Impact.Unclassified.Bytes != "21007199254741000" || got.Impact.Unclassified.Packets != "8000" ||
		bytes.Contains(raw, []byte("198.51.101.42")) {
		t.Fatal("the review lost exact total, benign subset or protected source scope", got, err)
	}
}
