// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type statelessFlowPlannerProbe struct {
	calls    int
	input    ai.FlowQuestionInput
	tenant   string
	proposal ai.FlowQuestionProposal
	onPlan   func()
}

func (p *statelessFlowPlannerProbe) Plan(ctx context.Context, input ai.FlowQuestionInput) (ai.FlowQuestionProposal, error) {
	p.calls++
	p.input = input
	p.tenant = auth.PrincipalFrom(ctx).TenantID
	if p.onPlan != nil {
		p.onPlan()
	}
	return p.proposal, nil
}
func statelessFlowReady() ai.FlowQuestionProposal {
	return ai.FlowQuestionProposal{Status: ai.FlowQuestionReady, Plan: &flow.QueryPlan{
		From: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC),
		GroupBy: []string{"src_addr"}, View: "table", RowLimit: 50000,
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}},
	}}
}
func statelessFlowPrincipal(tenant string) *auth.Principal {
	return &auth.Principal{TenantID: tenant, UserID: "operator", Permissions: map[string]bool{"flow.read": true, "ai.query": true}, TenantTimeZone: "America/New_York", TenantLocale: "en-US"}
}

func TestFlowQuestionStatelessRESTAndMCPShareAuthorizedProposal(t *testing.T) {
	for _, tenant := range []string{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"} {
		t.Run(tenant, func(t *testing.T) {
			srv := testServer(fakePinger{})
			probe := &statelessFlowPlannerProbe{proposal: statelessFlowReady()}
			srv.flowQuestionPlanner = probe
			p := statelessFlowPrincipal(tenant)
			req := httptest.NewRequest(http.MethodPost, "/v1/explorer/query", strings.NewReader(`{"source":"flow","plan_only":true,"question":"show all bytes"}`))
			req = req.WithContext(auth.WithPrincipal(req.Context(), p))
			rec := httptest.NewRecorder()
			if err := srv.handleExplorerQuery(rec, req); err != nil {
				t.Fatal(err)
			}
			var rest mcp.NativeFlowQuestionResult
			if err := json.Unmarshal(rec.Body.Bytes(), &rest); err != nil {
				t.Fatal(err)
			}
			wire, failed := nativeControlCall(t, nativeControlMCP(t, srv), p, "flow_explorer_plan", mcp.NativeFlowQuestionInput{Question: "show all bytes"})
			if failed {
				t.Fatal("MCP planning refused", string(wire))
			}
			var native mcp.NativeFlowQuestionResult
			if err := json.Unmarshal(wire, &native); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(rest, native) || rest.Proposal.Plan.RowLimit != 50000 {
				t.Fatal("proposal reach differs between REST and MCP")
			}
			if probe.calls != 2 || probe.tenant != tenant || probe.input.Parent != nil || probe.input.Now.IsZero() || probe.input.TimeZone != "America/New_York" || probe.input.Locale != "en-US" {
				t.Fatal("stateless planner did not receive authenticated scope/clock/preferences")
			}
		})
	}
}

func TestFlowQuestionStatelessRejectsAuthorityAndExecutionOverrides(t *testing.T) {
	srv := testServer(fakePinger{})
	probe := &statelessFlowPlannerProbe{proposal: statelessFlowReady()}
	srv.flowQuestionPlanner = probe
	for _, body := range []string{
		`{"source":"flow","plan_only":true,"question":"q","flow":{}}`,
		`{"source":"flow","plan_only":true,"question":"q","template":"top-talkers-site"}`,
		`{"source":"path","plan_only":true,"question":"q"}`,
		`{"source":"flow","plan_only":true,"question":"q","tenant_id":"other"}`,
		`{"source":"flow","plan_only":true,"question":"q","parent":{}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/explorer/query", strings.NewReader(body))
		req = req.WithContext(auth.WithPrincipal(req.Context(), statelessFlowPrincipal("red")))
		if err := srv.handleExplorerQuery(httptest.NewRecorder(), req); err == nil {
			t.Fatal("accepted override", body)
		}
	}
	for _, p := range []*auth.Principal{nil, {}, {TenantID: "red", UserID: "operator", Permissions: map[string]bool{"ai.query": true}}, {TenantID: "red", UserID: "operator", Permissions: map[string]bool{"flow.read": true}}} {
		if _, err := srv.planFlowQuestion(t.Context(), p, "q"); err == nil {
			t.Fatal("accepted missing identity/grant")
		}
	}
	if probe.calls != 0 {
		t.Fatal("unauthorized or malformed input reached planner")
	}
}

func TestFlowQuestionStatelessRechecksPermissionsAndValidatesModelGrammar(t *testing.T) {
	for _, name := range []string{"revoked", "joined-metadata", "invalid-plan"} {
		t.Run(name, func(t *testing.T) {
			srv := testServer(fakePinger{})
			p := statelessFlowPrincipal("red")
			probe := &statelessFlowPlannerProbe{proposal: statelessFlowReady()}
			switch name {
			case "revoked":
				probe.onPlan = func() { delete(p.Permissions, "flow.read") }
			case "joined-metadata":
				probe.proposal.Plan.GroupBy = []string{"in_if_name"}
			case "invalid-plan":
				probe.proposal.Plan.GroupBy = []string{"SELECT * FROM secrets"}
			}
			srv.flowQuestionPlanner = probe
			if _, err := srv.planFlowQuestion(t.Context(), p, "q"); err == nil {
				t.Fatal("unsafe proposal published")
			}
		})
	}
}

func TestFlowQuestionStatelessProductionBuiltinAndSafeFailures(t *testing.T) {
	srv := testServer(fakePinger{})
	result, err := srv.planFlowQuestion(t.Context(), statelessFlowPrincipal("red"), "show bps all rows")
	if err != nil || result.Proposal.Status != ai.FlowQuestionReady || result.Proposal.Plan.RowLimit != 50000 {
		t.Fatal("production composition did not use stateless builtin", err)
	}
	for _, cause := range []error{ai.ErrFlowQuestionBudget, ai.ErrFlowQuestionInput, ai.ErrEgressDenied, errors.New("private-provider-detail")} {
		err := flowQuestionError(cause)
		var domain *apierror.Error
		if !errors.As(err, &domain) || strings.Contains(err.Error(), "private-provider-detail") {
			t.Fatal("provider error crossed public boundary")
		}
	}
}
