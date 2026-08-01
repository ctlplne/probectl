// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/logging"
	rem "github.com/ctlplne/probectl/internal/remediation"
)

const remediationProposePermission = "remediation.propose"

// TestMandatoryAuditFailureReachesRESTAndMCP proves the two shipped entry
// points share the fixed Service path. Both surfaces report failure, and
// neither can leave a proposal behind when the mandatory remediation audit
// append fails.
func TestMandatoryAuditFailureReachesRESTAndMCP(t *testing.T) {
	auditFailure := errors.New("injected surface audit failure")
	newFailingService := func() (*Service, *MemStore) {
		store := NewMemStore()
		svc := New(
			store,
			&fakeEstimator{dry: rem.DryRun{BlastRadius: 1}},
			Audit(func(context.Context, string, string, string, string, map[string]any) error {
				return auditFailure
			}),
			Config{ApprovalsEnabled: true, MaxBlastRadius: 50},
		).withNow(func() time.Time { return fixedNow })
		return svc, store
	}

	t.Run("rest", func(t *testing.T) {
		svc, store := newFailingService()
		cfg := &config.Config{
			HTTPAddr:    ":0",
			HSTSEnabled: true,
			HSTSMaxAge:  time.Hour,
			AuthMode:    "session",
		}
		srv := control.New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil).
			WithRemediation(svc)
		principal := &auth.Principal{
			TenantID: testTenant,
			UserID:   "user-a",
			Email:    "a@example.test",
			Permissions: map[string]bool{
				remediationProposePermission: true,
			},
		}
		req := httptest.NewRequest(
			http.MethodPost,
			"/v1/remediation/proposals",
			strings.NewReader(`{"kind":"open_ticket","title":"surface rollback"}`),
		)
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("REST status = %d, want 500; body=%s", rec.Code, rec.Body.String())
		}
		assertTenantProposalCounts(t, store, 0, 0)
	})

	t.Run("mcp", func(t *testing.T) {
		svc, store := newFailingService()
		backend := remediationMCPBackend{svc: svc}
		gate := ai.NewEgressGate(
			func(context.Context, string) (bool, error) { return true, nil },
			func(context.Context, ai.EgressEvent) error { return nil },
			ai.RedactionPolicy{},
		)
		server := mcp.New(
			backend,
			gate,
			mcp.WithCallAudit(func(context.Context, mcp.CallEvent) error { return nil }),
		)
		principal := &auth.Principal{
			TenantID: testTenant,
			UserID:   "mcp-user-a",
			Permissions: map[string]bool{
				remediationProposePermission: true,
			},
		}
		raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"propose_remediation","arguments":{"kind":"open_ticket","title":"surface rollback"}}}`)
		var response struct {
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal(server.Handle(context.Background(), principal, raw), &response); err != nil {
			t.Fatalf("decode MCP response: %v", err)
		}
		if response.Result["isError"] != true {
			t.Fatalf("MCP result = %#v, want isError=true", response.Result)
		}
		assertTenantProposalCounts(t, store, 0, 0)
	})
}

func TestLicenseReadOnlyRemediationMutationRESTAndMCPClockAdvanced(t *testing.T) {
	readOnlyAt := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	now := readOnlyAt.Add(-time.Second)
	delegate := &surfaceRemediationDelegateSpy{}
	gated := rem.GateServiceWrites(delegate, license.WriteCapability(func() bool {
		return now.Before(readOnlyAt)
	}))
	cfg := &config.Config{
		HTTPAddr:    ":0",
		HSTSEnabled: true,
		HSTSMaxAge:  time.Hour,
		AuthMode:    "session",
	}
	srv := control.New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil).
		WithRemediation(gated)

	request := func(tenantID, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		principal := &auth.Principal{
			TenantID: tenantID,
			UserID:   "admin-" + tenantID,
			Email:    tenantID + "@example.test",
			Permissions: map[string]bool{
				remediationProposePermission: true,
				"remediation.approve":        true,
			},
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Active: every mutation reaches the delegate.
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodPost, "/v1/remediation/proposals", `{"kind":"open_ticket","title":"active"}`, http.StatusCreated},
		{http.MethodPost, "/v1/remediation/proposals/p-active/approve", `{"note":"go"}`, http.StatusOK},
		{http.MethodPost, "/v1/remediation/proposals/p-active/reject", `{"note":"stop"}`, http.StatusOK},
	} {
		if rec := request(testTenant, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Fatalf("active %s %s: status=%d body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	gate := ai.NewEgressGate(
		func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, ai.EgressEvent) error { return nil },
		ai.RedactionPolicy{},
	)
	mcpServer := mcp.New(
		remediationMCPBackend{svc: gated},
		gate,
		mcp.WithCallAudit(func(context.Context, mcp.CallEvent) error { return nil }),
	)
	mcpCall := func(tenantID string) []byte {
		t.Helper()
		principal := &auth.Principal{
			TenantID: tenantID,
			UserID:   "mcp-" + tenantID,
			Permissions: map[string]bool{
				remediationProposePermission: true,
			},
		}
		raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"propose_remediation","arguments":{"kind":"open_ticket","title":"mcp proposal"}}}`)
		return mcpServer.Handle(context.Background(), principal, raw)
	}
	if raw := mcpCall(testTenant); strings.Contains(string(raw), `"isError":true`) {
		t.Fatalf("active MCP proposal denied: %s", raw)
	}
	activeCounts := delegate.counts()

	// The already-wired REST and MCP surfaces observe read-only without a
	// restart. Reads still reach the delegate for two tenants; no write does.
	now = readOnlyAt
	for _, tenantID := range []string{testTenant, testTenantB} {
		for _, path := range []string{
			"/v1/remediation/proposals",
			"/v1/remediation/proposals/p-" + tenantID,
		} {
			if rec := request(tenantID, http.MethodGet, path, ""); rec.Code != http.StatusOK {
				t.Fatalf("read-only GET %s for %s: status=%d body=%s", path, tenantID, rec.Code, rec.Body.String())
			}
		}
		for _, tc := range []struct {
			path, body string
		}{
			{"/v1/remediation/proposals", `{"kind":"open_ticket","title":"blocked"}`},
			{"/v1/remediation/proposals/p-" + tenantID + "/approve", `{"note":"blocked"}`},
			{"/v1/remediation/proposals/p-" + tenantID + "/reject", `{"note":"blocked"}`},
		} {
			rec := request(tenantID, http.MethodPost, tc.path, tc.body)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "license_read_only") {
				t.Fatalf("read-only POST %s for %s: status=%d body=%s", tc.path, tenantID, rec.Code, rec.Body.String())
			}
		}
		raw := mcpCall(tenantID)
		if !strings.Contains(string(raw), `"isError":true`) {
			t.Fatalf("read-only MCP proposal for %s = %s", tenantID, raw)
		}
	}
	if got := delegate.counts(); got != activeCounts {
		t.Fatalf("read-only mutation reached delegate: before=%+v after=%+v", activeCounts, got)
	}
	if len(delegate.listTenants) != 2 || len(delegate.getTenants) != 2 {
		t.Fatalf("read-only review did not reach delegate for both tenants: list=%v get=%v",
			delegate.listTenants, delegate.getTenants)
	}
}

type surfaceRemediationCounts struct {
	propose int
	approve int
	reject  int
}

type surfaceRemediationDelegateSpy struct {
	surfaceRemediationCounts
	listTenants []string
	getTenants  []string
}

func (s *surfaceRemediationDelegateSpy) counts() surfaceRemediationCounts {
	return s.surfaceRemediationCounts
}

func (s *surfaceRemediationDelegateSpy) Propose(_ context.Context, tenantID, _ string, in rem.ProposeInput) (rem.Proposal, error) {
	s.propose++
	return rem.Proposal{ID: "p-" + tenantID, TenantID: tenantID, Kind: in.Kind, State: rem.StateProposed}, nil
}

func (s *surfaceRemediationDelegateSpy) List(_ context.Context, tenantID string) ([]rem.Proposal, error) {
	s.listTenants = append(s.listTenants, tenantID)
	return []rem.Proposal{{ID: "p-" + tenantID, TenantID: tenantID, State: rem.StateProposed}}, nil
}

func (s *surfaceRemediationDelegateSpy) Get(_ context.Context, tenantID, id string) (rem.Proposal, error) {
	s.getTenants = append(s.getTenants, tenantID)
	return rem.Proposal{ID: id, TenantID: tenantID, State: rem.StateProposed}, nil
}

func (s *surfaceRemediationDelegateSpy) Approve(_ context.Context, tenantID, _, id, _ string) (rem.Proposal, error) {
	s.approve++
	return rem.Proposal{ID: id, TenantID: tenantID, State: rem.StateApproved}, nil
}

func (s *surfaceRemediationDelegateSpy) Reject(_ context.Context, tenantID, _, id, _ string) (rem.Proposal, error) {
	s.reject++
	return rem.Proposal{ID: id, TenantID: tenantID, State: rem.StateRejected}, nil
}

func (*surfaceRemediationDelegateSpy) ApprovalsEnabled() bool { return true }

type remediationMCPBackend struct{ svc rem.Service }

func (remediationMCPBackend) ListTests(context.Context, *auth.Principal) (any, error) {
	return nil, errors.New("unexpected ListTests call")
}

func (remediationMCPBackend) GetPath(context.Context, *auth.Principal, string) (any, error) {
	return nil, errors.New("unexpected GetPath call")
}

func (remediationMCPBackend) GetBGPEvents(context.Context, *auth.Principal, string, string, int) (any, error) {
	return nil, errors.New("unexpected GetBGPEvents call")
}

func (remediationMCPBackend) QueryFlows(context.Context, *auth.Principal, string, string, string, int) (any, error) {
	return nil, errors.New("unexpected QueryFlows call")
}

func (remediationMCPBackend) GetIncident(context.Context, *auth.Principal, string) (any, error) {
	return nil, errors.New("unexpected GetIncident call")
}

func (remediationMCPBackend) CorrelateIncident(context.Context, *auth.Principal, string) (any, error) {
	return nil, errors.New("unexpected CorrelateIncident call")
}

func (remediationMCPBackend) ExplainDegradation(context.Context, *auth.Principal, string, map[string]string) (any, error) {
	return nil, errors.New("unexpected ExplainDegradation call")
}

func (b remediationMCPBackend) ProposeRemediation(
	ctx context.Context,
	p *auth.Principal,
	kind, title, rationale, target, incidentID string,
) (any, error) {
	return b.svc.Propose(ctx, p.TenantID, "ai:propose_remediation", rem.ProposeInput{
		Kind: rem.Kind(kind), Title: title, Rationale: rationale,
		Target: target, IncidentID: incidentID,
	})
}
