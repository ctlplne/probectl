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

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/ai/mcp"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/control"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	rem "github.com/imfeelingtheagi/probectl/internal/remediation"
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
