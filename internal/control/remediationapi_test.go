// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/remediation"
)

// fakeRemed is a configurable in-test implementation of the CORE
// remediation.Service interface (the control plane never imports ee/). It lets
// the handler tests drive each policy outcome.
type fakeRemed struct {
	approvals  bool
	proposeOut remediation.Proposal
	proposeErr error
	approveErr error
	listOut    []remediation.Proposal
	getOut     remediation.Proposal
	getErr     error
	lastBy     string // records the proposer/approver the handler passed
	lastInput  remediation.ProposeInput
}

func (f *fakeRemed) Propose(_ context.Context, tenantID, by string, in remediation.ProposeInput) (remediation.Proposal, error) {
	f.lastBy = by
	f.lastInput = in
	if f.proposeErr != nil {
		return remediation.Proposal{}, f.proposeErr
	}
	out := f.proposeOut
	out.TenantID = tenantID
	out.Kind = in.Kind
	out.Title = in.Title
	out.ProposedBy = by
	out.State = remediation.StateProposed // the handler can never make it anything else
	return out, nil
}
func (f *fakeRemed) List(context.Context, string) ([]remediation.Proposal, error) {
	return f.listOut, nil
}
func (f *fakeRemed) Get(context.Context, string, string) (remediation.Proposal, error) {
	return f.getOut, f.getErr
}
func (f *fakeRemed) Approve(_ context.Context, _, approver, _, _ string) (remediation.Proposal, error) {
	f.lastBy = approver
	if f.approveErr != nil {
		return remediation.Proposal{}, f.approveErr
	}
	return remediation.Proposal{State: remediation.StateApproved, DecidedBy: approver}, nil
}
func (f *fakeRemed) Reject(_ context.Context, _, decider, _, _ string) (remediation.Proposal, error) {
	f.lastBy = decider
	return remediation.Proposal{State: remediation.StateRejected, DecidedBy: decider}, nil
}
func (f *fakeRemed) ApprovalsEnabled() bool { return f.approvals }

// TestRemediationHiddenUnlicensed: with no service installed, every route 404s
// (hidden-unlicensed — no lockware).
func TestRemediationHiddenUnlicensed(t *testing.T) {
	srv := testServer(nil)
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/remediation/proposals"},
		{http.MethodPost, "/v1/remediation/proposals"},
		{http.MethodGet, "/v1/remediation/proposals/abc"},
		{http.MethodPost, "/v1/remediation/proposals/abc/approve"},
		{http.MethodPost, "/v1/remediation/proposals/abc/reject"},
	} {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}")))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s %s: status %d, want 404 (hidden)", tc.method, tc.path, rr.Code)
		}
	}
}

// TestRemediationProposeAlwaysProposed: the propose handler records the
// authenticated user as the proposer and returns a PROPOSED proposal (201).
func TestRemediationProposeAlwaysProposed(t *testing.T) {
	f := &fakeRemed{approvals: true}
	srv := testServer(nil)
	srv.WithRemediation(f)

	body := `{"kind":"open_ticket","title":"investigate detection","target":"203.0.113.66","incident_id":"inc-42","rationale":"Detection det-2 ioc.botnet confidence 90 from feodo"}`
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/remediation/proposals", strings.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var out remediation.Proposal
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.State != remediation.StateProposed {
		t.Fatalf("state=%q, want proposed", out.State)
	}
	// The proposer is the authenticated human (dev principal), never client input.
	if !strings.HasPrefix(f.lastBy, "user:") {
		t.Fatalf("proposer=%q, want a user: prefix from the authenticated principal", f.lastBy)
	}
	if f.lastInput.IncidentID != "inc-42" ||
		!strings.Contains(f.lastInput.Rationale, "det-2") ||
		f.lastInput.Target != "203.0.113.66" {
		t.Fatalf("proposal input lost detection evidence: %+v", f.lastInput)
	}
}

// TestRemediationApproveAdvisoryOnly: when approvals are disabled, Approve maps
// to 409 Conflict with the approvals_disabled code (advisory-only).
func TestRemediationApproveAdvisoryOnly(t *testing.T) {
	f := &fakeRemed{approvals: false, approveErr: remediation.ErrApprovalsDisabled}
	srv := testServer(nil)
	srv.WithRemediation(f)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/remediation/proposals/abc/approve", strings.NewReader(`{"note":"go"}`)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("status %d: %s, want 409", rr.Code, rr.Body.String())
	}
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error.Code != "approvals_disabled" {
		t.Fatalf("code=%q, want approvals_disabled; body=%s", e.Error.Code, rr.Body.String())
	}
}

// TestRemediationApproveBlastRadius: an over-limit proposal maps to 409 with the
// blast_radius_exceeded code.
func TestRemediationApproveBlastRadius(t *testing.T) {
	f := &fakeRemed{approvals: true, approveErr: remediation.ErrBlastRadiusExceeded}
	srv := testServer(nil)
	srv.WithRemediation(f)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/remediation/proposals/abc/approve", strings.NewReader(`{}`)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409: %s", rr.Code, rr.Body.String())
	}
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error.Code != "blast_radius_exceeded" {
		t.Fatalf("code=%q, want blast_radius_exceeded", e.Error.Code)
	}
}

func TestRemediationDecisionRejectsMalformedOptionalBody(t *testing.T) {
	f := &fakeRemed{approvals: true}
	srv := testServer(nil)
	srv.WithRemediation(f)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/remediation/proposals/abc/approve", strings.NewReader(`{"note":`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed optional note body returned %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if f.lastBy != "" {
		t.Fatalf("malformed decision body still reached service as %q", f.lastBy)
	}
}

// TestRemediationListExposesApprovalsFlag: the list response carries the
// advisory-only master switch so the UI can disable/relabel Approve.
func TestRemediationListExposesApprovalsFlag(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		f := &fakeRemed{approvals: enabled, listOut: []remediation.Proposal{{ID: "rem-1", State: remediation.StateProposed}}}
		srv := testServer(nil)
		srv.WithRemediation(f)

		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/remediation/proposals", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
		}
		var got struct {
			Items            []remediation.Proposal `json:"items"`
			ApprovalsEnabled bool                   `json:"approvals_enabled"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.ApprovalsEnabled != enabled {
			t.Fatalf("approvals_enabled=%v, want %v", got.ApprovalsEnabled, enabled)
		}
		if len(got.Items) != 1 {
			t.Fatalf("items=%d, want 1", len(got.Items))
		}
	}
}
