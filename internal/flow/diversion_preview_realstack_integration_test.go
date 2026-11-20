// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

const diversionPreviewPath = "/v1/remediation/diversion-preview"
const diversionProposalPath = "/v1/remediation/diversion-proposals"

func assertShippedDiversionPreview(t *testing.T, stack *shipped.Stack, owner, reviewer, sibling *nativeLane, observation remediation.PrefixImpactInput) {
	t.Helper()
	var preview remediation.DiversionPreview
	start := remediation.DiversionPreviewInput{Action: remediation.DiversionStart, Observation: &observation}
	owner.do(t, stack, http.MethodPost, diversionPreviewPath, start, &preview, http.StatusOK)
	sibling.do(t, stack, http.MethodPost, diversionPreviewPath, start, nil, http.StatusNotFound)
	if preview.Connector != remediation.LocalDiversionPreview || preview.Impact == nil || preview.Impact.KnownBenign.Packets != "4060" || preview.Impact.Matched.Bytes != "301250" {
		t.Fatalf("start did not preserve the whole protected scope: %+v", preview)
	}
	input := remediation.DiversionProposalInput{Selection: start, ObservedTo: &preview.Impact.To,
		PreviewFingerprint: preview.Fingerprint, MaxKnownBenignPackets: "4059"}
	owner.do(t, stack, http.MethodPost, diversionProposalPath, input, nil, http.StatusConflict)
	input.MaxKnownBenignPackets = "4060"
	var proposed remediation.Proposal
	owner.do(t, stack, http.MethodPost, diversionProposalPath, input, &proposed, http.StatusCreated)
	if proposed.Kind != remediation.KindDiversionPreview || proposed.State != remediation.StateProposed || proposed.DryRun.BlastRadius != 256 {
		t.Fatalf("unexpected pending start preview: %+v", proposed)
	}
	base := "/v1/remediation/proposals/" + proposed.ID
	stop := remediation.DiversionPreviewInput{Action: remediation.DiversionStop, StartPreviewID: proposed.ID}
	reviewer.do(t, stack, http.MethodPost, diversionPreviewPath, stop, nil, http.StatusNotFound)
	var review remediation.DiversionReview
	reviewer.do(t, stack, http.MethodGet, base+"/diversion-review", nil, &review, http.StatusOK)
	if review.Receipt != nil || review.Candidate.Action != remediation.DiversionStart || review.Fingerprint == preview.Fingerprint {
		t.Fatal("a proposed preview exposed an acknowledgement or lost the approval binding")
	}
	approve := remediation.DiversionApprovalInput{Fingerprint: review.Fingerprint}
	owner.do(t, stack, http.MethodPost, base+"/diversion-approve", approve, nil, http.StatusForbidden)
	sibling.do(t, stack, http.MethodGet, base+"/diversion-review", nil, nil, http.StatusNotFound)
	sibling.do(t, stack, http.MethodPost, base+"/diversion-approve", approve, nil, http.StatusNotFound)
	reviewer.do(t, stack, http.MethodPost, base+"/approve", map[string]string{"note": "generic"}, nil, http.StatusUnprocessableEntity)
	reviewer.do(t, stack, http.MethodPost, base+"/diversion-approve", remediation.DiversionApprovalInput{Fingerprint: preview.Fingerprint}, nil, http.StatusConflict)
	proveDiversionConsole(t, stack, reviewer, "dark", []testsupport.RenderStep{
		{Click: "Review local preview", Within: "tr:has-text('Start diversion preview')", Expect: []string{"Local preview", "Known benign packets", "4060"}},
		{Click: "Approve local preview", Expect: []string{"Local acknowledgement", "Preview stop"}},
	})
	var started remediation.DiversionReceipt
	reviewer.do(t, stack, http.MethodPost, base+"/diversion-approve", approve, &started, http.StatusOK)
	if started.Connector != remediation.LocalDiversionPreview || started.Action != remediation.DiversionStart || started.StartPreviewID != proposed.ID || started.Prefix != preview.Prefix {
		t.Fatalf("approval did not acknowledge the exact local start: %+v", started)
	}
	sibling.do(t, stack, http.MethodPost, diversionPreviewPath, stop, nil, http.StatusNotFound)
	assertShippedDiversionStop(t, stack, owner, reviewer, sibling, stop, started, base)
	assertDiversionDecisionsInTenantReport(t, stack, reviewer, sibling, observation)
}

func assertShippedDiversionStop(t *testing.T, stack *shipped.Stack, owner, reviewer, sibling *nativeLane, stop remediation.DiversionPreviewInput, start remediation.DiversionReceipt, startPath string) {
	t.Helper()
	proveDiversionConsole(t, stack, owner, "light", []testsupport.RenderStep{
		{Click: "Open preview receipt", Within: "tr:has-text('Start diversion preview')", Expect: []string{"Local acknowledgement", "Preview stop"}},
		{Click: "Preview stop", Expect: []string{"File stop for independent review"}},
		{Click: "File stop for independent review", Expect: []string{"Stop preview filed for independent review."}},
	})
	var list struct{ Items []remediation.Proposal }
	owner.do(t, stack, http.MethodGet, "/v1/remediation/proposals", nil, &list, http.StatusOK)
	var stopID string
	for _, proposal := range list.Items {
		if proposal.Kind == remediation.KindDiversionPreview && proposal.State == remediation.StateProposed && proposal.Title == "Stop diversion preview" {
			stopID = proposal.ID
		}
	}
	if stopID == "" {
		t.Fatal("stop preview was not filed")
	}
	base := "/v1/remediation/proposals/" + stopID
	var pending remediation.DiversionReview
	reviewer.do(t, stack, http.MethodGet, base+"/diversion-review", nil, &pending, http.StatusOK)
	if pending.Candidate.StartPreviewID != start.StartPreviewID || pending.Receipt != nil {
		t.Fatal("stop preview did not resolve the exact original local start")
	}
	approval := remediation.DiversionApprovalInput{Fingerprint: pending.Fingerprint}
	owner.do(t, stack, http.MethodPost, base+"/diversion-approve", approval, nil, http.StatusForbidden)
	sibling.do(t, stack, http.MethodPost, base+"/diversion-approve", approval, nil, http.StatusNotFound)
	var stopped, retried remediation.DiversionReceipt
	reviewer.do(t, stack, http.MethodPost, base+"/diversion-approve", approval, &stopped, http.StatusOK)
	reviewer.do(t, stack, http.MethodPost, base+"/diversion-approve", approval, &retried, http.StatusOK)
	reviewer.do(t, stack, http.MethodPost, diversionPreviewPath, stop, nil, http.StatusNotFound)
	var original remediation.DiversionReview
	reviewer.do(t, stack, http.MethodGet, startPath+"/diversion-review", nil, &original, http.StatusOK)
	if stopped.Action != remediation.DiversionStop || stopped.StartPreviewID != start.StartPreviewID || stopped.Connector != start.Connector ||
		!retried.RecordedAt.Equal(stopped.RecordedAt) || original.StartStoppedAt == nil || original.Receipt == nil || !original.Receipt.RecordedAt.Equal(start.RecordedAt) {
		t.Fatalf("stop or its retry did not preserve the exact recorded start and stop: %+v", stopped)
	}
}

func proveDiversionConsole(t *testing.T, stack *shipped.Stack, lane *nativeLane, theme string, steps []testsupport.RenderStep) {
	t.Helper()
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL: stack.BaseURL + "/ui/admin", TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
		Accessibility: true, Theme: theme, Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
		Expect: []string{"AI remediation proposals"}, Steps: steps,
	})
}

func assertDiversionDecisionsInTenantReport(t *testing.T, stack *shipped.Stack, reviewer, sibling *nativeLane, observation remediation.PrefixImpactInput) {
	t.Helper()
	var receipt alert.DDoSEvaluationEvidence
	reviewer.do(t, stack, http.MethodGet, "/v1/alerts/rules/"+observation.RuleID+"/ddos-receipt?fingerprint="+observation.ReceiptFingerprint, nil, &receipt, http.StatusOK)
	query := url.Values{"rule_id": {observation.RuleID}, "fingerprint": {observation.ReceiptFingerprint}}
	path := "/v1/incidents/" + receipt.IncidentID + "/ddos-report?" + query.Encode()
	var report alert.DDoSReport
	reviewer.do(t, stack, http.MethodGet, path, nil, &report, http.StatusOK)
	sibling.do(t, stack, http.MethodGet, path, nil, nil, http.StatusNotFound)
	for _, kind := range []string{"diversion_preview_start", "diversion_preview_stop"} {
		if !slices.ContainsFunc(report.Actions, func(action alert.DDoSReportDecision) bool { return action.Kind == kind && action.State == "approved" }) {
			t.Fatalf("tenant report did not include the recorded %s decision", kind)
		}
	}
}
