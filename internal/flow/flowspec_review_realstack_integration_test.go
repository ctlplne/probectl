// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestFlowSpecReviewUsesOwnedMatchesAndIndependentApproval(t *testing.T) {
	stack, owner, reviewer, sibling, scoped, end, operator := prepareShippedRoutingReceipt(t, true)
	appendFlowSpecControlObservation(t, owner, end)
	flowSpecPort := uint16(42001)
	destination := uint16(443)
	input := remediation.FlowSpecPreviewInput{
		PrefixImpactInput: scoped.PrefixImpactInput, RoutingPolicyAgreed: true,
		Transport: remediation.FlowSpecTransport{Protocol: "tcp", SourcePort: &flowSpecPort, DestinationPort: &destination},
	}
	const previewPath = "/v1/remediation/flowspec-preview"
	shipped.Await(t, "complete protected-prefix totals after the nonmatching observation", 30*time.Second, func() bool {
		scope := fmt.Sprintf("10.%d.1.0/24", owner.octet)
		plan := nativeGoldenPlan(owner.octet, end, []string{"dst_addr"})
		plan.From, plan.To, plan.DataSeries = end.Add(-5*time.Minute), end, "raw"
		plan.Filter.Conditions = append(plan.Filter.Conditions, flow.QueryPredicate{Field: "dst_addr", Op: flow.QueryCIDR, Values: []string{scope}})
		result := owner.query(t, stack, plan)
		return result.Totals["bytes:total"] == "301250" && result.Totals["packets:total"] == "4060"
	})
	var preview remediation.FlowSpecPreview
	owner.do(t, stack, http.MethodPost, previewPath, input, &preview, http.StatusOK)
	sibling.do(t, stack, http.MethodPost, previewPath, input, nil, http.StatusNotFound)
	prefix := fmt.Sprintf("10.%d.1.0/24", owner.octet)
	if preview.Candidate.Destination != prefix || preview.Candidate.Action != "discard" ||
		preview.Candidate.Transport.Protocol != "tcp" || preview.Candidate.Transport.SourcePort == nil ||
		*preview.Candidate.Transport.SourcePort != flowSpecPort || preview.Fingerprint == "" ||
		!preview.Matching.To.Equal(end) || preview.Matching.KnownBenign.Packets != "4000" ||
		preview.Matching.Matched.Bytes != "300000" || preview.WholeScope.Matched.Bytes != "301250" ||
		preview.WholeScope.KnownBenign.Packets != "4060" || preview.Matching.ObservedRecords != 1 ||
		preview.WholeScope.ObservedRecords != 2 || !preview.Matching.Sampled || !preview.WholeScope.Sampled {
		t.Fatalf("wrong scoped FlowSpec candidate or collateral: %+v", preview)
	}
	diversion := remediation.DiversionPreviewInput{Action: remediation.DiversionStart, Observation: &input.PrefixImpactInput}
	diversionPreview := readShippedDiversionStart(t, stack, owner, sibling, diversion, end)
	proposeFlowSpecAndApprove(t, stack, owner, reviewer, sibling, input, preview)
	assertShippedDiversionDecisions(t, stack, owner, reviewer, sibling, diversion, diversionPreview)
	assertShippedDDoSProviderReport(t, stack, owner, sibling, operator, input.PrefixImpactInput)
	assertDDoSProviderReportConsole(t, stack, operator)
}

func appendFlowSpecControlObservation(t *testing.T, owner *nativeLane, end time.Time) {
	t.Helper()
	// Export one benign observation record over the owned loopback collector.
	// The report's described traffic is never sent.
	socket, err := net.Dial("udp", owner.listeners["IPFIX"])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = socket.Close() }()
	record := controlledTrafficIPFIX(t, owner.octet, 0, 0, 801, end.Add(-time.Minute),
		trafficVector{transport: 17, port: 25001}, 125, 6)
	if n, err := socket.Write(record); err != nil || n != len(record) {
		t.Fatal("the benign observation did not reach the test exporter socket", err)
	}
}

func proposeFlowSpecAndApprove(t *testing.T, stack *shipped.Stack, owner, reviewer, sibling *nativeLane, input remediation.FlowSpecPreviewInput, preview remediation.FlowSpecPreview) {
	t.Helper()
	const proposals = "/v1/remediation/flowspec-proposals"
	file := remediation.FlowSpecProposalInput{
		Preview: input, ObservedTo: preview.Matching.To, PreviewFingerprint: preview.Fingerprint, MaxKnownBenignPackets: "3999",
	}
	owner.do(t, stack, http.MethodPost, proposals, file, nil, http.StatusConflict)
	file.MaxKnownBenignPackets = "4000"
	var proposal remediation.Proposal
	owner.do(t, stack, http.MethodPost, proposals, file, &proposal, http.StatusCreated)
	if proposal.State != remediation.StateProposed || proposal.Kind != remediation.KindFlowSpecReview || proposal.DryRun.BlastRadius != 256 || proposal.Target != "" {
		t.Fatal("the filed FlowSpec proposal lost its pending state, scope or privacy")
	}
	base := "/v1/remediation/proposals/" + proposal.ID
	var review remediation.FlowSpecReview
	reviewer.do(t, stack, http.MethodGet, base+"/flowspec-review", nil, &review, http.StatusOK)
	sibling.do(t, stack, http.MethodGet, base+"/flowspec-review", nil, nil, http.StatusNotFound)
	if review.Fingerprint == "" || review.Fingerprint == preview.Fingerprint || review.Proposal.Matching != preview.Matching ||
		review.Proposal.WholeScope != preview.WholeScope || review.MaxKnownBenignPackets != "4000" {
		t.Fatal("the independent reviewer did not receive the same measured surfaces")
	}
	qualification, qualificationFingerprint := assertScopedFlowSpecRouterProfile(t, stack, reviewer, sibling, base, review)
	assertFlowSpecReviewConsole(t, stack, reviewer, sibling, proposal.Title, review)
	exact := map[string]string{"review_fingerprint": review.Fingerprint}
	approve := base + "/flowspec-approve"
	approved := remediation.FlowSpecApprovalInput{Fingerprint: review.Fingerprint, Handoff: &remediation.FlowSpecHandoffInput{
		Qualification: qualification, QualificationFingerprint: qualificationFingerprint, DurationSeconds: 90,
	}}
	wrong := approved
	wrongHandoff := *approved.Handoff
	wrongHandoff.QualificationFingerprint = review.Fingerprint
	wrong.Handoff = &wrongHandoff
	reviewer.do(t, stack, http.MethodPost, approve, wrong, nil, http.StatusConflict)
	reviewer.do(t, stack, http.MethodGet, base+"/flowspec-handoff", nil, nil, http.StatusNotFound)
	reviewer.do(t, stack, http.MethodPost, base+"/approve", map[string]string{"note": "not typed"}, nil, http.StatusUnprocessableEntity)
	reviewer.do(t, stack, http.MethodPost, base+"/approve", exact, nil, http.StatusNotFound)
	owner.do(t, stack, http.MethodPost, approve, exact, nil, http.StatusForbidden)
	sibling.do(t, stack, http.MethodPost, approve, exact, nil, http.StatusNotFound)
	reviewer.do(t, stack, http.MethodPost, approve, map[string]string{"review_fingerprint": preview.Fingerprint}, nil, http.StatusConflict)
	sessionFile := filepath.Join(t.TempDir(), "reviewer-session")
	if err := os.WriteFile(sessionFile, []byte(reviewer.cookie), 0o600); err != nil {
		t.Fatal(err)
	}
	stack.MustCLI(t, nil, &proposal, "remediation", "flowspec-approve", proposal.ID,
		"--session-cookie-file", sessionFile, "--body-file", stack.SecretFile(t, approved))
	if proposal.State != remediation.StateApproved || proposal.DecidedBy != "user:alice@acme.example" {
		t.Fatal("the independent reviewer session did not record the exact approval")
	}
	reviewer.do(t, stack, http.MethodPost, approve, exact, nil, http.StatusConflict)
	assertDDoSIncidentReport(t, stack, reviewer, sibling, input, proposal.ID)
	assertFlowSpecHandoffWithdrawal(t, stack, reviewer, sibling, base, approved)
	assertFlowSpecHandoffExpires(t, stack, owner, reviewer, file, qualification)
}

func assertFlowSpecHandoffWithdrawal(t *testing.T, stack *shipped.Stack, reviewer, sibling *nativeLane, base string, approval remediation.FlowSpecApprovalInput) {
	t.Helper()
	var handoff remediation.FlowSpecHandoffStatus
	reviewer.do(t, stack, http.MethodGet, base+"/flowspec-handoff", nil, &handoff, http.StatusOK)
	sibling.do(t, stack, http.MethodGet, base+"/flowspec-handoff", nil, nil, http.StatusNotFound)
	sibling.do(t, stack, http.MethodPost, base+"/flowspec-withdraw", nil, nil, http.StatusNotFound)
	if handoff.State != remediation.FlowSpecAuthorized || handoff.ReviewFingerprint != approval.Fingerprint ||
		handoff.Qualification.QualificationFingerprint != approval.Handoff.QualificationFingerprint ||
		handoff.ExpiresAt.Sub(handoff.IssuedAt) != time.Duration(approval.Handoff.DurationSeconds)*time.Second {
		t.Fatalf("handoff authorization lost its fixed scope or expiry: %+v", handoff)
	}
	for _, theme := range []string{"light", "dark"} {
		steps := []testsupport.RenderStep{
			{Click: "Open handoff", Expect: []string{"Approved FlowSpec handoff", "Authorized", "flow-spec ipv4"}},
		}
		if theme == "dark" {
			steps = append(steps, testsupport.RenderStep{Click: "Withdraw handoff", Expect: []string{"Withdrawal requested"}})
		}
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: stack.BaseURL + "/ui/admin", TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile, Accessibility: true, Theme: theme,
			Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: reviewer.cookie}},
			Expect:  []string{"AI remediation proposals"}, Steps: steps,
		})
	}
	var first, repeated remediation.FlowSpecHandoffStatus
	reviewer.do(t, stack, http.MethodGet, base+"/flowspec-handoff", nil, &first, http.StatusOK)
	reviewer.do(t, stack, http.MethodPost, base+"/flowspec-withdraw", nil, &repeated, http.StatusOK)
	if first.State != remediation.FlowSpecWithdrawalRequested || first.WithdrawRequested == nil || repeated.WithdrawRequested == nil ||
		!repeated.WithdrawRequested.Equal(*first.WithdrawRequested) || !first.ExpiresAt.Equal(handoff.ExpiresAt) {
		t.Fatal("withdrawal did not retain one audited intent for the original handoff")
	}
}

func assertFlowSpecHandoffExpires(t *testing.T, stack *shipped.Stack, owner, reviewer *nativeLane,
	file remediation.FlowSpecProposalInput, qualification remediation.FlowSpecQualificationInput,
) {
	t.Helper()
	var second remediation.Proposal
	owner.do(t, stack, http.MethodPost, "/v1/remediation/flowspec-proposals", file, &second, http.StatusCreated)
	base := "/v1/remediation/proposals/" + second.ID
	var review remediation.FlowSpecReview
	reviewer.do(t, stack, http.MethodGet, base+"/flowspec-review", nil, &review, http.StatusOK)
	var report remediation.FlowSpecQualification
	reviewer.do(t, stack, http.MethodPost, base+"/flowspec-qualification", qualification, &report, http.StatusOK)
	input := remediation.FlowSpecApprovalInput{Fingerprint: review.Fingerprint, Handoff: &remediation.FlowSpecHandoffInput{
		Qualification: qualification, QualificationFingerprint: report.QualificationFingerprint, DurationSeconds: 3,
	}}
	reviewer.do(t, stack, http.MethodPost, base+"/flowspec-approve", input, nil, http.StatusOK)
	shipped.Await(t, "the exact handoff expires under its approved clock", 15*time.Second, func() bool {
		var expired remediation.FlowSpecHandoffStatus
		reviewer.do(t, stack, http.MethodGet, base+"/flowspec-handoff", nil, &expired, http.StatusOK)
		return expired.State == remediation.FlowSpecExpired && expired.WithdrawRequested == nil
	})
}

func assertDDoSIncidentReport(t *testing.T, stack *shipped.Stack, reviewer, sibling *nativeLane, input remediation.FlowSpecPreviewInput, proposalID string) {
	t.Helper()
	var receipt alert.DDoSEvaluationEvidence
	reviewer.do(t, stack, http.MethodGet, "/v1/alerts/rules/"+input.RuleID+"/ddos-receipt?fingerprint="+input.ReceiptFingerprint, nil, &receipt, http.StatusOK)
	query := url.Values{"rule_id": {input.RuleID}, "fingerprint": {input.ReceiptFingerprint}}
	reportPath := "/v1/incidents/" + receipt.IncidentID + "/ddos-report?" + query.Encode()
	var report alert.DDoSReport
	reviewer.do(t, stack, http.MethodGet, reportPath, nil, &report, http.StatusOK)
	sibling.do(t, stack, http.MethodGet, reportPath, nil, nil, http.StatusNotFound)
	if report.ObservedSeconds != 600 || report.PeakBitRate.Count != "2400000" || report.PeakBitRate.PerSecond != "8000.000" ||
		report.PeakPacketRate.Count != "4000" || report.PeakPacketRate.PerSecond != "13.333" || !report.ActionsVisible ||
		len(report.TopSources) != 1 || report.TopSources[0].Bytes != "600000" || report.TopSources[0].Packets != "8000" ||
		len(report.Actions) != 1 || report.Actions[0].ProposalID != proposalID || report.Actions[0].State != "approved" {
		t.Fatalf("the report lost the original scoped source, rates or action: %+v", report)
	}
	for _, theme := range []string{"light", "dark"} {
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL:            stack.BaseURL + "/ui/incidents?incident=" + url.QueryEscape(receipt.IncidentID),
			TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile, Accessibility: true, Theme: theme,
			Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: reviewer.cookie}},
			Expect:  []string{"alert.ddos_assessment"},
			Steps: []testsupport.RenderStep{
				{Click: "Sustained traffic red", Within: "table:has-text('alert.ddos_assessment')", Expect: []string{"Traffic pressure receipt"}},
				{Click: "Show original traffic evidence", Expect: []string{"First qualifying window"}},
				{Click: "Open DDoS incident report", Expect: []string{"Top observed source addresses by bytes", "600000", "8000.000 bits per second", "FlowSpec · approved"}},
			},
		})
	}
}

func assertScopedFlowSpecRouterProfile(t *testing.T, stack *shipped.Stack, reviewer, sibling *nativeLane, base string, review remediation.FlowSpecReview) (remediation.FlowSpecQualificationInput, string) {
	t.Helper()
	path := base + "/flowspec-qualification"
	input := remediation.FlowSpecQualificationInput{Profile: remediation.FlowSpecFRR1071, RoutingTable: "vrf"}
	var rejected remediation.FlowSpecQualification
	reviewer.do(t, stack, http.MethodPost, path, input, &rejected, http.StatusOK)
	if rejected.SyntaxCompatible || rejected.Template != nil || len(rejected.Findings) != 2 || rejected.ReviewFingerprint != review.Fingerprint {
		t.Fatalf("the documented FRRouting limits were not applied: %+v", rejected)
	}
	input.Profile, input.RoutingTable = remediation.FlowSpecEOS436, "default"
	available := uint32(1)
	input.AvailableEntries = &available
	var report remediation.FlowSpecQualification
	reviewer.do(t, stack, http.MethodPost, path, input, &report, http.StatusOK)
	sibling.do(t, stack, http.MethodPost, path, input, nil, http.StatusNotFound)
	if !report.SyntaxCompatible || report.ReviewFingerprint != review.Fingerprint || report.AddressFamily != "flow-spec ipv4" ||
		report.Capacity.FitsDeclared == nil || !*report.Capacity.FitsDeclared || report.Template == nil ||
		report.Template.SAFI != 133 || len(report.Template.Components) != 4 ||
		report.Template.Components[0].Value != review.Proposal.Candidate.Destination ||
		report.Template.Components[2].Value != "443" || report.Template.Components[3].Value != "42001" {
		t.Fatalf("router profile did not preserve the exact tenant review: %+v", report)
	}
	if report.QualificationFingerprint == "" {
		t.Fatal("the router profile omitted its exact qualification fingerprint")
	}
	return input, report.QualificationFingerprint
}

func assertFlowSpecReviewConsole(t *testing.T, stack *shipped.Stack, reviewer, sibling *nativeLane, title string, review remediation.FlowSpecReview) {
	t.Helper()
	spec := testsupport.RenderSpec{
		URL: stack.BaseURL + "/ui/admin", TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
		Accessibility: true, Theme: "dark",
		Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: reviewer.cookie}},
		Expect:  []string{"AI remediation proposals", title},
		Steps: []testsupport.RenderStep{{Click: "Review", Expect: []string{
			review.Proposal.Candidate.Destination, "Proposed FlowSpec match", "source port 42001",
			"Whole protected prefix", "301250 bytes", "Known benign traffic matching the proposal", "4000 packets",
			"Benign packet limit",
		}}, {Select: `select[name="flowspec-router-profile"]`, Value: string(remediation.FlowSpecEOS436)},
			{Fill: `input[name="flowspec-available-entries"]`, Value: "1"},
			{Click: "Check router profile", Expect: []string{
				"Compatible", "Declared entries meet the minimum", "flow-spec ipv4", "Router profile reference",
			}},
		},
	}
	testsupport.RenderUI(t, spec)
	spec.Theme = "light"
	testsupport.RenderUI(t, spec)
	spec.Cookies[0].Value = sibling.cookie
	spec.Expect = []string{"AI remediation proposals", "No proposals"}
	spec.Absent = []string{title, review.Proposal.Candidate.Destination}
	spec.Steps = nil
	testsupport.RenderUI(t, spec)
}
