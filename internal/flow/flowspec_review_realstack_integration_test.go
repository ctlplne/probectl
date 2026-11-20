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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestFlowSpecReviewUsesOwnedMatchesAndIndependentApproval(t *testing.T) {
	stack, owner, reviewer, sibling, scoped, end := prepareShippedRoutingReceipt(t, true)
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
	proposeFlowSpecAndApprove(t, stack, owner, reviewer, sibling, input, preview)
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
	assertFlowSpecReviewConsole(t, stack, reviewer, sibling, proposal.Title, review)
	exact := map[string]string{"review_fingerprint": review.Fingerprint}
	approve := base + "/flowspec-approve"
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
		"--session-cookie-file", sessionFile, "--body-file", stack.SecretFile(t, exact))
	if proposal.State != remediation.StateApproved || proposal.DecidedBy != "user:alice@acme.example" {
		t.Fatal("the independent reviewer session did not record the exact approval")
	}
	reviewer.do(t, stack, http.MethodPost, approve, exact, nil, http.StatusConflict)
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
		}}},
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
