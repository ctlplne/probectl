// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestRTBHReviewFromShippedReceiptsKeepsIndependentTenantReview(t *testing.T) {
	stack, owner, reviewer, sibling, input, end, _ := prepareShippedRoutingReceipt(t, false)
	var catalog struct {
		Items []remediation.RTBHUpstreamTemplate `json:"items"`
	}
	owner.do(t, stack, http.MethodGet, "/v1/remediation/rtbh-templates", nil, &catalog, http.StatusOK)
	if !slices.Equal(catalog.Items, remediation.RTBHUpstreamTemplates()) {
		t.Fatal("the published template catalog did not reach the routed API", catalog.Items)
	}
	token := stack.APIToken(t, owner.cookie, "remediation.propose")
	listed := catalog
	listed.Items = nil
	stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": token}, &listed, "remediation", "rtbh-templates")
	if !slices.Equal(catalog.Items, listed.Items) {
		t.Fatal("the named CLI lost a provider, revision, or policy field", listed.Items)
	}
	template, found := remediation.RTBHUpstreamTemplateByID("hurricane-electric-transit-v1")
	if !found {
		t.Fatal("expected the published Hurricane Electric template")
	}
	var manual remediation.RTBHPreview
	owner.do(t, stack, http.MethodPost, "/v1/remediation/rtbh-preview", input, &manual, http.StatusOK)
	if manual.UpstreamTemplate != nil || manual.Fingerprint == "" {
		t.Fatal("the existing manual review lost its evidence")
	}
	input.Community, input.UpstreamTemplateID = template.Community, template.ID
	var published remediation.RTBHPreview
	owner.do(t, stack, http.MethodPost, "/v1/remediation/rtbh-preview", input, &published, http.StatusOK)
	if published.UpstreamTemplate == nil || *published.UpstreamTemplate != template ||
		published.Fingerprint == manual.Fingerprint {
		t.Fatal("the reviewed provider template was not bound to the observed source")
	}
	assertShippedReviewDecision(t, stack, owner, reviewer, sibling, input, end)
}

func prepareShippedRoutingReceipt(t *testing.T, separateControlTraffic bool) (*shipped.Stack, *nativeLane, *nativeLane, *nativeLane, remediation.RTBHPreviewInput, time.Time, string) {
	t.Helper()
	stack := shipped.Start(t, shipped.Options{Name: "routingreview", TenantBand: 4, Env: map[string]string{
		"PROBECTL_ALERT_EVAL_INTERVAL": "1s", "PROBECTL_REMEDIATION_APPROVALS_ENABLED": "true", "PROBECTL_REMEDIATION_MAX_BLAST_RADIUS": "512",
	}})
	operator := stack.OnboardOperator(t, "root@msp-routing-review.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []*nativeLane{{name: "red", octet: 183}, {name: "blue", octet: 183}}
	for _, lane := range lanes {
		lane.provision(t, stack, operator, "routing-review-"+run)
	}
	owner, sibling := lanes[0], lanes[1]
	reviewer := &nativeLane{name: "independent reviewer", id: owner.id,
		cookie: stack.SignIn(t, owner.id, "alice@acme.example", "Native red")}
	current, err := anomaly.FlowFieldCompletedWindows(flowObservationTestClock(t), anomaly.FlowFieldPreviousWeek, 300)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := anomaly.FlowFieldCompletedWindows(current.After.Start, anomaly.FlowFieldPreviousWeek, 300)
	if err != nil {
		t.Fatal(err)
	}
	var views [2]flow.SavedQueryView
	for i, lane := range lanes {
		replayOwnedIPFIXObservationVectors(t, lane, previous, current, i == 0)
		waitOwnedIPFIXObservationVectors(t, stack, lane, previous, current, i == 0)
		plan := nativeGoldenPlan(lane.octet, current.After.End, []string{"dst_addr"})
		if separateControlTraffic {
			plan.Filter.Conditions = append(plan.Filter.Conditions, flow.QueryPredicate{
				Field: "src_port", Op: flow.QueryEqual, Values: []string{"42001"},
			})
		}
		plan.From, plan.To, plan.DataSeries = current.After.Start, current.After.End, "raw"
		lane.do(t, stack, http.MethodPost, "/v1/explorer/flow-views", flow.SaveQueryView{Definition: flow.QueryViewDefinition{
			Name: "Cited protected traffic", Visibility: "tenant", Plan: plan, Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 300},
		}}, &views[i], http.StatusCreated)
	}
	input := registerShippedReviewContext(t, stack, owner, previous.Before.Start)
	input.RuleID, input.ReceiptFingerprint = assertShippedSustainedReceipt(t, stack, lanes, views, previous, current)
	whole := views[0].Definition
	whole.Name, whole.Plan.Filter = "Whole protected traffic", nil
	var wholeView flow.SavedQueryView
	owner.do(t, stack, http.MethodPost, "/v1/explorer/flow-views", flow.SaveQueryView{Definition: whole}, &wholeView, http.StatusCreated)
	input.WholeViewID, input.WholeViewVersion = wholeView.ID, wholeView.Version
	return stack, owner, reviewer, sibling, input, current.After.End, operator
}

func registerShippedReviewContext(t *testing.T, stack *shipped.Stack, owner *nativeLane, earliest time.Time) remediation.RTBHPreviewInput {
	t.Helper()
	var routing entity.ContextRecord
	owner.do(t, stack, http.MethodPost, "/v1/entity-contexts", map[string]string{"site_label": "Lab", "vrf_label": "Review"}, &routing, http.StatusCreated)
	var protected, benign entity.Record
	for _, item := range []struct {
		label, cidr string
		record      *entity.Record
	}{
		{"Protected test addresses", fmt.Sprintf("10.%d.1.0/24", owner.octet), &protected},
		{"Measured lab source", fmt.Sprintf("10.%d.30.0/24", owner.octet), &benign},
	} {
		owner.do(t, stack, http.MethodPost, "/v1/entities", map[string]string{"context_id": routing.ContextID,
			"kind": "prefix", "label": item.label, "network_prefix": item.cidr}, item.record, http.StatusCreated)
	}
	owner.do(t, stack, http.MethodPut, "/v1/entity-source-contexts", map[string]string{"context_id": routing.ContextID,
		"agent_id": owner.agent, "source_kind": "flow_exporter", "source_ref": "127.0.0.1"}, nil, http.StatusOK)
	// The lab compresses one week. Backdate only the registered source clocks
	// in this test database. Observations still enter through the shipped agent.
	db, err := pgxpool.New(t.Context(), stack.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	bound := earliest.Add(-time.Minute)
	for _, statement := range []string{
		`UPDATE public.entity_agent_contexts SET assigned_at=$4 WHERE tenant_id=$1 AND context_id=$2 AND agent_id=$3`,
		`UPDATE public.entity_source_contexts SET assigned_at=$4 WHERE tenant_id=$1 AND context_id=$2 AND agent_id=$3 AND source_kind='flow_exporter' AND source_ref='127.0.0.1'`,
	} {
		tag, err := db.Exec(t.Context(), statement, owner.id, routing.ContextID, owner.agent, bound)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("the registered test source was not bound to its original observation window", err)
		}
	}
	return remediation.RTBHPreviewInput{PrefixImpactInput: remediation.PrefixImpactInput{
		ContextID: routing.ContextID, ProtectedEntityID: protected.ID, BenignEntityID: benign.ID,
	}, Community: "64512:100", RoutingPolicyAgreed: true}
}

func assertShippedReviewDecision(t *testing.T, stack *shipped.Stack, owner, reviewer, sibling *nativeLane, input remediation.RTBHPreviewInput, end time.Time) {
	t.Helper()
	var preview remediation.RTBHPreview
	owner.do(t, stack, http.MethodPost, "/v1/remediation/rtbh-preview", input, &preview, http.StatusOK)
	sibling.do(t, stack, http.MethodPost, "/v1/remediation/rtbh-preview", input, nil, http.StatusNotFound)
	if preview.Fingerprint == "" || preview.Announcement.Prefix != fmt.Sprintf("10.%d.1.0/24", owner.octet) ||
		preview.Announcement.Community != input.Community || !preview.Impact.To.Equal(end) || !preview.Impact.Sampled ||
		preview.Impact.ObservedRecords != 1 || preview.Impact.Matched.Bytes != "300000" || preview.Impact.KnownBenign.Packets != "4000" {
		t.Fatal("the deployed scoped review changed the original traffic or exact candidate")
	}
	proposalInput := remediation.RTBHProposalInput{Preview: input, ObservedTo: end, PreviewFingerprint: preview.Fingerprint, MaxKnownBenignPackets: "3999"}
	owner.do(t, stack, http.MethodPost, "/v1/remediation/rtbh-proposals", proposalInput, nil, http.StatusConflict)
	proposalInput.MaxKnownBenignPackets = "4000"
	var proposal remediation.Proposal
	owner.do(t, stack, http.MethodPost, "/v1/remediation/rtbh-proposals", proposalInput, &proposal, http.StatusCreated)
	if proposal.State != remediation.StateProposed || proposal.DryRun.BlastRadius != 256 || proposal.Target != "" {
		t.Fatal("the deployed proposal lost its pending state, scope or privacy")
	}
	base := "/v1/remediation/proposals/" + proposal.ID
	var review remediation.RTBHReview
	reviewer.do(t, stack, http.MethodGet, base+"/routing-review", nil, &review, http.StatusOK)
	sibling.do(t, stack, http.MethodGet, base+"/routing-review", nil, nil, http.StatusNotFound)
	if review.Fingerprint == "" || review.Fingerprint == preview.Fingerprint || review.Candidate.Impact != preview.Impact || review.MaxKnownBenignPackets != "4000" {
		t.Fatal("the independent reviewer did not receive the exact bounded evidence")
	}
	if input.UpstreamTemplateID != "" && (review.Candidate.UpstreamTemplate == nil ||
		preview.UpstreamTemplate == nil || *review.Candidate.UpstreamTemplate != *preview.UpstreamTemplate) {
		t.Fatal("the independent review did not retain the exact published template")
	}
	assertShippedReviewConsole(t, stack, reviewer, sibling, proposal.Title, review)
	approve := base + "/approve"
	confirmed := map[string]string{"review_fingerprint": review.Fingerprint}
	owner.do(t, stack, http.MethodPost, approve, confirmed, nil, http.StatusForbidden)
	reviewer.do(t, stack, http.MethodPost, approve, map[string]string{"review_fingerprint": preview.Fingerprint}, nil, http.StatusConflict)
	sibling.do(t, stack, http.MethodPost, approve, confirmed, nil, http.StatusNotFound)
	reviewer.do(t, stack, http.MethodPost, approve, confirmed, &proposal, http.StatusOK)
	if proposal.State != remediation.StateApproved || proposal.DecidedBy != "user:alice@acme.example" {
		t.Fatal("the independent reviewer session did not record the approval")
	}
	reviewer.do(t, stack, http.MethodPost, approve, confirmed, nil, http.StatusConflict)
}

func assertShippedReviewConsole(t *testing.T, stack *shipped.Stack, reviewer, sibling *nativeLane, title string, review remediation.RTBHReview) {
	t.Helper()
	spec := testsupport.RenderSpec{
		URL: stack.BaseURL + "/ui/admin", TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
		Accessibility: true, Theme: "dark",
		Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: reviewer.cookie}},
		Expect:  []string{"AI remediation proposals", title},
		Steps: []testsupport.RenderStep{{Click: "Review", Expect: []string{
			"Review proposal: " + title, review.Candidate.Announcement.Prefix, review.Candidate.Announcement.Community,
			"Known benign traffic", review.Candidate.Impact.KnownBenign.Packets + " packets",
			"Benign packet limit", review.MaxKnownBenignPackets,
		}}},
	}
	if template := review.Candidate.UpstreamTemplate; template != nil {
		spec.Steps[0].Expect = append(spec.Steps[0].Expect, template.Provider)
	}
	testsupport.RenderUI(t, spec)
	spec.Theme = "light"
	spec.Cookies[0].Value = sibling.cookie
	spec.Expect = []string{"AI remediation proposals", "No proposals"}
	spec.Absent = []string{title, review.Candidate.Announcement.Prefix}
	spec.Steps = nil
	testsupport.RenderUI(t, spec)
}
