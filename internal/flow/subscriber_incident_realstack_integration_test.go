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
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestShippedSubscriberIncidentKeepsScopedOriginalAndActions(t *testing.T) {
	st, owner, _, sibling, proposalInput, end, _ := prepareShippedRoutingReceipt(t, false)
	observation := proposalInput.PrefixImpactInput
	var original alert.DDoSEvaluationEvidence
	owner.do(t, st, http.MethodGet, "/v1/alerts/rules/"+observation.RuleID+"/ddos-receipt?fingerprint="+observation.ReceiptFingerprint, nil, &original, http.StatusOK)
	window := original.Previous.After.From
	var preview remediation.RTBHPreview
	owner.do(t, st, http.MethodPost, "/v1/remediation/rtbh-preview", proposalInput, &preview, http.StatusOK)
	var proposal remediation.Proposal
	owner.do(t, st, http.MethodPost, "/v1/remediation/rtbh-proposals", remediation.RTBHProposalInput{
		Preview: proposalInput, ObservedTo: end, PreviewFingerprint: preview.Fingerprint,
		MaxKnownBenignPackets: preview.Impact.KnownBenign.Packets,
	}, &proposal, http.StatusCreated)

	ownerView, ownerTag := prepareSubscriberIncidentUsage(t, st, owner, observation, window, end)
	foreignContext := registerShippedReviewContext(t, st, sibling, original.Previous.Before.From)
	foreignView, foreignTag := prepareSubscriberIncidentUsage(t, st, sibling, foreignContext.PrefixImpactInput, window, end)

	selection := map[string]string{"context_id": observation.ContextID, "incident_id": original.IncidentID,
		"rule_id": observation.RuleID, "receipt_fingerprint": observation.ReceiptFingerprint}
	input := map[string]any{"version": ownerView.Version, "tag_id": ownerTag, "tag_key": "subscriber", "subscriber": "alpha", "incident": selection}
	var report struct {
		flow.SubscriberUsageReport
		Incident struct {
			IncidentID     string                     `json:"incident_id"`
			EpisodeID      string                     `json:"episode_id"`
			ContextID      string                     `json:"context_id"`
			Prefix         string                     `json:"prefix"`
			From           time.Time                  `json:"from"`
			To             time.Time                  `json:"to"`
			ActionsVisible bool                       `json:"actions_visible"`
			Actions        []alert.DDoSReportDecision `json:"actions"`
		}
	}
	owner.do(t, st, http.MethodPost, subscriberUsagePath(ownerView.ID), input, &report, http.StatusOK)
	if report.Total.Bytes != "600000" || report.Incident.IncidentID != original.IncidentID || report.Incident.EpisodeID != original.EpisodeID ||
		report.Incident.ContextID != observation.ContextID || report.Incident.Prefix != original.Current.Prefix ||
		!report.Incident.From.Equal(window) || !report.Incident.To.Equal(end) || !report.Incident.ActionsVisible || len(report.Incident.Actions) != 1 ||
		report.Incident.Actions[0].ProposalID != proposal.ID || report.Incident.Actions[0].State != "proposed" {
		t.Fatal("subscriber incident lost its original scope or recorded decision", report)
	}
	proveSubscriberIncidentConsole(t, st, owner, ownerView, ownerTag, selection)
	input["subscriber"] = "beta"
	owner.do(t, st, http.MethodPost, subscriberUsagePath(ownerView.ID), input, nil, http.StatusNotFound)
	input["subscriber"] = "alpha"
	selection["context_id"] = foreignContext.ContextID
	owner.do(t, st, http.MethodPost, subscriberUsagePath(ownerView.ID), input, nil, http.StatusNotFound)
	input["version"], input["tag_id"] = foreignView.Version, foreignTag
	sibling.do(t, st, http.MethodPost, subscriberUsagePath(foreignView.ID), input, nil, http.StatusNotFound)
}

func prepareSubscriberIncidentUsage(t *testing.T, st *shipped.Stack, lane *nativeLane, observation remediation.PrefixImpactInput, from, to time.Time) (flow.SavedQueryView, string) {
	t.Helper()
	var tag struct{ ID string }
	lane.do(t, st, http.MethodPost, "/v1/tags", map[string]string{"key": "subscriber"}, &tag, http.StatusCreated)
	for _, item := range []struct{ target, value string }{{observation.ProtectedEntityID, "alpha"}, {observation.BenignEntityID, "beta"}} {
		lane.do(t, st, http.MethodPost, "/v1/entity-contexts/"+observation.ContextID+"/tag-assignments", map[string]string{
			"tag_id": tag.ID, "target_kind": "prefix", "target_id": item.target, "value": item.value,
		}, nil, http.StatusCreated)
	}
	// The same compressed history as the original deployed detector fixture.
	// All observations entered through the shipped flow collector.
	db, err := pgxpool.New(t.Context(), st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(t.Context(), `UPDATE public.entities SET updated_at=$3 WHERE tenant_id=$1 AND context_id=$2 AND kind='prefix'`,
		lane.id, observation.ContextID, from.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `UPDATE public.tenant_tag_revisions SET changed_at=$2 WHERE tenant_id=$1`, lane.id, from.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	plan := nativeGoldenPlan(lane.octet, to, []string{"dst_addr"})
	plan.From, plan.To, plan.DataSeries = from, to, "raw"
	var saved flow.SavedQueryView
	lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", flow.SaveQueryView{Definition: flow.QueryViewDefinition{
		Name: "Subscriber incident usage", Visibility: "private", Plan: plan, Time: flow.QueryViewTime{Mode: "absolute"},
	}}, &saved, http.StatusCreated)
	return saved, tag.ID
}

func proveSubscriberIncidentConsole(t *testing.T, st *shipped.Stack, lane *nativeLane, view flow.SavedQueryView, tagID string, selection map[string]string) {
	t.Helper()
	for _, theme := range []string{"light", "dark"} {
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: st.BaseURL + "/ui/explore?flow_view=" + view.ID, TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
			Accessibility: true, Theme: theme, Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
			Expect: []string{"Subscriber usage"}, Steps: []testsupport.RenderStep{
				{Click: "Open subscriber usage", Expect: []string{"Subscriber prefix tag"}},
				{Select: "label:text-is('Subscriber prefix tag') + div select", Value: tagID},
				{Fill: "label:text-is('Subscriber tag value') + div input", Value: "alpha"},
				{Click: "Include a DDoS incident", Role: "checkbox"},
				{Select: "label:text-is('Incident routing context') + div select", Value: selection["context_id"]},
				{Select: "label:text-is('Incident') + div select", Value: selection["incident_id"]},
				{Select: "label:text-is('DDoS observation') + div select", Value: selection["receipt_fingerprint"]},
				{Click: "Run subscriber report", Expect: []string{"Open incident", fmt.Sprintf("10.%d.1.0/24", lane.octet), "Recorded incident decisions", "rtbh review"}},
			},
		})
	}
}
