// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type subscriberIncidentSelection struct {
	reporting.DDoSReportDefinition
	ContextID string `json:"context_id"`
}

type subscriberIncidentEvidence struct {
	IncidentID     string                     `json:"incident_id"`
	EpisodeID      string                     `json:"episode_id"`
	ContextID      string                     `json:"context_id"`
	Prefix         string                     `json:"prefix"`
	Direction      string                     `json:"direction"`
	From           time.Time                  `json:"from"`
	To             time.Time                  `json:"to"`
	ActionsVisible bool                       `json:"actions_visible"`
	Actions        []alert.DDoSReportDecision `json:"actions,omitempty"`
}

type subscriberIncidentCapture struct {
	selection subscriberIncidentSelection
	evidence  subscriberIncidentEvidence
	digest    string
	origins   []store.PrefixImpactFlowBinding
	matched   *reportFlowCapture
}

func (s *Server) captureSubscriberIncident(ctx context.Context, actor *auth.Principal, input subscriberUsageRequest,
	usage flow.SubscriberUsageReport, contexts []string, budget flowstore.ExplorerBudget) (*subscriberIncidentCapture, error) {
	selection := *input.Incident
	if !slices.Contains(contexts, selection.ContextID) {
		return nil, apierror.NotFound("incident unavailable for this subscriber and routing context")
	}
	capture := &subscriberIncidentCapture{selection: selection}
	var proof alert.DDoSEvaluationEvidence
	err := tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		proof, err = s.scopedDDoSReportReceipt(ctx, sc, actor, selection.DDoSReportDefinition, budget.MemoryBytes/8)
		if err != nil {
			return err
		}
		_, capture.origins, err = s.subscriberIncidentScope(ctx, sc, actor, input, proof)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierror.NotFound("incident unavailable for this subscriber and routing context")
	}
	if err != nil {
		return nil, err
	}
	report, err := alert.SummarizeDDoSReport(proof)
	if err != nil {
		return nil, mapDDoSCoverage(err)
	}
	if report.From.Before(usage.From) || report.To.After(usage.To) {
		return nil, apierror.Conflict("choose a usage interval containing the complete incident observation")
	}
	capture.digest, err = prefixImpactDigest(proof)
	if err != nil {
		return nil, err
	}
	capture.matched, err = s.captureMatchedDDoSOrigins(ctx, actor, selection.RuleID, proof, capture.origins, budget)
	if err != nil {
		return nil, err
	}
	capture.evidence = subscriberIncidentEvidence{IncidentID: report.IncidentID, EpisodeID: report.EpisodeID,
		ContextID: selection.ContextID, Prefix: report.Prefix, Direction: report.Direction, From: report.From, To: report.To}
	return capture, nil
}

func (s *Server) subscriberIncidentScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, input subscriberUsageRequest,
	proof alert.DDoSEvaluationEvidence) (entity.ContextRecord, []store.PrefixImpactFlowBinding, error) {
	var record entity.ContextRecord
	authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return record, nil, err
	}
	ctx, principal, err := authority.requestContext(ctx, actor)
	if err != nil {
		return record, nil, err
	}
	record, err = store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, input.Incident.ContextID)
	if err != nil {
		return record, nil, err
	}
	if err := s.authorizeFlowRoutingContext(ctx, principal, record); err != nil {
		return record, nil, err
	}
	resource := entityContextResource(record)
	resource["incident_id"], resource["rule_id"] = input.Incident.IncidentID, input.Incident.RuleID
	for _, permission := range []string{permIncidentRead, permAlertRead} {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
			return record, nil, err
		}
	}
	prefix, err := netip.ParsePrefix(proof.Current.Prefix)
	if err != nil {
		return record, nil, mapDDoSCoverage(err)
	}
	owned, err := store.SubscriberOwnsProtectedPrefixInScope(ctx, sc, record.ContextID, input.TagID, input.Subscriber, prefix)
	if err != nil {
		return record, nil, err
	}
	if !owned {
		return record, nil, apierror.NotFound("incident unavailable for this subscriber and routing context")
	}
	origins, err := store.PrefixImpactFlowBindingsInScope(ctx, sc, record.ContextID, proof.Previous.Before.From)
	if errors.Is(err, store.ErrPrefixImpactSources) {
		return record, nil, apierror.Conflict("complete original exporter bindings are required for the selected routing context")
	}
	return record, origins, err
}

func (s *Server) attachSubscriberIncident(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, input subscriberUsageRequest,
	capture *subscriberIncidentCapture, memory int64) (*subscriberIncidentEvidence, error) {
	if capture == nil {
		return nil, nil
	}
	proof, err := s.scopedDDoSReportReceipt(ctx, sc, actor, capture.selection.DDoSReportDefinition, memory)
	if err != nil {
		return nil, err
	}
	digest, err := prefixImpactDigest(proof)
	if err != nil || digest != capture.digest {
		return nil, apierror.Conflict("the cited incident receipt changed during generation").Wrap(err)
	}
	record, origins, err := s.subscriberIncidentScope(ctx, sc, actor, input, proof)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(origins, capture.origins) {
		return nil, apierror.Conflict("the selected incident exporter bindings changed during generation")
	}
	if err := s.validateReportSourcePublication(ctx, sc, actor, capture.matched); err != nil {
		return nil, err
	}
	evidence := capture.evidence
	evidence.Actions, evidence.ActionsVisible, err = s.scopedDDoSReportPackDecisions(ctx, sc, actor, capture.selection.DDoSReportDefinition, &record)
	if errors.Is(err, alert.ErrQueryGroups) {
		return nil, apierror.Conflict("the selected incident has more decisions than the report can include")
	}
	return &evidence, err
}
