// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ddosReportPackRequirements struct {
	Selection      reporting.DDoSReportDefinition `json:"selection"`
	ReceiptDigest  string                         `json:"receipt_digest"`
	DecisionDigest string                         `json:"decision_digest,omitempty"`
	ObservedFrom   time.Time                      `json:"observed_from"`
	ObservedTo     time.Time                      `json:"observed_to"`
}

func validDDoSReportSelection(selection reporting.DDoSReportDefinition) bool {
	return reportRequirementUUID(selection.IncidentID) && reportRequirementUUID(selection.RuleID) && alert.ValidFieldDigest(selection.ReceiptFingerprint)
}

func cleanDDoSReportDefinition(definition dashboardDefinition) error {
	if definition.DDoSReport == nil {
		return nil
	}
	if !validDDoSReportSelection(*definition.DDoSReport) {
		return apierror.Validation("select an incident and exact traffic assessment receipt")
	}
	if definition.ClientReport != nil || definition.CarrierClaim != nil || definition.ComplianceControl != "" ||
		definition.ComplianceFlow != nil || len(definition.FlowSources) != 0 || len(definition.Metrics) != 0 ||
		!definition.AbsoluteFrom.IsZero() || !definition.AbsoluteTo.IsZero() {
		return apierror.Validation("the traffic report uses the exact incident observation interval and sources")
	}
	return nil
}

// Use ordinary metadata reads under the report publisher's existing tenant
// audit lock. Alert writers acquire the rule row before that audit lock.
func (s *Server) scopedDDoSReportReceipt(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, selection reporting.DDoSReportDefinition, memory int64) (alert.DDoSEvaluationEvidence, error) {
	var empty alert.DDoSEvaluationEvidence
	if actor == nil || actor.TenantID != sc.Tenant.String() || !validDDoSReportSelection(selection) {
		return empty, apierror.Forbidden("traffic report source scope is unavailable")
	}
	authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return empty, err
	}
	ctx, current, err := authority.requestContext(ctx, actor)
	if err != nil {
		return empty, err
	}
	resource := map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}
	for _, permission := range []string{permIncidentRead, permAlertRead} {
		if err := s.authorize(ctx, current, permission, auth.RBACGlobal, resource); err != nil {
			return empty, err
		}
	}
	if _, err := (store.Incidents{}).Get(ctx, sc, selection.IncidentID); err != nil {
		return empty, err
	}
	rules := store.AlertRules{}
	rule, err := rules.Get(ctx, sc, selection.RuleID)
	if err != nil {
		return empty, err
	}
	source, err := rules.GetQuerySource(ctx, sc, selection.RuleID, rule.UpdatedAt, memory)
	if err != nil {
		return empty, err
	}
	if source == nil || source.Source.Condition.Mode != alert.DDoSCondition || source.Source.Condition.DDoS == nil {
		return empty, apierror.NotFound("traffic assessment receipt not found")
	}
	record, err := (store.AlertEvaluations{}).GetFlowReceipt(ctx, sc, store.AlertDDoSReceipt, selection.RuleID, selection.ReceiptFingerprint, rule.UpdatedAt, memory)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrAlertQueryChanged) {
		return empty, apierror.NotFound("traffic assessment receipt not found")
	}
	if err != nil {
		return empty, err
	}
	receipt, bound, err := decodeDDoSReceipt(ctx, record, source.Source.Binding(sc.Tenant.String(), selection.RuleID), rule.UpdatedAt, selection.ReceiptFingerprint, memory)
	if err != nil {
		return empty, err
	}
	if receipt.Evidence.IncidentID != selection.IncidentID {
		return empty, apierror.NotFound("traffic assessment receipt not found in this incident")
	}
	if err := s.validateReportSourcePublication(ctx, sc, current, bound); err != nil {
		return empty, err
	}
	return receipt.Evidence, nil
}

func (s *Server) captureDDoSReportPack(ctx context.Context, actor *auth.Principal, selection reporting.DDoSReportDefinition, at time.Time) (*reportFlowCapture, error) {
	if s.pool == nil || s.fairnessGate == nil {
		return nil, apierror.Unavailable("traffic report admission is unavailable")
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || actor.TenantID != tenant.String() || !validDDoSReportSelection(selection) {
		return nil, apierror.Forbidden("traffic report source scope is unavailable")
	}
	budget, err := s.sourceReportBudget()
	if err != nil {
		return nil, err
	}
	var proof alert.DDoSEvaluationEvidence
	var decisions []alert.DDoSReportDecision
	var actionsVisible bool
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		proof, err = s.scopedDDoSReportReceipt(ctx, sc, actor, selection, budget.MemoryBytes/8)
		if err != nil {
			return err
		}
		decisions, actionsVisible, err = s.scopedDDoSReportPackDecisions(ctx, sc, actor, selection)
		return err
	})
	if err != nil {
		return nil, err
	}
	report, err := alert.SummarizeDDoSReport(proof)
	if err != nil {
		return nil, mapDDoSCoverage(err)
	}
	report.TopSources, err = s.readIncidentDDoSTopSources(ctx, actor, selection.RuleID, proof)
	if err != nil {
		return nil, err
	}
	report.Actions, report.ActionsVisible = decisions, actionsVisible
	requirements := &ddosReportPackRequirements{Selection: selection, ObservedFrom: report.From, ObservedTo: report.To}
	requirements.ReceiptDigest, err = prefixImpactDigest(proof)
	if err != nil {
		return nil, err
	}
	if actionsVisible {
		requirements.DecisionDigest, err = prefixImpactDigest(decisions)
		if err != nil {
			return nil, err
		}
	}
	return &reportFlowCapture{TenantID: tenant.String(), ObservedAt: at.UTC(), DDoSReport: requirements, Tables: ddosReportPackTables(tenant.String(), report)}, nil
}

func (s *Server) scopedDDoSReportPackDecisions(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, selection reporting.DDoSReportDefinition) ([]alert.DDoSReportDecision, bool, error) {
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return nil, false, err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return nil, false, err
	}
	resource := map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}
	// A scoped audit reader is already allowed to read these recorded decisions.
	// The worker uses that read-only grant. An interactive reviewer can also use
	// the existing remediation permission when no audit grant is available.
	if err := s.authorize(ctx, principal, permAuditRead, auth.RBACGlobal, resource); err != nil {
		if typed, ok := apierror.As(err); !ok || typed.Kind != apierror.KindForbidden {
			return nil, false, err
		}
		if err := s.authorize(ctx, principal, permRemediationPropose, auth.RBACGlobal, resource); err != nil {
			if typed, ok := apierror.As(err); ok && typed.Kind == apierror.KindForbidden {
				return nil, false, nil
			}
			return nil, false, err
		}
	}
	decisions, err := store.DDoSReportDecisions(ctx, sc, selection.IncidentID, selection.RuleID, selection.ReceiptFingerprint)
	return decisions, true, err
}

func (s *Server) validateDDoSReportPackScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, value *ddosReportPackRequirements, publication bool) error {
	if value == nil {
		return errReportSourceRequirements
	}
	budget, err := s.sourceReportBudget()
	if err != nil {
		return err
	}
	proof, err := s.scopedDDoSReportReceipt(ctx, sc, actor, value.Selection, budget.MemoryBytes/8)
	if err != nil {
		return err
	}
	digest, err := prefixImpactDigest(proof)
	if err != nil || digest != value.ReceiptDigest {
		return apierror.Conflict("traffic report receipt changed").Wrap(err)
	}
	if value.DecisionDigest == "" {
		return ctx.Err()
	}
	decisions, visible, err := s.scopedDDoSReportPackDecisions(ctx, sc, actor, value.Selection)
	if err != nil {
		return err
	}
	if !visible {
		return apierror.Forbidden("traffic report decisions are unavailable to the current reader")
	}
	if publication {
		current, err := prefixImpactDigest(decisions)
		if err != nil || current != value.DecisionDigest {
			return apierror.Conflict("traffic report decisions changed during publication").Wrap(err)
		}
	}
	return ctx.Err()
}

func ddosReportPackTables(tenant string, report alert.DDoSReport) []reporting.CSVTable {
	table := func(key, title string, names []string, rows [][]string) reporting.CSVTable {
		out := sealedClientReportTable(tenant, key, title, report.From, report.To, plainClientReportColumns(names), rows)
		out.Source = "exact tenant traffic assessment receipt and retained source observations"
		return out
	}
	windows := make([][]string, 0, len(report.Windows))
	for _, window := range report.Windows {
		fact := window.Evidence
		windows = append(windows, []string{fact.From.Format(time.RFC3339Nano), fact.To.Format(time.RFC3339Nano), string(window.Vector),
			window.Service, window.Confidence, fact.Bytes, fact.Packets, strconv.Itoa(fact.ObservedRecords), strconv.FormatBool(fact.Sampled), fact.Citation})
	}
	var sources [][]string
	for _, source := range report.TopSources {
		sources = append(sources, []string{source.Address, source.Bytes, source.Packets})
	}
	out := []reporting.CSVTable{
		table("ddos-summary", "Observed DDoS incident", []string{"incident", "episode", "prefix", "direction", "observed_seconds", "decisions_visible"},
			[][]string{{report.IncidentID, report.EpisodeID, report.Prefix, report.Direction, strconv.FormatInt(report.ObservedSeconds, 10), strconv.FormatBool(report.ActionsVisible)}}),
		table("ddos-windows", "Observed traffic windows", []string{"from", "to", "vector", "service", "confidence", "bytes", "packets", "records", "sampled", "citation"}, windows),
		table("ddos-peak-rates", "Peak observed window averages", []string{"unit", "numerator", "observed_seconds", "per_second", "from", "to"},
			[][]string{ddosReportRateRow("bits", report.PeakBitRate), ddosReportRateRow("packets", report.PeakPacketRate)}),
		table("ddos-top-sources", "Top observed sources", []string{"source_address", "bytes", "packets"}, sources),
	}
	if report.ActionsVisible {
		var actions [][]string
		for _, action := range report.Actions {
			var decided string
			if action.DecidedAt != nil {
				decided = action.DecidedAt.Format(time.RFC3339Nano)
			}
			actions = append(actions, []string{action.ProposalID, action.Kind, action.State, action.CreatedAt.Format(time.RFC3339Nano), decided})
		}
		out = append(out, table("ddos-decisions", "Recorded mitigation decisions", []string{"proposal", "kind", "state", "created_at", "decided_at"}, actions))
	}
	return out
}

func ddosReportRateRow(unit string, rate alert.DDoSReportRate) []string {
	return []string{unit, rate.Count, strconv.FormatInt(rate.Seconds, 10), rate.PerSecond, rate.From.Format(time.RFC3339Nano), rate.To.Format(time.RFC3339Nano)}
}
