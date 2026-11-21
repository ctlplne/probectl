// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"net/netip"
	"slices"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) handleIncidentDDoSReport(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return apierror.Unauthorized("tenant identity required")
	}
	id := r.PathValue("id")
	if !reportRequirementUUID(id) {
		return apierror.Validation("select an incident for the traffic report")
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.Incidents{}).Get(ctx, sc, id)
		return err
	}); err != nil {
		return err
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(actor.TenantID))
	ruleID, fingerprint := r.URL.Query().Get("rule_id"), r.URL.Query().Get("fingerprint")
	credential := s.pathAlertRequestCredential(r, actor)
	receipt, err := s.readAlertDDoSReceipt(ctx, actor, ruleID, fingerprint, credential, nil)
	if err != nil {
		return err
	}
	if receipt.IncidentID != id {
		return apierror.NotFound("traffic assessment receipt not found in this incident")
	}
	report, err := alert.SummarizeDDoSReport(receipt)
	if err != nil {
		return mapDDoSCoverage(err)
	}
	report.TopSources, err = s.readIncidentDDoSTopSources(ctx, actor, ruleID, receipt)
	if err != nil {
		return err
	}
	if err := s.readIncidentDDoSDecisions(r, actor, ruleID, fingerprint, &report); err != nil {
		return err
	}
	current, err := s.readAlertDDoSReceipt(ctx, actor, ruleID, fingerprint, credential, nil)
	if err != nil {
		return err
	}
	original, err := prefixImpactDigest(receipt)
	if err != nil {
		return err
	}
	latest, err := prefixImpactDigest(current)
	if err != nil || original != latest {
		return apierror.Conflict("the traffic assessment receipt changed during report publication").Wrap(err)
	}
	writeJSON(w, http.StatusOK, report)
	return nil
}

func (s *Server) readIncidentDDoSTopSources(ctx context.Context, actor *auth.Principal, ruleID string, proof alert.DDoSEvaluationEvidence) ([]alert.DDoSReportSource, error) {
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	settings, err := s.citedDDoSSettings(ctx, ruleID, proof, budget.MemoryBytes/8)
	if err != nil {
		return nil, err
	}
	clocks, err := citedDDoSClocks(proof, settings)
	if err != nil {
		return nil, err
	}
	settings.IncludeSources, settings.Cited = true, true
	capture, err := s.captureDDoSWindows(ctx, actor, settings, clocks.ends(), budget.MemoryBytes/4)
	if err != nil {
		return nil, err
	}
	defer capture.Close()
	prior, err := assessCapturedDDoS(ctx, capture, settings, clocks.Previous, 0, 2, budget.MemoryBytes/8)
	if err != nil {
		return nil, mapDDoSCoverage(err)
	}
	current, err := assessCapturedDDoS(ctx, capture, settings, clocks.Current, 1, 3, budget.MemoryBytes/8)
	if err != nil {
		return nil, mapDDoSCoverage(err)
	}
	if !sameDDoSRoutingEvidence(proof.Previous, prior) || !sameDDoSRoutingEvidence(proof.Current, current) {
		return nil, apierror.Conflict("the current flows no longer match the original traffic assessment")
	}
	top, err := projectDDoSTopSources(ctx, capture.Results[2].Result.Rows, capture.Results[3].Result.Rows, budget.MemoryBytes/8)
	if err != nil {
		return nil, mapDDoSCoverage(err)
	}
	if err := s.recheckFlowEvidencePublication(ctx, actor, capture); err != nil {
		return nil, err
	}
	return top, ctx.Err()
}

type ddosReportSourceCounters struct {
	addr           netip.Addr
	bytes, packets big.Int
}

func projectDDoSTopSources(ctx context.Context, prior, current []flowstore.PlanRow, memory int64) ([]alert.DDoSReportSource, error) {
	if int64(len(prior))+int64(len(current)) > memory/512 {
		return nil, anomaly.ErrDDoSCoverage
	}
	totals := make(map[netip.Addr]*ddosReportSourceCounters)
	for _, rows := range [2][]flowstore.PlanRow{prior, current} {
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			address, err := netip.ParseAddr(row.Group["src_addr"])
			bytes, byteOK := ddosWindowCounter(row.Metrics["bytes:total"])
			packets, packetOK := ddosWindowCounter(row.Metrics["packets:total"])
			if row.Other || err != nil || address.Is4In6() || !byteOK || !packetOK {
				return nil, anomaly.ErrDDoSCoverage
			}
			total := totals[address]
			if total == nil {
				total = &ddosReportSourceCounters{addr: address}
				totals[address] = total
			}
			total.bytes.Add(&total.bytes, bytes)
			total.packets.Add(&total.packets, packets)
		}
	}
	var ranked []*ddosReportSourceCounters
	for _, total := range totals {
		ranked = append(ranked, total)
	}
	slices.SortFunc(ranked, func(a, b *ddosReportSourceCounters) int {
		if byBytes := b.bytes.Cmp(&a.bytes); byBytes != 0 {
			return byBytes
		}
		return a.addr.Compare(b.addr)
	})
	out := make([]alert.DDoSReportSource, 0, min(20, len(ranked)))
	for _, total := range ranked[:min(20, len(ranked))] {
		out = append(out, alert.DDoSReportSource{Address: total.addr.String(), Bytes: total.bytes.String(), Packets: total.packets.String()})
	}
	return out, ctx.Err()
}

func (s *Server) readIncidentDDoSDecisions(r *http.Request, actor *auth.Principal, ruleID, fingerprint string, report *alert.DDoSReport) error {
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, current, err := authority.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, current, permRemediationPropose, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}); err != nil {
			if typed, ok := apierror.As(err); ok && typed.Kind == apierror.KindForbidden {
				return nil
			}
			return err
		}
		report.Actions, err = store.DDoSReportDecisions(ctx, sc, report.IncidentID, ruleID, fingerprint, "")
		report.ActionsVisible = err == nil
		return err
	})
	if errors.Is(err, alert.ErrQueryGroups) {
		return apierror.Conflict("the incident contains more decisions than this report can include")
	}
	return err
}
