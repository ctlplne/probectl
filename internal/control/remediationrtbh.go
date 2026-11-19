// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"math"
	"math/big"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) handleRTBHPreview(w http.ResponseWriter, r *http.Request) error {
	svc, err := s.remediationSvc()
	if err != nil {
		return err
	}
	preview, installed := svc.(remediation.RTBHPreviewer)
	if !installed {
		return apierror.NotFound("traffic review is unavailable")
	}
	tenant, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var input remediation.RTBHPreviewInput
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	actor := auth.PrincipalFrom(r.Context())
	result, err := preview.PreviewRTBH(r.Context(), tenant, input, s.pathAlertRequestCredential(r, actor))
	if err != nil {
		if _, typed := apierror.As(err); typed {
			return err
		}
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

type prefixImpactInventory struct {
	protected entity.Record
	benign    entity.Record
	origins   []store.PrefixImpactFlowBinding
}

type prefixImpactCapture struct {
	view    reportFlowSourceRef
	prefix  netip.Prefix
	width   time.Duration
	origins []store.PrefixImpactFlowBinding
}

func (c prefixImpactCapture) preparePlan(plan *flow.QueryPlan) error {
	if plan.Filter != nil || plan.To.Sub(plan.From) != c.width || plan.Cursor != "" {
		return apierror.Validation("the whole-prefix view needs an unfiltered moving lookback matching the cited window")
	}
	if len(c.origins) == 0 {
		return apierror.Conflict("the routing context has no complete current flow exporter bindings")
	}
	plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "dst_addr", Op: flow.QueryCIDR, Values: []string{c.prefix.String()}}},
		Groups: []flow.QueryFilterGroup{prefixImpactSenderGroup(c.origins)}}
	plan.View, plan.DataSeries = "table", "raw"
	plan.GroupBy, plan.MatrixWith = []string{"agent_id", "exporter", "dst_addr", "src_addr", "sampling"}, nil
	plan.Metrics = []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"},
		{Measure: "packets", Calculation: "total", Role: "additional"}, {Measure: "flows", Calculation: "total", Role: "additional"}}
	plan.RowLimit, plan.PageSize = 25, 25
	return nil
}

func prefixImpactSenderGroup(origins []store.PrefixImpactFlowBinding) flow.QueryFilterGroup {
	assigned := flow.QueryFilterGroup{Mode: "include", Match: "any", Groups: make([]flow.QueryFilterGroup, 0, len(origins))}
	for _, origin := range origins {
		assigned.Groups = append(assigned.Groups, flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "agent_id", Op: flow.QueryEqual, Values: []string{origin.AgentID}},
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{origin.Exporter.String()}},
		}})
	}
	return assigned
}

// ObservePrefixImpact measures the whole observed destination scope using the
// current tenant's original flow rows and configured prefix identities.
func (s *Server) ObservePrefixImpact(ctx context.Context, tenantID string, input remediation.PrefixImpactInput,
	credential func(context.Context) error) (remediation.PrefixImpact, error) {
	var empty remediation.PrefixImpact
	actor := auth.PrincipalFrom(ctx)
	if actor == nil || actor.UserID == "" || actor.TenantID == "" || actor.TenantID != tenantID || credential == nil {
		return empty, apierror.Forbidden("current traffic review identity is unavailable")
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != tenantID {
		return empty, tenancy.ErrNoTenant
	}
	if s.pool == nil || s.flowQueryViews == nil || s.fairnessGate == nil {
		return empty, apierror.Unavailable("traffic review source admission is unavailable")
	}
	for _, id := range []string{input.RuleID, input.ContextID, input.ProtectedEntityID, input.BenignEntityID, input.WholeViewID} {
		if !reportRequirementUUID(id) {
			return empty, apierror.Validation("the incident, routing context and exact source identities are required")
		}
	}
	if input.ProtectedEntityID == input.BenignEntityID || !alert.ValidFieldDigest(input.ReceiptFingerprint) {
		return empty, apierror.Validation("the original receipt and both prefix identities are required")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	proof, err := s.readAlertDDoSReceipt(ctx, actor, input.RuleID, input.ReceiptFingerprint, credential, nil)
	if err != nil {
		return empty, err
	}
	width := proof.Current.After.To.Sub(proof.Current.After.From)
	if width != time.Minute && width != 2*time.Minute && width != 5*time.Minute {
		return empty, apierror.Conflict("the original traffic clock is unavailable")
	}
	windows, err := anomaly.FlowFieldCompletedWindows(time.Now(), anomaly.FlowFieldPreviousWeek, int(width/time.Second))
	if err != nil {
		return empty, err
	}
	inventory, err := s.readPrefixImpactInventory(ctx, actor, input, proof.Previous.Before.From)
	if err != nil {
		return empty, err
	}
	protected, err := netip.ParsePrefix(inventory.protected.NetworkPrefix)
	if err != nil || protected.Bits() < 1 || protected.String() != proof.Current.Prefix || proof.Current.Direction != "ingress" {
		return empty, apierror.Conflict("the configured protected prefix must match the cited ingress finding")
	}
	benign, err := netip.ParsePrefix(inventory.benign.NetworkPrefix)
	if err != nil || benign.Bits() < 1 || benign.Addr().BitLen() != protected.Addr().BitLen() {
		return empty, apierror.Validation("the known benign prefix must use the protected prefix address family")
	}
	settings := prefixImpactCapture{view: reportFlowSourceRef{ID: input.WholeViewID, Version: input.WholeViewVersion}, prefix: protected, width: width, origins: inventory.origins}
	capture, err := s.captureFlowSourcesWithOptions(ctx, actor, []reportFlowSourceRef{settings.view}, true, false, reportFlowCaptureOptions{
		SeasonalPeriodEnds: []time.Time{windows.After.End}, CombineSeasonal: true, PrefixImpact: &settings, ReservedMemoryBytes: budget.MemoryBytes / 4,
	})
	if err != nil {
		return empty, err
	}
	defer capture.Close()
	if len(capture.Results) != 1 || !matchFlowEvidenceClocks(capture.Inputs, settings.view, []time.Time{windows.After.End}, width) {
		return empty, apierror.Conflict("complete observations for the whole protected prefix are required")
	}
	impact, err := projectPrefixImpact(ctx, capture.Results[0], settings, benign, budget.MemoryBytes/8)
	if err != nil {
		return empty, mapDDoSCoverage(err)
	}
	capture.Results = nil
	capture.Close()
	if err := s.verifyPrefixImpactDetector(ctx, actor, input.RuleID, proof, inventory.origins, budget); err != nil {
		return empty, err
	}
	if err := s.recheckFlowEvidencePublication(ctx, actor, capture); err != nil {
		return empty, err
	}
	current, err := s.readPrefixImpactInventory(ctx, actor, input, proof.Previous.Before.From)
	if err != nil {
		return empty, err
	}
	if !current.protected.UpdatedAt.Equal(inventory.protected.UpdatedAt) || !current.benign.UpdatedAt.Equal(inventory.benign.UpdatedAt) ||
		!slices.EqualFunc(current.origins, inventory.origins, func(a, b store.PrefixImpactFlowBinding) bool {
			return a.AgentID == b.AgentID && a.Exporter == b.Exporter && a.Since.Equal(b.Since)
		}) {
		return empty, apierror.Conflict("the configured routing prefixes or exporter bindings changed during the review")
	}
	if _, err := s.readAlertDDoSReceipt(ctx, actor, input.RuleID, input.ReceiptFingerprint, credential, nil); err != nil {
		return empty, err
	}
	return impact, ctx.Err()
}

func (s *Server) readPrefixImpactInventory(ctx context.Context, actor *auth.Principal, input remediation.PrefixImpactInput, from time.Time) (prefixImpactInventory, error) {
	var result prefixImpactInventory
	registry := store.NewEntityRegistry(s.pool)
	err := tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		contextRecord, err := registry.GetEntityContextInScope(ctx, sc, input.ContextID)
		if err != nil {
			return err
		}
		if err := s.authorizeFlowRoutingContext(ctx, principal, contextRecord); err != nil {
			return err
		}
		scope := entity.Scope{TenantID: sc.Tenant.String(), ContextID: input.ContextID}
		result.protected, err = registry.GetEntityInScope(ctx, sc, scope, input.ProtectedEntityID)
		if err != nil {
			return err
		}
		result.benign, err = registry.GetEntityInScope(ctx, sc, scope, input.BenignEntityID)
		if err != nil {
			return err
		}
		if result.protected.Kind != entity.Prefix || result.benign.Kind != entity.Prefix || result.protected.NetworkPrefix == "" || result.benign.NetworkPrefix == "" {
			return apierror.Validation("the routing context needs configured protected and known benign network prefixes")
		}
		result.origins, err = store.PrefixImpactFlowBindingsInScope(ctx, sc, input.ContextID, from)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return prefixImpactInventory{}, apierror.NotFound("routing review scope not found")
	}
	if errors.Is(err, store.ErrPrefixImpactSources) {
		return prefixImpactInventory{}, apierror.Conflict("complete current exporter bindings are required for the entire routing scope")
	}
	return result, err
}

type prefixImpactTotals struct {
	bytes, packets, benignBytes, benignPackets big.Int
	records                                    int
	sampled                                    bool
	addresses                                  map[netip.Addr]struct{}
}

func projectPrefixImpact(ctx context.Context, captured capturedReportFlow, settings prefixImpactCapture, benign netip.Prefix, memory int64) (remediation.PrefixImpact, error) {
	var empty remediation.PrefixImpact
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != captured.TenantID {
		return empty, tenancy.ErrNoTenant
	}
	result := captured.Result
	if result.Source != "raw" || result.Coverage == nil || !result.Coverage.CompleteInputs || result.OldestInput.IsZero() ||
		result.DetailLimited || result.Other != nil || len(result.Rows) == 0 || int64(len(result.Rows)) > memory/512 {
		return empty, anomaly.ErrDDoSCoverage
	}
	totals := prefixImpactTotals{addresses: make(map[netip.Addr]struct{})}
	origins := make(map[store.PrefixImpactFlowBinding]bool, len(settings.origins))
	for _, origin := range settings.origins {
		origins[store.PrefixImpactFlowBinding{AgentID: origin.AgentID, Exporter: origin.Exporter}] = true
	}
	for _, row := range result.Rows {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		exporter, err := netip.ParseAddr(row.Group["exporter"])
		if err != nil || !origins[store.PrefixImpactFlowBinding{AgentID: row.Group["agent_id"], Exporter: exporter.Unmap()}] {
			return empty, anomaly.ErrDDoSCoverage
		}
		if err := totals.add(row, settings.prefix, benign); err != nil {
			return empty, err
		}
	}
	return remediation.PrefixImpact{Prefix: settings.prefix.String(), From: result.Query.From, To: result.Query.To, Sampled: totals.sampled,
		ObservedRecords: totals.records, ObservedAddresses: len(totals.addresses),
		Matched:     remediation.PrefixTraffic{Bytes: totals.bytes.String(), Packets: totals.packets.String()},
		KnownBenign: remediation.PrefixTraffic{Bytes: totals.benignBytes.String(), Packets: totals.benignPackets.String()},
		Unclassified: remediation.PrefixTraffic{Bytes: new(big.Int).Sub(&totals.bytes, &totals.benignBytes).String(),
			Packets: new(big.Int).Sub(&totals.packets, &totals.benignPackets).String()}}, ctx.Err()
}

func (totals *prefixImpactTotals) add(row flowstore.PlanRow, protected, benign netip.Prefix) error {
	source, srcErr := netip.ParseAddr(row.Group["src_addr"])
	destination, dstErr := netip.ParseAddr(row.Group["dst_addr"])
	sampling, sampleErr := strconv.ParseUint(row.Group["sampling"], 10, 64)
	records, countErr := strconv.Atoi(row.Metrics["flows:total"])
	amount, byteOK := ddosWindowCounter(row.Metrics["bytes:total"])
	packets, packetOK := ddosWindowCounter(row.Metrics["packets:total"])
	if row.Other || srcErr != nil || dstErr != nil || !protected.Contains(destination) || sampleErr != nil || sampling == 0 ||
		countErr != nil || records < 1 || records > math.MaxInt-totals.records || !byteOK || !packetOK {
		return anomaly.ErrDDoSCoverage
	}
	totals.bytes.Add(&totals.bytes, amount)
	totals.packets.Add(&totals.packets, packets)
	if benign.Contains(source) {
		totals.benignBytes.Add(&totals.benignBytes, amount)
		totals.benignPackets.Add(&totals.benignPackets, packets)
	}
	totals.sampled = totals.sampled || sampling > 1
	totals.records += records
	totals.addresses[destination] = struct{}{}
	return nil
}
