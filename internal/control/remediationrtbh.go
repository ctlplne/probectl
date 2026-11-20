// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
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
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) handleRTBHUpstreamTemplates(w http.ResponseWriter, r *http.Request) error {
	svc, err := s.remediationSvc()
	if err != nil {
		return err
	}
	if _, installed := svc.(remediation.RTBHPreviewer); !installed {
		return apierror.NotFound("traffic review is unavailable")
	}
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, struct {
		Items []remediation.RTBHUpstreamTemplate `json:"items"`
	}{remediation.RTBHUpstreamTemplates()})
	return nil
}

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

func (s *Server) handleFlowSpecPreview(w http.ResponseWriter, r *http.Request) error {
	svc, err := s.remediationSvc()
	if err != nil {
		return err
	}
	preview, installed := svc.(remediation.FlowSpecPreviewer)
	if !installed {
		return apierror.NotFound("traffic review is unavailable")
	}
	tenant, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var input remediation.FlowSpecPreviewInput
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	actor := auth.PrincipalFrom(r.Context())
	result, err := preview.PreviewFlowSpec(r.Context(), tenant, input, s.pathAlertRequestCredential(r, actor))
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
	view      reportFlowSourceRef
	prefix    netip.Prefix
	width     time.Duration
	origins   []store.PrefixImpactFlowBinding
	transport *remediation.FlowSpecTransport
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
	if c.transport != nil {
		plan.GroupBy = append(plan.GroupBy, "transport")
		if c.transport.SourcePort != nil {
			plan.GroupBy = append(plan.GroupBy, "src_port")
		}
		if c.transport.DestinationPort != nil {
			plan.GroupBy = append(plan.GroupBy, "dst_port")
		}
	}
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
	prepared, err := s.PreparePrefixImpact(ctx, tenantID, input, time.Time{}, credential)
	return prepared.Impact, err
}

func (s *Server) PreparePrefixImpact(ctx context.Context, tenantID string, input remediation.PrefixImpactInput,
	observedTo time.Time, credential func(context.Context) error) (remediation.RTBHImpactPublication, error) {
	return s.prepareRoutingImpact(ctx, tenantID, input, nil, observedTo, credential)
}

func (s *Server) PrepareFlowSpecImpact(ctx context.Context, tenantID string, input remediation.PrefixImpactInput,
	transport remediation.FlowSpecTransport, observedTo time.Time, credential func(context.Context) error) (remediation.RTBHImpactPublication, error) {
	if err := transport.Validate(); err != nil {
		return remediation.RTBHImpactPublication{}, err
	}
	return s.prepareRoutingImpact(ctx, tenantID, input, &transport, observedTo, credential)
}

func (s *Server) prepareRoutingImpact(ctx context.Context, tenantID string, input remediation.PrefixImpactInput,
	transport *remediation.FlowSpecTransport, observedTo time.Time, credential func(context.Context) error) (remediation.RTBHImpactPublication, error) {
	var empty remediation.RTBHImpactPublication
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
	if observedTo.IsZero() {
		observedTo = windows.After.End
	}
	observedTo = observedTo.UTC()
	if !observedTo.Truncate(width).Equal(observedTo) || observedTo.After(windows.After.End) || windows.After.End.Sub(observedTo) > 10*time.Minute {
		return empty, apierror.Conflict("the selected traffic review window is unavailable")
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
	settings := prefixImpactCapture{view: reportFlowSourceRef{ID: input.WholeViewID, Version: input.WholeViewVersion}, prefix: protected, width: width,
		origins: inventory.origins, transport: transport}
	capture, err := s.captureFlowSourcesWithOptions(ctx, actor, []reportFlowSourceRef{settings.view}, true, false, reportFlowCaptureOptions{
		SeasonalPeriodEnds: []time.Time{observedTo}, CombineSeasonal: true, PrefixImpact: &settings, ReservedMemoryBytes: budget.MemoryBytes / 4,
	})
	if err != nil {
		return empty, err
	}
	defer capture.Close()
	if len(capture.Results) != 1 || !matchFlowEvidenceClocks(capture.Inputs, settings.view, []time.Time{observedTo}, width) {
		return empty, apierror.Conflict("complete observations for the whole protected prefix are required")
	}
	impact, whole, err := projectPrefixImpact(ctx, capture.Results[0], settings, benign, budget.MemoryBytes/8)
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
	if !samePrefixImpactInventory(current, inventory) {
		return empty, apierror.Conflict("the configured routing prefixes or exporter bindings changed during the review")
	}
	latest, err := s.readAlertDDoSReceipt(ctx, actor, input.RuleID, input.ReceiptFingerprint, credential, nil)
	if err != nil {
		return empty, err
	}
	originalDigest, err := prefixImpactDigest(proof)
	if err != nil {
		return empty, err
	}
	latestDigest, err := prefixImpactDigest(latest)
	if err != nil || latestDigest != originalDigest {
		return empty, apierror.Conflict("the cited traffic receipt changed during the review").Wrap(err)
	}
	scope, err := prefixImpactDigest(struct {
		Receipt           string
		Protected, Benign time.Time
		Origins           []store.PrefixImpactFlowBinding
		Generation        int64
		ViewID, Version   string
		From, To          time.Time
		FlowSpec          *remediation.FlowSpecTransport `json:"flow_spec,omitempty"`
	}{originalDigest, inventory.protected.UpdatedAt.UTC(), inventory.benign.UpdatedAt.UTC(), inventory.origins, capture.SourceGeneration,
		capture.Inputs[0].ID, capture.Inputs[0].Version, capture.Inputs[0].From.UTC(), capture.Inputs[0].To.UTC(), transport})
	if err != nil {
		return empty, err
	}
	return remediation.RTBHImpactPublication{Impact: impact, WholeScope: whole, Scope: scope,
		Publish: func(ctx context.Context, sc tenancy.Scope, permission string, commit func(context.Context, tenancy.Scope) error) error {
			return s.publishRTBHReview(ctx, sc, actor, input, permission, budget.MemoryBytes/8, originalDigest, proof.Previous.Before.From, inventory, capture, commit)
		}}, ctx.Err()
}

func (s *Server) publishRTBHReview(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, input remediation.PrefixImpactInput,
	permission string, memory int64, digest string, from time.Time, expected prefixImpactInventory, capture *reportFlowCapture,
	commit func(context.Context, tenancy.Scope) error) error {
	if sc.Tenant.String() != actor.TenantID || commit == nil {
		return tenancy.ErrNoTenant
	}
	if permission == permRemediationApprove {
		if err := s.lockRoutingReviewApprovalSession(ctx, sc, actor); err != nil {
			return err
		}
	}
	return s.loadAlertDDoSReceiptInScope(ctx, sc, actor, input.RuleID, input.ReceiptFingerprint, memory,
		func(ctx context.Context, sc tenancy.Scope, proof alert.DDoSEvaluationEvidence, _ []byte) error {
			actual, err := prefixImpactDigest(proof)
			if err != nil || actual != digest {
				return apierror.Conflict("the cited traffic receipt changed during publication").Wrap(err)
			}
			authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
			if err != nil {
				return err
			}
			ctx, current, err := authority.requestContext(ctx, actor)
			if err != nil {
				return err
			}
			for _, required := range []string{permAlertRead, permission} {
				if err := s.authorize(ctx, current, required, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}); err != nil {
					return err
				}
			}
			latest, err := s.readPrefixImpactInventoryInScope(ctx, sc, current, input, from)
			if err != nil {
				return err
			}
			if !samePrefixImpactInventory(latest, expected) {
				return apierror.Conflict("the configured routing scope changed during publication")
			}
			if err := s.validateReportSourcePublication(ctx, sc, current, capture); err != nil {
				return err
			}
			return commit(ctx, sc)
		})
}

func samePrefixImpactInventory(current, expected prefixImpactInventory) bool {
	return current.protected.UpdatedAt.Equal(expected.protected.UpdatedAt) && current.benign.UpdatedAt.Equal(expected.benign.UpdatedAt) &&
		slices.EqualFunc(current.origins, expected.origins, func(a, b store.PrefixImpactFlowBinding) bool {
			return a.AgentID == b.AgentID && a.Exporter == b.Exporter && a.Since.Equal(b.Since)
		})
}

func prefixImpactDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(raw)), nil
}

func (s *Server) readPrefixImpactInventory(ctx context.Context, actor *auth.Principal, input remediation.PrefixImpactInput, from time.Time) (prefixImpactInventory, error) {
	var result prefixImpactInventory
	err := tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = s.readPrefixImpactInventoryInScope(ctx, sc, actor, input, from)
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

func (s *Server) readPrefixImpactInventoryInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal,
	input remediation.PrefixImpactInput, from time.Time) (prefixImpactInventory, error) {
	var result prefixImpactInventory
	registry := store.NewEntityRegistry(s.pool)
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return result, err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return result, err
	}
	contextRecord, err := registry.GetEntityContextInScope(ctx, sc, input.ContextID)
	if err != nil {
		return result, err
	}
	if err := s.authorizeFlowRoutingContext(ctx, principal, contextRecord); err != nil {
		return result, err
	}
	scope := entity.Scope{TenantID: sc.Tenant.String(), ContextID: input.ContextID}
	result.protected, err = registry.GetEntityInScope(ctx, sc, scope, input.ProtectedEntityID)
	if err != nil {
		return result, err
	}
	result.benign, err = registry.GetEntityInScope(ctx, sc, scope, input.BenignEntityID)
	if err != nil {
		return result, err
	}
	if result.protected.Kind != entity.Prefix || result.benign.Kind != entity.Prefix || result.protected.NetworkPrefix == "" || result.benign.NetworkPrefix == "" {
		return result, apierror.Validation("the routing context needs configured protected and known benign network prefixes")
	}
	result.origins, err = store.PrefixImpactFlowBindingsInScope(ctx, sc, input.ContextID, from)
	return result, err
}

type prefixImpactTotals struct {
	bytes, packets, benignBytes, benignPackets big.Int
	records                                    int
	sampled                                    bool
	addresses                                  map[netip.Addr]struct{}
}

func projectPrefixImpact(ctx context.Context, captured capturedReportFlow, settings prefixImpactCapture, benign netip.Prefix, memory int64) (remediation.PrefixImpact, *remediation.PrefixImpact, error) {
	var empty remediation.PrefixImpact
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != captured.TenantID {
		return empty, nil, tenancy.ErrNoTenant
	}
	result := captured.Result
	if result.Source != "raw" || result.Coverage == nil || !result.Coverage.CompleteInputs || result.OldestInput.IsZero() ||
		result.DetailLimited || result.Other != nil || len(result.Rows) == 0 || int64(len(result.Rows)) > memory/512 {
		return empty, nil, anomaly.ErrDDoSCoverage
	}
	totals := prefixImpactTotals{addresses: make(map[netip.Addr]struct{})}
	var matched prefixImpactTotals
	if settings.transport != nil {
		matched.addresses = make(map[netip.Addr]struct{})
	}
	origins := make(map[store.PrefixImpactFlowBinding]bool, len(settings.origins))
	for _, origin := range settings.origins {
		origins[store.PrefixImpactFlowBinding{AgentID: origin.AgentID, Exporter: origin.Exporter}] = true
	}
	for _, row := range result.Rows {
		if err := ctx.Err(); err != nil {
			return empty, nil, err
		}
		exporter, err := netip.ParseAddr(row.Group["exporter"])
		if err != nil || !origins[store.PrefixImpactFlowBinding{AgentID: row.Group["agent_id"], Exporter: exporter.Unmap()}] {
			return empty, nil, anomaly.ErrDDoSCoverage
		}
		if err := totals.add(row, settings.prefix, benign); err != nil {
			return empty, nil, err
		}
		if settings.transport == nil {
			continue
		}
		switch flowSpecDecisionFromRetainedRow(*settings.transport, row.Group) {
		case remediation.FlowSpecTransportOutside:
		case remediation.FlowSpecTransportInside:
			if err := matched.add(row, settings.prefix, benign); err != nil {
				return empty, nil, err
			}
		default:
			return empty, nil, anomaly.ErrDDoSCoverage
		}
	}
	if settings.transport == nil {
		return totals.impact(settings.prefix, result.Query.From, result.Query.To), nil, ctx.Err()
	}
	whole := totals.impact(settings.prefix, result.Query.From, result.Query.To)
	return matched.impact(settings.prefix, result.Query.From, result.Query.To), &whole, ctx.Err()
}

func (totals *prefixImpactTotals) impact(prefix netip.Prefix, from, to time.Time) remediation.PrefixImpact {
	return remediation.PrefixImpact{Prefix: prefix.String(), From: from, To: to, Sampled: totals.sampled,
		ObservedRecords: totals.records, ObservedAddresses: len(totals.addresses),
		Matched:     remediation.PrefixTraffic{Bytes: totals.bytes.String(), Packets: totals.packets.String()},
		KnownBenign: remediation.PrefixTraffic{Bytes: totals.benignBytes.String(), Packets: totals.benignPackets.String()},
		Unclassified: remediation.PrefixTraffic{Bytes: new(big.Int).Sub(&totals.bytes, &totals.benignBytes).String(),
			Packets: new(big.Int).Sub(&totals.packets, &totals.benignPackets).String()}}
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
