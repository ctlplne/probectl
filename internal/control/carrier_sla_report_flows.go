// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type carrierSLAFlowRequirement struct {
	Key    string `json:"key"`
	Digest string `json:"digest"`
}

// Observed counters are unscaled exporter originals. Endpoint addresses and
// payloads are excluded. These records never enter the contractual credit math.
type carrierSLAFlowOriginal struct {
	Key              string    `json:"capture_key"`
	CapturedAt       time.Time `json:"captured_at"`
	Start            time.Time `json:"start"`
	End              time.Time `json:"end"`
	ClockBasis       string    `json:"clock_basis"`
	ContextID        string    `json:"context_id"`
	RouterID         string    `json:"router_id"`
	OriginalSourceID string    `json:"original_source_id"`
	InIf             uint32    `json:"ingress_if_index"`
	OutIf            uint32    `json:"egress_if_index"`
	Bytes            string    `json:"observed_bytes"`
	Packets          string    `json:"observed_packets"`
	Sampling         string    `json:"sampling"`
}

func (s *Server) carrierSLACircuitFlowSources(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, target flow.CapacityTarget, memory int64) ([]store.IncidentImpactSource,
	func(context.Context, entity.ContextRecord, store.IncidentImpactEntity) error, error) {
	authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity) error {
		if record.TenantID != actor.TenantID || record.ContextID != member.ContextID {
			return entity.ErrScopeMismatch
		}
		resource := entityContextResource(record)
		resource["entity_id"] = member.EntityID
		if err := s.authorize(ctx, actor, "entities.read", auth.RBACGlobal, resource); err != nil {
			return err
		}
		return s.authorize(ctx, actor, permFlowRead, auth.RBACGlobal, resource)
	}
	members, _, err := s.capacityBillMembersInScope(ctx, sc, actor, target, memory/2, func(ctx context.Context, record entity.ContextRecord) error {
		return s.authorize(ctx, actor, permFlowRead, auth.RBACGlobal, entityContextResource(record))
	})
	if err != nil {
		return nil, nil, err
	}
	if len(members) == 0 || int64(len(members)) > memory/1024 {
		return nil, nil, store.ErrClientReportBudget
	}
	interfaces := make([]store.IncidentImpactEntity, 0, len(members))
	for _, member := range members {
		if member.Scope.TenantID != actor.TenantID {
			return nil, nil, entity.ErrScopeMismatch
		}
		interfaces = append(interfaces, store.IncidentImpactEntity{ContextID: member.Scope.ContextID, EntityID: member.InterfaceID})
	}
	sources, err := store.CurrentFlowSourcesInScope(ctx, sc, interfaces, entity.InterfaceRolePolicyBudget{MemoryBytes: memory, WorkUnits: memory}, authorize)
	return sources, authorize, err
}

func (s *Server) carrierSLAFlowOriginals(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, target flow.CapacityTarget, period flow.CapacityBillingPeriod,
	keys []string, budget flowstore.ExplorerBudget, chargeRead func(int64, int64) error) ([]carrierSLAFlowOriginal, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || actor == nil || actor.TenantID != bound.String() || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if s.flowStore == nil {
		return []carrierSLAFlowOriginal{}, nil
	}
	if err := s.authorize(ctx, actor, permFlowRead, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
		return nil, err
	}
	memory := budget.MemoryBytes / 8
	// Reserve one eighth for the retained report and give the raw query one
	// of the seven remaining shares. Its decoded rows coexist with the
	// owner lookup, source selectors, receipts and signed projections.
	batch, err := flowstore.NewReportPlanBatch(ctx, s.flowStore, bound.String(), 1, memory, budget.ExecutionLimit, 6)
	if err != nil {
		return nil, err
	}
	defer batch.Close()
	ctx = batch.Context()
	sources, authorize, err := s.carrierSLACircuitFlowSources(ctx, sc, actor, target, memory)
	if err != nil {
		return nil, err
	}
	var selected []flowstore.IncidentTrafficSource
	for _, source := range sources {
		selected = append(selected, source.Selections...)
	}
	if len(selected) == 0 {
		return []carrierSLAFlowOriginal{}, ctx.Err()
	}
	rows, err := batch.IncidentTrafficRows(flowstore.IncidentTrafficQuery{
		TenantID: bound.String(), From: period.From, To: period.To, Series: "raw", Sources: selected, RetainedKeys: keys,
		IncludeClockBasis: true,
	})
	if err != nil {
		var unavailable *flowstore.PlanCoverageError
		if len(keys) == 0 && errors.As(err, &unavailable) {
			return []carrierSLAFlowOriginal{}, nil
		}
		return nil, err
	}
	eligible := rows[:0]
	var readBytes int64
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if row.TenantID != bound.String() || row.TS.Before(period.From) || !row.TS.Before(period.To) {
			return nil, entity.ErrScopeMismatch
		}
		readBytes += int64(1024 + len(row.AgentID) + len(row.Exporter) + len(row.SrcAddr) + len(row.DstAddr))
		if carrierSLAFlowClockBasis(row, period) != "" {
			eligible = append(eligible, row)
		}
	}
	// Charge the complete raw read at once. An optional flow population
	// that exceeds admission must not spend part of the report's remaining
	// read budget before being discarded.
	if chargeRead != nil && len(rows) > 0 {
		if err := chargeRead(readBytes, int64(len(rows))); err != nil {
			return nil, err
		}
	}
	reads, err := flowstore.IncidentTrafficCaptureReferences(ctx, bound.String(), eligible, memory)
	if err != nil {
		return nil, err
	}
	if len(reads) == 0 {
		return []carrierSLAFlowOriginal{}, ctx.Err()
	}
	owners, err := (store.CapturedFlowOwners{}).ReadInScope(ctx, sc, reads, store.BGPRoutingBudget{
		MemoryBytes: memory, WorkUnits: memory, StateBytes: memory,
	}, selectedFlowOwnerAuthorization(sources, authorize))
	if err != nil {
		return nil, err
	}
	ownersByKey := make(map[string]store.CapturedFlowOwner, len(owners))
	for _, owner := range owners {
		ownersByKey[hex.EncodeToString(owner.Reference.Key[:])] = owner
	}
	coverage := incidentImpactSourceCoverage(sources)
	originals := make(map[string]carrierSLAFlowOriginal)
	for _, row := range eligible {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		owner := ownersByKey[row.RoutingCaptureKey]
		if !incidentTrafficOwnerMatches(row, owner) || !coverage.covers(row, owner) {
			continue
		}
		record := carrierSLAFlowOriginal{
			Key: row.RoutingCaptureKey, CapturedAt: owner.Reference.CapturedAt.UTC(), Start: row.StartTS.UTC(), End: row.TS.UTC(),
			ClockBasis: carrierSLAFlowClockBasis(row, period),
			ContextID:  owner.Owner.ContextID, RouterID: owner.Owner.RouterID, OriginalSourceID: owner.Owner.SourceID, InIf: row.InIf, OutIf: row.OutIf,
			Bytes: strconv.FormatUint(row.Bytes, 10), Packets: strconv.FormatUint(row.Packets, 10), Sampling: strconv.FormatUint(row.Sampling, 10),
		}
		if old, found := originals[record.Key]; found && old != record {
			return nil, entity.ErrInvalidClaim
		}
		originals[record.Key] = record
	}
	result := make([]carrierSLAFlowOriginal, 0, len(originals))
	for _, original := range originals {
		result = append(result, original)
	}
	slices.SortFunc(result, func(a, b carrierSLAFlowOriginal) int {
		return cmp.Compare(a.Key, b.Key)
	})
	return result, ctx.Err()
}

func carrierSLAFlowClockBasis(row flowstore.Row, period flow.CapacityBillingPeriod) string {
	clock := flowstore.FlowCaptureTiming{Start: row.StartTS, End: row.TS, Basis: row.ClockBasis}
	from, to, ok := clock.ObservationRange(row.Protocol, 0)
	if !ok || from.Before(period.From) || to.After(period.To) {
		return ""
	}
	if row.ClockBasis == flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL {
		return "exporter_interval"
	}
	return "collector_sample"
}

func carrierSLAFlowRequirements(records []carrierSLAFlowOriginal) ([]carrierSLAFlowRequirement, error) {
	result := make([]carrierSLAFlowRequirement, 0, len(records))
	for _, record := range records {
		body, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		result = append(result, carrierSLAFlowRequirement{Key: record.Key, Digest: hex.EncodeToString(crypto.Hash(body))})
	}
	return result, nil
}

func carrierSLAFlowUnavailable(err error) bool {
	if errors.Is(err, flowstore.ErrExplorerBudget) || errors.Is(err, store.ErrBGPRoutingBudget) ||
		errors.Is(err, entity.ErrInterfaceRoleBudget) || errors.Is(err, store.ErrClientReportBudget) {
		return true
	}
	failure, ok := apierror.As(err)
	return ok && (failure.Kind == apierror.KindForbidden || failure.Kind == apierror.KindNotFound)
}
