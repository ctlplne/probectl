// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) captureAssessmentComponents(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, result *clientReportCapture, memory int64) error {
	if actor == nil || actor.TenantID != sc.Tenant.String() || result.TenantID != actor.TenantID {
		return entity.ErrScopeMismatch
	}
	if err := s.authorize(ctx, actor, "topology.read", auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
		return err
	}
	if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&result.InventoryAt); err != nil {
		return err
	}
	result.InventoryAt = result.InventoryAt.UTC()
	var err error
	result.Inventory, err = s.captureAssessmentInventory(ctx, sc, actor, memory/2)
	if err != nil {
		return err
	}
	result.PhysicalLinks, err = store.NewEntityRegistry(s.pool).ClientReportPhysicalLinksInScope(ctx, sc, memory/2, func(ctx context.Context, record entity.ContextRecord, from, to string) error {
		if record.TenantID != actor.TenantID {
			return entity.ErrScopeMismatch
		}
		for _, id := range []string{from, to} {
			resource := entityContextResource(record)
			resource["entity_id"] = id
			for _, permission := range []string{"topology.read", "entities.read", "metrics.read"} {
				if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
					return err
				}
			}
		}
		return ctx.Err()
	})
	return err
}

func projectAssessmentTopology(ctx context.Context, capture *clientReportCapture, memory int64) (reporting.CSVTable, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || capture == nil || bound.String() != capture.TenantID {
		return reporting.CSVTable{}, entity.ErrScopeMismatch
	}
	projection := &reportFlowProjection{ctx: ctx, tenant: capture.TenantID, memory: memory}
	var rows [][]string
	for _, item := range capture.PhysicalLinks {
		if item.TenantID != capture.TenantID {
			return reporting.CSVTable{}, entity.ErrScopeMismatch
		}
		row := []string{item.TenantID, item.ContextID, item.LinkID, item.FromEntityID, item.ToEntityID, item.Protocol,
			strconv.FormatUint(uint64(item.LocalIfIndex), 10), item.LocalPort, item.RemotePort, item.Chassis, item.DeviceName, item.ManagementAddress,
			item.EvidenceID, item.ObservationID, item.Source.AgentID, item.Source.SourceRef, item.ObservedAt.Format(time.RFC3339Nano),
			item.RemoteEvidenceID, item.RemoteObservationID, item.RemoteSource.AgentID, item.RemoteSource.SourceRef, item.RemoteObservedAt.Format(time.RFC3339Nano),
			item.CapturedAt.Format(time.RFC3339Nano), item.OriginalsDigest}
		if err := chargeClientReportCells(projection, row); err != nil {
			return reporting.CSVTable{}, err
		}
		rows = append(rows, row)
	}
	columns := plainClientReportColumns([]string{"tenant_id", "context_id", "link_id", "from_entity_id", "to_entity_id", "protocol", "local_if_index", "local_port", "remote_port", "remote_chassis", "remote_device_name", "remote_management_address",
		"local_evidence_id", "local_observation_id", "local_agent_id", "local_source_ref", "local_observed_at", "remote_evidence_id", "remote_observation_id", "remote_agent_id", "remote_source_ref", "remote_observed_at", "captured_at", "originals_digest"})
	table := sealedClientReportTable(capture.TenantID, "assessment-topology", "Observed physical adjacency at report capture", capture.From, capture.To, columns, rows)
	table.Source = "Complete authorized current canonical LLDP/CDP receipt population at capture with exact independent SNMP support; not historical discovery, continuing reachability or proof of complete network discovery"
	return table, ctx.Err()
}

func validateAssessmentTopologyRequirements(refs []store.ReportPhysicalLinkRef, access []clientReportAccessRequirement) error {
	permissions := map[string]bool{}
	for _, item := range access {
		permissions[item.Permission+":"+item.Resource["context_id"]+":"+item.Resource["entity_id"]] = true
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		if !reportRequirementUUID(ref.ContextID) || !reportRequirementUUID(ref.LinkID) || !reportRequirementUUID(ref.EvidenceID) || !reportRequirementUUID(ref.RemoteEvidenceID) || ref.CapturedAt.IsZero() || !canonicalFlowRoutingDigest(ref.OriginalsDigest) || seen[ref.LinkID] {
			return errReportSourceRequirements
		}
		seen[ref.LinkID] = true
		for _, id := range []string{ref.FromEntityID, ref.ToEntityID} {
			if !reportRequirementUUID(id) {
				return errReportSourceRequirements
			}
			for _, permission := range []string{"topology.read", "entities.read", "metrics.read"} {
				if !permissions[permission+":"+ref.ContextID+":"+id] {
					return errReportSourceRequirements
				}
			}
		}
	}
	return nil
}
