// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) captureAssessmentInventory(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, memory int64) ([]store.ClientReportInventoryItem, error) {
	return store.NewEntityRegistry(s.pool).ClientReportInventoryInScope(ctx, sc, memory, func(ctx context.Context, record entity.ContextRecord, id string) error {
		if actor == nil || actor.TenantID != sc.Tenant.String() || record.TenantID != actor.TenantID {
			return entity.ErrScopeMismatch
		}
		resource := entityContextResource(record)
		resource["entity_id"] = id
		return s.authorize(ctx, actor, "entities.read", auth.RBACGlobal, resource)
	})
}

func projectAssessmentInventory(ctx context.Context, capture *clientReportCapture, memory int64) (reporting.CSVTable, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || capture == nil || bound.String() != capture.TenantID {
		return reporting.CSVTable{}, entity.ErrScopeMismatch
	}
	projection := &reportFlowProjection{ctx: ctx, tenant: capture.TenantID, memory: memory}
	var rows [][]string
	for _, item := range capture.Inventory {
		if item.Context.TenantID != capture.TenantID || item.Entity.Scope.TenantID != capture.TenantID || item.Entity.Scope.ContextID != item.Context.ContextID {
			return reporting.CSVTable{}, entity.ErrScopeMismatch
		}
		row := []string{capture.TenantID, item.Context.ContextID, item.Context.SiteID, item.Context.VRFID, item.Context.SiteLabel, item.Context.VRFLabel,
			item.Entity.ID, string(item.Entity.Kind), item.Entity.Label, item.ParentEntityID, item.Entity.NetworkPrefix,
			item.Entity.CreatedAt.UTC().Format(time.RFC3339Nano), item.Entity.UpdatedAt.UTC().Format(time.RFC3339Nano), capture.InventoryAt.UTC().Format(time.RFC3339Nano)}
		if err := chargeClientReportCells(projection, row); err != nil {
			return reporting.CSVTable{}, err
		}
		rows = append(rows, row)
	}
	columns := plainClientReportColumns([]string{"tenant_id", "context_id", "site_id", "vrf_id", "site_label", "vrf_label", "entity_id", "entity_kind", "name", "parent_entity_id", "network_prefix", "created_at", "updated_at", "captured_at"})
	table := sealedClientReportTable(capture.TenantID, "assessment-inventory", "Canonical inventory at report capture", capture.From, capture.To, columns, rows)
	table.Source = "complete tenant registry metadata at capture; not historical discovery, current reachability, measured inventory speed or proof of complete network discovery"
	return table, ctx.Err()
}

func assessmentInventoryRefs(items []store.ClientReportInventoryItem) []store.ReportInventoryRef {
	refs := make([]store.ReportInventoryRef, 0, len(items))
	for _, item := range items {
		refs = append(refs, store.ReportInventoryRef{ContextID: item.Context.ContextID, EntityID: item.Entity.ID, CreatedAt: item.Entity.CreatedAt})
	}
	return refs
}

func projectClientAssessment(ctx context.Context, capture *clientReportCapture, definition *reporting.ClientReportAssessment, memory int64) ([]reporting.CSVTable, error) {
	findings, err := projectClientAssessmentFindings(ctx, capture, memory/2)
	if err != nil {
		return nil, err
	}
	inventory, err := projectAssessmentInventory(ctx, capture, memory/2)
	if err != nil {
		return nil, err
	}
	columns := []reporting.CSVColumn{{Name: "prepared_by"}, {Name: "period_from"}, {Name: "period_to"}}
	rows := [][]string{{definition.Preparer, capture.From.Format(time.RFC3339Nano), capture.To.Format(time.RFC3339Nano)}}
	scope := sealedClientReportTable(capture.TenantID, "client-assessment", "Assessment scope and preparer", capture.From, capture.To, columns, rows)
	scope.Source = "Operator-provided assessment configuration"
	tables := append([]reporting.CSVTable{scope}, findings...)
	return append(tables, inventory), nil
}

func validateAssessmentInventoryRequirements(refs []store.ReportInventoryRef, access []clientReportAccessRequirement) error {
	permissions := map[string]bool{}
	for _, item := range access {
		if item.Permission == "entities.read" {
			permissions[item.Resource["context_id"]+":"+item.Resource["entity_id"]] = true
		}
	}
	seen := map[string]bool{}
	for _, item := range refs {
		key := item.ContextID + ":" + item.EntityID
		if !reportRequirementUUID(item.ContextID) || !reportRequirementUUID(item.EntityID) || item.CreatedAt.IsZero() || seen[key] || !permissions[key] {
			return errReportSourceRequirements
		}
		seen[key] = true
	}
	return nil
}
