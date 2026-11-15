// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ClientReportInventoryItem struct {
	Context        entity.ContextRecord
	Entity         entity.Record
	ParentEntityID string
}

// Inventory refs are existence/identity requirements for a frozen metadata
// snapshot. They contain no telemetry, permission outcome or reader grant.
type ReportInventoryRef struct {
	ContextID string    `json:"context_id"`
	EntityID  string    `json:"entity_id"`
	CreatedAt time.Time `json:"created_at"`
}

// ClientReportInventoryInScope walks the complete tenant registry in one RLS
// snapshot. It describes durable canonical configuration at capture, not
// historical discovery or current health. Authorization covers each entity's
// current site/VRF context after the result cursor has been closed.
func (*EntityRegistry) ClientReportInventoryInScope(ctx context.Context, sc tenancy.Scope, memory int64, authorize func(context.Context, entity.ContextRecord, string) error) ([]ClientReportInventoryItem, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || authorize == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	if memory <= 0 {
		return nil, ErrClientReportBudget
	}
	rows, err := sc.Q.Query(ctx, `SELECT c.id::text,c.site_id::text,c.vrf_id::text,c.site_label,c.vrf_label,c.created_at,
 n.id::text,n.kind,n.label,n.created_at,n.updated_at,COALESCE(n.network_prefix::text,''),COALESCE(n.parent_entity_id::text,'')
 FROM entities n JOIN entity_contexts c ON (c.tenant_id,c.id)=(n.tenant_id,n.context_id)
 WHERE n.tenant_id=$1 AND c.tenant_id=$1 ORDER BY c.id,n.id LIMIT $2`, bound.String(), memory/1024+1)
	if err != nil {
		return nil, err
	}
	items := []ClientReportInventoryItem{}
	remaining := memory
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		var item ClientReportInventoryItem
		item.Context.TenantID = bound.String()
		if err := rows.Scan(&item.Context.ContextID, &item.Context.SiteID, &item.Context.VRFID, &item.Context.SiteLabel, &item.Context.VRFLabel, &item.Context.CreatedAt,
			&item.Entity.ID, &item.Entity.Kind, &item.Entity.Label, &item.Entity.CreatedAt, &item.Entity.UpdatedAt, &item.Entity.NetworkPrefix, &item.ParentEntityID); err != nil {
			rows.Close()
			return nil, err
		}
		cost := int64(4096 + 16*(len(item.Context.SiteLabel)+len(item.Context.VRFLabel)+len(item.Entity.Label)+len(item.Entity.NetworkPrefix)))
		if cost > remaining {
			rows.Close()
			return nil, ErrClientReportBudget
		}
		remaining -= cost
		item.Entity.Scope = entity.Scope{TenantID: bound.String(), ContextID: item.Context.ContextID}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if err := authorize(ctx, item.Context, item.Entity.ID); err != nil {
			return nil, err
		}
	}
	return items, ctx.Err()
}

func (*EntityRegistry) RecheckReportInventoryInScope(ctx context.Context, sc tenancy.Scope, refs []ReportInventoryRef, memory int64) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return entity.ErrScopeMismatch
	}
	if err := requireReportSourceReadScope(ctx, sc); err != nil {
		return err
	}
	if memory <= 0 || int64(len(refs)) > memory/1024 {
		return ErrClientReportBudget
	}
	contexts, ids, clocks := []string{}, []string{}, []time.Time{}
	seen := map[string]bool{}
	for _, item := range refs {
		if _, err := validRegistryUUID(item.ContextID); err != nil {
			return err
		}
		if _, err := validRegistryUUID(item.EntityID); err != nil {
			return err
		}
		key := item.ContextID + ":" + item.EntityID
		if item.CreatedAt.IsZero() || seen[key] {
			return entity.ErrInvalidClaim
		}
		seen[key] = true
		contexts, ids, clocks = append(contexts, item.ContextID), append(ids, item.EntityID), append(clocks, item.CreatedAt)
	}
	var matched int
	err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM unnest($2::uuid[],$3::uuid[],$4::timestamptz[]) original(context_id,id,created_at)
 JOIN entities n ON n.tenant_id=$1 AND n.context_id=original.context_id AND n.id=original.id AND n.created_at=original.created_at
 JOIN entity_contexts c ON (c.tenant_id,c.id)=(n.tenant_id,n.context_id)`, bound.String(), contexts, ids, clocks).Scan(&matched)
	if err != nil {
		return err
	}
	if matched != len(refs) {
		return entity.ErrInvalidClaim
	}
	return ctx.Err()
}
