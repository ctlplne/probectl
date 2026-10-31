// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store/flowconversation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type erasurePreparation struct {
	irPlanID string
	history  []StoreResult
}

func (e *Engine) prepareConversationErasure(ctx context.Context, tenant, actor string) ([]StoreResult, error) {
	// Engine's controlled lifecycle operation supplies independent authority.
	// A caller's Principal, old creator credential and provider telemetry grants
	// cannot enter this storage operation. Routing/quarantine/TxGuard remain.
	ctx = tenancy.WithTenant(auth.WithPrincipal(ctx, nil), tenancy.ID(tenant))
	authorize := func(ctx context.Context, current string) error {
		bound, ok := tenancy.FromContext(ctx)
		if !ok || bound.String() != tenant || current != tenant || auth.PrincipalFrom(ctx) != nil {
			return errors.New("tenantlife: history maintenance scope refused")
		}
		return tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
			var eligible bool
			if err := q.QueryRow(ctx, `SELECT status IN ('active','suspended','offboarding') FROM public.tenants WHERE id=$1::uuid`, tenant).Scan(&eligible); err != nil {
				return err
			}
			if !eligible {
				return errors.New("tenantlife: history maintenance registry state refused")
			}
			return nil
		})
	}
	// These are per-transaction resources, never a total history/tenant cap.
	budget := flowconversation.CancellationBudget{Rows: 256, TimeLimit: 5 * time.Second}
	result, err := flowconversation.NewJournal(e.pool).EraseTenant(ctx, budget, authorize, func(ctx context.Context) error {
		return e.fenceTenantAuditWrites(ctx, tenant, actor)
	})
	if err != nil || !result.Installed {
		return nil, err
	}
	return []StoreResult{
		{Store: "flow_conversation_messages", Deleted: result.MessagesDeleted, VerifiedZero: true},
		{Store: "flow_conversation_jobs", Deleted: result.JobsDeleted, VerifiedZero: true},
		{Store: "flow_conversation_activity", VerifiedZero: true, Notes: "all source operations acknowledged actual drain; unknown instances prevent erasure"},
	}, nil
}
