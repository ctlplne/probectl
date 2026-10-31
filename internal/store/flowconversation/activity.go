// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const activityCleanupTimeout = 2 * time.Second

func assertActivityGuard(ctx context.Context, sc tenancy.Scope) error {
	var schema string
	if err := sc.Q.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		return err
	}
	return tenancy.AssertFlowHistoryOwnerGuard(ctx, sc.Q, schema, "flow_conversation_activity")
}

// Registration commits independently of the long family read transaction.
// An uncertain result never enters source; its private reference is already
// eligible for no-IO retirement/retry if INSERT may have been attempted.
func (j *Journal) registerActivity(ctx context.Context, id historyIdentity, ref *activityRef, generation uint64) error {
	err := j.fence.WithTenantWrites(ctx, []string{id.tenant}, func(ctx context.Context) error {
		return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
			owner, origin, err := bindRequestOwner(ctx, sc)
			if err != nil || owner != id.owner || sc.Tenant.String() != id.tenant || !sameRequestOrigin(origin, id.origin) {
				return ErrMessageDenied
			}
			if err := assertActivityGuard(ctx, sc); err != nil {
				return err
			}
			if err := audit.LockTenantStream(ctx, sc.Q, id.tenant); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO flow_conversation_epochs(tenant_id,generation) VALUES($1::uuid,1) ON CONFLICT (tenant_id) DO NOTHING`, id.tenant); err != nil {
				return err
			}
			current, err := activeConversationEpoch(ctx, sc, epochUpdate)
			if err != nil {
				return err
			}
			if current != generation {
				return ErrJournalGeneration
			}
			if err := ref.runtime.setAttempt(ref, current); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO flow_conversation_activity(tenant_id,owner_id,operation_id,instance_id,epoch) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5)`, ref.tenant, ref.owner, ref.operation, ref.instance, int64(ref.generation)); err != nil {
				return err
			}
			return j.record(ctx, sc, id.owner, "flow.conversation.operation_started", ref.operation, map[string]any{"instance_id": ref.instance, "generation": ref.generation})
		})
	})
	return journalError(ctx, err)
}

// Journal data operations under a private read callback must still have an
// exact active durable registration. The registration itself grants no source.
func (j *Journal) checkActivityContext(ctx context.Context, sc tenancy.Scope) error {
	lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease)
	if !ok {
		return nil
	}
	if lease == nil || lease.journal != j || lease.activity == nil || !lease.activity.runtime.isActive(lease.activity) {
		return ErrMessageDenied
	}
	ref := lease.activity
	owner, origin, err := bindRequestOwner(ctx, sc)
	if err != nil || owner != ref.owner || sc.Tenant.String() != ref.tenant || !sameRequestOrigin(origin, lease.owner.origin) {
		return ErrMessageDenied
	}
	var live bool
	err = sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND operation_id=$3::uuid AND instance_id=$4::uuid AND epoch=$5 AND drained_at IS NULL)`, ref.tenant, ref.owner, ref.operation, ref.instance, int64(ref.generation)).Scan(&live)
	if err != nil {
		return err
	}
	if !live {
		return ErrJournalLease
	}
	return nil
}

type activityCleanupParent struct{ context.Context }

func (ctx activityCleanupParent) Value(key any) any {
	if _, ok := key.(operationLeaseKey); ok {
		return nil
	}
	return ctx.Context.Value(key)
}
func cleanupActivityContext(ctx context.Context, ref *activityRef) (context.Context, context.CancelFunc) {
	// Keep routing/transaction guards but not cancellation or source authority.
	parent := auth.WithPrincipal(activityCleanupParent{context.WithoutCancel(ctx)}, nil)
	return context.WithTimeout(tenancy.WithTenant(parent, tenancy.ID(ref.tenant)), activityCleanupTimeout)
}

func (j *Journal) retireActivity(ctx context.Context, ref *activityRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenant, err := maintenanceTenant(ctx)
	if err != nil || ref == nil || tenant != ref.tenant {
		return ErrMessageDenied
	}
	if err := j.available(); err != nil {
		return err
	}
	state, err := activityRuntimeFor(j.pool)
	if err != nil {
		return err
	}
	if state != ref.runtime || !state.canRetire(ref) {
		return ErrMessageDenied
	}
	schema, err := historyStorageSchema(ctx)
	if err != nil {
		return err
	}
	err = tenancy.InTenantProviderMaintenance(tenancy.WithSiloTableLock(ctx), j.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if sc.Tenant.String() != ref.tenant {
			return ErrMessageDenied
		}
		if err := tenancy.LockTenantWrites(ctx, sc.Q, ref.tenant); err != nil {
			return err
		}
		if err := audit.LockTenantStream(ctx, sc.Q, ref.tenant); err != nil {
			return err
		}
		var status string
		var fenced bool
		if err := sc.Q.QueryRow(ctx, `SELECT status,audit_write_fenced_at IS NOT NULL FROM public.tenants WHERE id=$1::uuid FOR SHARE`, ref.tenant).Scan(&status, &fenced); err != nil {
			return err
		}
		if status != "active" && status != "suspended" && status != "offboarding" && status != "deleted" {
			return ErrMessageDenied
		}
		if _, err := sc.Q.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{tenancy.AppRole}.Sanitize()); err != nil {
			return err
		}
		if err := bindLifecycle(ctx, sc); err != nil {
			return err
		}
		if err := lockHistoryFamily(ctx, sc, schema); err != nil {
			return err
		}
		if err := assertActivityGuard(ctx, sc); err != nil {
			return err
		}
		var owner, instance string
		var generation uint64
		err := sc.Q.QueryRow(ctx, `SELECT owner_id::text,instance_id::text,epoch FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND operation_id=$2::uuid FOR UPDATE`, ref.tenant, ref.operation).Scan(&owner, &instance, &generation)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if owner != ref.owner || instance != ref.instance || generation != ref.generation {
			return ErrJournalConflict
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE flow_conversation_activity SET drained_at=clock_timestamp() WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND operation_id=$3::uuid AND instance_id=$4::uuid AND epoch=$5`, ref.tenant, ref.owner, ref.operation, ref.instance, int64(ref.generation)); err != nil {
			return err
		}
		data := map[string]any{"tenant_id": ref.tenant, "owner_id": ref.owner, "instance_id": ref.instance, "generation": ref.generation, "actual_callback_drained": true}
		if !fenced && (status == "active" || status == "suspended") {
			if err := j.record(ctx, sc, "system:flow-conversation", "flow.conversation.operation_drained", ref.operation, data); err != nil {
				return err
			}
		} else {
			if _, err := sc.Q.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{tenancy.ProviderRole}.Sanitize()); err != nil {
				return err
			}
			if err := j.recordProvider(ctx, sc.Q, "system:flow-conversation", "flow.conversation.operation_drained", ref.operation, data); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{tenancy.AppRole}.Sanitize()); err != nil {
				return err
			}
		}
		changed, err := sc.Q.Exec(ctx, `DELETE FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND operation_id=$3::uuid AND instance_id=$4::uuid AND epoch=$5 AND drained_at IS NOT NULL`, ref.tenant, ref.owner, ref.operation, ref.instance, int64(ref.generation))
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return ErrJournalConflict
		}
		return nil
	})
	return journalError(ctx, err)
}

func (j *Journal) finishActivity(ctx context.Context, ref *activityRef) error {
	if ref == nil || !ref.runtime.drainAndClaim(ref) {
		return ErrMessageDenied
	}
	cleanup, cancel := cleanupActivityContext(ctx, ref)
	defer cancel()
	err := j.retireActivity(cleanup, ref)
	ref.runtime.finishRetirement(ref, err)
	return err
}
