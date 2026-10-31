// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TenantErasure describes this storage family's physical deletion only. It is
// not a completed tenant/key/backup erasure attestation or a drain capability.
type TenantErasure struct {
	Installed                    bool
	MessagesDeleted, JobsDeleted int64
}

func (TenantErasure) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (TenantErasure) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "flowconversation.TenantErasure[private]")
}

// EraseTenant composes full-tenant lifecycle, not an owner request. The caller
// supplies independently refreshed operational authority and the canonical
// global offboarding fence. That fence runs only after durable actual drain.
// Positive per-batch resources impose no limit on the total retained history.
// Unknown/crashed source operations remain pending; they are never adopted.
func (j *Journal) EraseTenant(ctx context.Context, budget CancellationBudget, authorize AuthorizeMaintenance, fence func(context.Context) error) (TenantErasure, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return TenantErasure{}, err
	}
	if budget.Rows <= 0 || budget.TimeLimit <= 0 || fence == nil {
		return TenantErasure{}, ErrMessageBudget
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return TenantErasure{}, fmt.Errorf("history erase authority: %w", err)
	}
	installed, err := j.historyFamilyInstalled(ctx)
	if err != nil {
		return TenantErasure{}, fmt.Errorf("history erase posture: %w", err)
	}
	if !installed {
		return TenantErasure{}, fence(ctx)
	}
	pending, err := j.tenantEraseIntent(ctx, tenant, authorize)
	if err != nil {
		return TenantErasure{}, fmt.Errorf("history erase intent: %w", err)
	}
	var fenced bool
	err = tenancy.InProvider(ctx, j.pool, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(ctx, `SELECT status='offboarding' AND audit_write_fenced_at IS NOT NULL FROM public.tenants WHERE id=$1::uuid`, tenant).Scan(&fenced)
	})
	if err != nil {
		return TenantErasure{}, journalError(ctx, err)
	}
	if !fenced {
		for {
			batch, err := j.CancelInvalidated(ctx, pending, budget, authorize)
			if err != nil {
				return TenantErasure{}, fmt.Errorf("history erase cancellation: %w", err)
			}
			if batch.ActiveRemaining == 0 {
				break
			}
			if batch.Canceled == 0 {
				return TenantErasure{}, ErrJournalUnavailable
			}
		}
	}
	for {
		retried, err := j.RetryDrainedOperations(ctx, ActivityBudget(budget), authorize)
		if err != nil {
			return TenantErasure{}, fmt.Errorf("history erase acknowledgement: %w", err)
		}
		if retried.Pending == 0 {
			break
		}
		if retried.Acknowledged == 0 {
			return TenantErasure{}, ErrJournalUnavailable
		}
	}
	if err := j.WithDrainedInvalidation(ctx, pending, authorize, fence); err != nil {
		return TenantErasure{}, fmt.Errorf("history erase drain/fence: %w", err)
	}
	result := TenantErasure{Installed: true}
	for {
		batch, err := j.purgeTenantBatch(ctx, pending, budget, authorize)
		if err != nil {
			return TenantErasure{}, fmt.Errorf("history erase purge: %w", err)
		}
		if batch.messagesDeleted > math.MaxInt64-result.MessagesDeleted || batch.jobsDeleted > math.MaxInt64-result.JobsDeleted {
			return TenantErasure{}, ErrMessageBudget
		}
		result.MessagesDeleted += batch.messagesDeleted
		result.JobsDeleted += batch.jobsDeleted
		if batch.messagesRemaining == 0 && batch.jobsRemaining == 0 {
			return result, nil
		}
	}
}

func (j *Journal) historyFamilyInstalled(ctx context.Context) (bool, error) {
	if err := j.available(); err != nil {
		return false, err
	}
	schema, err := historyStorageSchema(ctx)
	if err != nil {
		return false, err
	}
	installed := false
	// Only this catalog probe permits an entirely absent family. Every actual
	// journal operation locks the four exact routed tables before any data SQL.
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), j.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		installed, err = assertHistoryErasureFamily(ctx, sc, schema)
		return err
	})
	return installed, journalError(ctx, err)
}

func historyStorageSchema(ctx context.Context) (string, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || !historyID(tenant.String()) {
		return "", ErrMessageDenied
	}
	target, err := tenancy.CurrentRouter().TargetsFor(ctx, tenant.String())
	if err != nil {
		return "", ErrJournalUnavailable
	}
	if target.PGSchema == "" {
		return "public", nil
	}
	return target.PGSchema, nil
}

var historyStorageTables = [...]string{"flow_conversation_activity", "flow_conversation_epochs", "flow_conversation_jobs", "flow_conversation_messages"}

func lockHistoryFamily(ctx context.Context, sc tenancy.Scope, schema string) error {
	if err := validOwnerScope(ctx, sc); err != nil {
		return err
	}
	var tables []string
	for _, table := range historyStorageTables {
		tables = append(tables, pgx.Identifier{schema, table}.Sanitize())
	}
	// ACCESS SHARE prevents DROP/fallback but permits ordinary data writers.
	// Existing UPDATE/DELETE privileges suffice even when every source SELECT
	// is revoked; no private data is read or new privilege granted.
	_, err := sc.Q.Exec(ctx, "LOCK TABLE "+strings.Join(tables, ",")+" IN ACCESS SHARE MODE")
	return err
}

func assertHistoryErasureFamily(ctx context.Context, sc tenancy.Scope, schema string) (bool, error) {
	var current string
	if err := sc.Q.QueryRow(ctx, `SELECT current_schema()`).Scan(&current); err != nil {
		return false, err
	}
	if current != schema {
		return false, ErrJournalUnavailable
	}
	rows, err := sc.Q.Query(ctx, `SELECT c.relname,c.oid=to_regclass(quote_ident(c.relname)),c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND starts_with(c.relname,'flow_conversation_') AND c.relkind IN ('r','p','v','m','f') ORDER BY c.relname`, schema)
	if err != nil {
		return false, err
	}
	var tables []string
	for rows.Next() {
		var table string
		var resolved, forced bool
		if err := rows.Scan(&table, &resolved, &forced); err != nil {
			rows.Close()
			return false, err
		}
		if !resolved || !forced {
			rows.Close()
			return false, ErrJournalUnavailable
		}
		tables = append(tables, table)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	expected := []string{"flow_conversation_activity", "flow_conversation_epochs", "flow_conversation_jobs", "flow_conversation_messages"}
	if len(tables) == 0 {
		var fallback bool
		err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM unnest($1::text[]) name WHERE to_regclass(name) IS NOT NULL) OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND starts_with(c.relname,'flow_conversation_') AND c.relkind IN ('r','p','v','m','f'))`, expected).Scan(&fallback)
		if err != nil {
			return false, err
		}
		if fallback {
			return false, ErrJournalUnavailable
		}
		return false, nil
	}
	if len(tables) != len(expected) {
		return false, ErrJournalUnavailable
	}
	if err := lockHistoryFamily(ctx, sc, schema); err != nil {
		return false, err
	}
	for index, table := range tables {
		if table != expected[index] {
			return false, ErrJournalUnavailable
		}
		if tenancy.FlowHistoryOwnerTable(table) {
			if err := tenancy.AssertFlowHistoryOwnerGuard(ctx, sc.Q, schema, table); err != nil {
				return false, err
			}
		}
	}
	return true, nil
}

func (j *Journal) tenantEraseIntent(ctx context.Context, tenant string, authorize AuthorizeMaintenance) (Invalidation, error) {
	binding := crypto.Hash([]byte("probectl.flow_conversation.full_tenant_erasure.v1:" + tenant))
	defer clear(binding)
	request := MaintenanceRequest{Kind: MaintenanceTenantErase, Binding: bindingArray(binding)}
	var state conversationEpoch
	err := j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		state, err = readConversationEpoch(ctx, sc, epochRead)
		return err
	})
	if err != nil {
		return Invalidation{}, journalError(ctx, err)
	}
	if state.invalidating {
		request.ID = *state.operation
		return j.ResumeInvalidation(ctx, request, authorize)
	}
	request.ID, err = crypto.UUIDv4()
	if err != nil {
		return Invalidation{}, ErrJournalUnavailable
	}
	// A simultaneous independently authorized eraser may win the exact intent.
	// Its losing caller retries from durable metadata; no successor plan is
	// silently adopted and no caller-supplied operation ID selects this path.
	return j.BeginInvalidation(ctx, request, authorize)
}

type tenantPurgeBatch struct {
	messagesDeleted, jobsDeleted     int64
	messagesRemaining, jobsRemaining int64
}

func (j *Journal) purgeTenantBatch(ctx context.Context, pending Invalidation, budget CancellationBudget, authorize AuthorizeMaintenance) (tenantPurgeBatch, error) {
	ctx, cancel := context.WithTimeout(ctx, budget.TimeLimit)
	defer cancel()
	schema, err := historyStorageSchema(ctx)
	if err != nil {
		return tenantPurgeBatch{}, err
	}
	var result tenantPurgeBatch
	err = j.WithDrainedInvalidation(ctx, pending, authorize, func(ctx context.Context) error {
		return tenancy.InTenantProviderMaintenance(tenancy.WithSiloTableLock(ctx), j.pool, func(ctx context.Context, sc tenancy.Scope) error {
			tenant := sc.Tenant.String()
			if pending.value.tenant != tenant || pending.value.request.Kind != MaintenanceTenantErase {
				return ErrMessageDenied
			}
			if err := tenancy.LockTenantWrites(ctx, sc.Q, tenant); err != nil {
				return err
			}
			if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
				return err
			}
			var fenced bool
			if err := sc.Q.QueryRow(ctx, `SELECT status='offboarding' AND audit_write_fenced_at IS NOT NULL FROM public.tenants WHERE id=$1::uuid FOR SHARE`, tenant).Scan(&fenced); err != nil {
				return err
			}
			if !fenced {
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
			if installed, err := assertHistoryErasureFamily(ctx, sc, schema); err != nil || !installed {
				if err != nil {
					return err
				}
				return ErrJournalUnavailable
			}
			state, err := readConversationEpoch(ctx, sc, epochUpdate)
			if err != nil {
				return err
			}
			if !state.matches(pending.value.request) || state.generation != pending.value.generation {
				return ErrJournalGeneration
			}
			before, err := countTenantPurge(ctx, sc)
			if err != nil {
				return err
			}
			if before.jobsRemaining != 0 {
				changed, err := sc.Q.Exec(ctx, `WITH candidates AS (SELECT owner_id,job_id FROM flow_conversation_jobs WHERE tenant_id=$1::uuid ORDER BY owner_id,job_id LIMIT $2 FOR UPDATE SKIP LOCKED) DELETE FROM flow_conversation_jobs j USING candidates c WHERE j.tenant_id=$1::uuid AND j.owner_id=c.owner_id AND j.job_id=c.job_id`, tenant, int64(budget.Rows))
				if err != nil {
					return err
				}
				result.jobsDeleted = changed.RowsAffected()
			} else if before.messagesRemaining != 0 {
				// Delete leaves only: deleting a root would cascade through an
				// unbounded ancestry despite the selected-row resource limit.
				changed, err := sc.Q.Exec(ctx, `WITH candidates AS (SELECT m.owner_id,m.conversation_id,m.message_id,m.revision FROM flow_conversation_messages m WHERE m.tenant_id=$1::uuid AND NOT EXISTS(SELECT 1 FROM flow_conversation_messages child WHERE child.tenant_id=m.tenant_id AND child.owner_id=m.owner_id AND child.conversation_id=m.conversation_id AND child.parent_message_id=m.message_id AND child.parent_revision=m.revision) ORDER BY m.owner_id,m.conversation_id,m.position LIMIT $2 FOR UPDATE OF m SKIP LOCKED) DELETE FROM flow_conversation_messages m USING candidates c WHERE m.tenant_id=$1::uuid AND m.owner_id=c.owner_id AND m.conversation_id=c.conversation_id AND m.message_id=c.message_id AND m.revision=c.revision`, tenant, int64(budget.Rows))
				if err != nil {
					return err
				}
				result.messagesDeleted = changed.RowsAffected()
			}
			after, err := countTenantPurge(ctx, sc)
			if err != nil {
				return err
			}
			result.messagesRemaining, result.jobsRemaining = after.messagesRemaining, after.jobsRemaining
			if !exactPurgeDelta(before.messagesRemaining, result.messagesDeleted, after.messagesRemaining) || !exactPurgeDelta(before.jobsRemaining, result.jobsDeleted, after.jobsRemaining) {
				return ErrJournalConflict
			}
			if result.messagesDeleted == 0 && result.jobsDeleted == 0 {
				if result.messagesRemaining != 0 || result.jobsRemaining != 0 {
					return ErrJournalUnavailable
				}
				return nil
			}
			if _, err := sc.Q.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{tenancy.ProviderRole}.Sanitize()); err != nil {
				return err
			}
			return j.recordProvider(ctx, sc.Q, "system:flow-conversation", "flow.conversation.tenant_purge", pending.value.request.ID, map[string]any{"tenant_id": tenant, "generation": state.generation, "messages_deleted": result.messagesDeleted, "jobs_deleted": result.jobsDeleted, "messages_remaining": result.messagesRemaining, "jobs_remaining": result.jobsRemaining})
		})
	})
	if err != nil {
		return tenantPurgeBatch{}, journalError(ctx, err)
	}
	return result, nil
}

func countTenantPurge(ctx context.Context, sc tenancy.Scope) (tenantPurgeBatch, error) {
	var result tenantPurgeBatch
	var activeJobs, activeOperations int64
	err := sc.Q.QueryRow(ctx, `SELECT (SELECT count(*) FROM flow_conversation_messages WHERE tenant_id=$1::uuid),(SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid),(SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND status IN ('queued','processing')),(SELECT count(*) FROM flow_conversation_activity WHERE tenant_id=$1::uuid)`, sc.Tenant.String()).Scan(&result.messagesRemaining, &result.jobsRemaining, &activeJobs, &activeOperations)
	if err != nil {
		return tenantPurgeBatch{}, err
	}
	if activeOperations != 0 {
		return tenantPurgeBatch{}, ErrJournalDraining
	}
	if activeJobs != 0 {
		return tenantPurgeBatch{}, ErrJournalConflict
	}
	return result, nil
}

func exactPurgeDelta(before, deleted, after int64) bool {
	return before >= 0 && deleted >= 0 && after >= 0 && deleted <= before && before-deleted == after
}
