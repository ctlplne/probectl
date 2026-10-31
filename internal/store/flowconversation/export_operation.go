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

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type tenantExportLeaseKey struct{}

var errTenantExportClosed = errors.New("flow conversation: export admission is closed")

const (
	exportAuthorityRecheck = 250 * time.Millisecond
	exportAuthorityTimeout = 2 * time.Second
)

// withTenantExportSource is controlled privacy-operation admission. It never
// adopts a message creator's Principal, origin or permission snapshot. Its
// independent authorizer must verify the current initiating export operation.
// Source readers join this private lease and release all buffers before return.
func (j *Journal) withTenantExportSource(ctx context.Context, authorize AuthorizeMaintenance, fn func(context.Context, func(context.Context) error) error) error {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return err
	}
	if fn == nil || authorize == nil {
		return ErrMessageDenied
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return err
	}
	return j.operationLease(ctx, tenant, false, func(ctx context.Context) error {
		if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
			return err
		}
		generation, err := j.exportGeneration(ctx)
		if err != nil {
			return err
		}
		state, err := activityRuntimeFor(j.pool)
		if err != nil {
			return err
		}
		// This bookkeeping identity is not an impersonated user. No ordinary
		// owner operation accepts this Principal-free export context.
		owner, err := crypto.UUIDv4()
		if err != nil {
			return ErrJournalUnavailable
		}
		ref, err := state.reserve(ctx, tenant, owner)
		if err != nil {
			return err
		}
		if err := j.registerExportActivity(ctx, ref, generation); err != nil {
			if !ref.attempted {
				state.abandonUnstarted(ref)
				return err
			}
			return errors.Join(err, j.finishActivity(ctx, ref))
		}
		lease := &operationLease{journal: j, owner: historyIdentity{tenant: tenant, owner: owner}, generation: generation, activity: ref}
		operationErr := j.runTenantExportSource(ctx, lease, authorize, fn)
		return errors.Join(operationErr, j.finishActivity(ctx, ref))
	})
}

func (j *Journal) runTenantExportSource(parent context.Context, lease *operationLease, authorize AuthorizeMaintenance, fn func(context.Context, func(context.Context) error) error) (result error) {
	owned, cancel := context.WithCancelCause(parent)
	current := context.WithValue(owned, tenantExportLeaseKey{}, lease)
	check := func(ctx context.Context) error {
		if err := j.exportLeaseScope(ctx, lease); err != nil {
			return err
		}
		bounded, stop := context.WithTimeout(ctx, exportAuthorityTimeout)
		defer stop()
		if err := authorize(bounded, lease.owner.tenant); err != nil {
			return messageError(ctx, err)
		}
		generation, err := j.exportGeneration(bounded)
		if err != nil {
			return err
		}
		if generation != lease.generation {
			return ErrJournalGeneration
		}
		return nil
	}
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(exportAuthorityRecheck)
		defer ticker.Stop()
		for {
			select {
			case <-current.Done():
				done <- current.Err()
				return
			case <-ticker.C:
				if err := check(current); err != nil {
					if current.Err() == nil {
						cancel(err)
					}
					done <- err
					return
				}
			}
		}
	}()
	// Closing admission precedes actual nested-reader and watcher join. A
	// canceled context cannot retire a writer that has not actually returned.
	defer func() {
		lease.finish(func() { cancel(context.Canceled) })
		watchErr := <-done
		if result == nil && watchErr != nil && !errors.Is(watchErr, context.Canceled) && !errors.Is(watchErr, errTenantExportClosed) {
			result = watchErr
		}
		if result == nil {
			result = parent.Err()
		}
	}()
	if err := check(current); err != nil {
		return err
	}
	if err := fn(current, check); err != nil {
		return err
	}
	if err := check(current); err != nil {
		return err
	}
	return nil
}

func (j *Journal) exportLeaseScope(ctx context.Context, lease *operationLease) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || lease == nil || lease.journal != j || tenant.String() != lease.owner.tenant || auth.PrincipalFrom(ctx) != nil || ctx.Value(operationLeaseKey{}) != nil || ctx.Value(subjectSourceLeaseKey{}) != nil || ctx.Value(tenantExportLeaseKey{}) != lease || lease.activity == nil || !lease.activity.runtime.isActive(lease.activity) {
		return ErrMessageDenied
	}
	lease.mu.Lock()
	closed := lease.closed
	lease.mu.Unlock()
	if closed {
		return errors.Join(ErrMessageDenied, errTenantExportClosed)
	}
	return nil
}

func (j *Journal) exportGeneration(ctx context.Context) (uint64, error) {
	var generation uint64
	err := j.scoped(ctx, func(ctx context.Context, scope tenancy.Scope) error {
		if err := bindLifecycle(ctx, scope); err != nil {
			return err
		}
		var err error
		generation, err = activeConversationEpoch(ctx, scope, epochRead)
		return err
	})
	return generation, journalError(ctx, err)
}

func (j *Journal) checkExportActivityContext(ctx context.Context, sc tenancy.Scope, lease *operationLease) error {
	if err := j.exportLeaseScope(ctx, lease); err != nil {
		return err
	}
	if sc.Tenant.String() != lease.owner.tenant {
		return ErrMessageDenied
	}
	if err := bindLifecycle(ctx, sc); err != nil {
		return err
	}
	if err := assertActivityGuard(ctx, sc); err != nil {
		return err
	}
	ref := lease.activity
	var live bool
	if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND operation_id=$3::uuid AND instance_id=$4::uuid AND epoch=$5 AND drained_at IS NULL)`, ref.tenant, ref.owner, ref.operation, ref.instance, int64(ref.generation)).Scan(&live); err != nil {
		return err
	}
	if !live {
		return ErrJournalLease
	}
	generation, err := activeConversationEpoch(ctx, sc, epochRead)
	if err != nil {
		return err
	}
	if generation != lease.generation {
		return ErrJournalGeneration
	}
	return nil
}

func (j *Journal) registerExportActivity(ctx context.Context, ref *activityRef, generation uint64) error {
	err := j.fence.WithTenantWrites(ctx, []string{ref.tenant}, func(ctx context.Context) error {
		return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
			if sc.Tenant.String() != ref.tenant {
				return ErrMessageDenied
			}
			if err := bindLifecycle(ctx, sc); err != nil {
				return err
			}
			if err := assertActivityGuard(ctx, sc); err != nil {
				return err
			}
			if err := audit.LockTenantStream(ctx, sc.Q, ref.tenant); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO flow_conversation_epochs(tenant_id,generation) VALUES($1::uuid,1) ON CONFLICT(tenant_id) DO NOTHING`, ref.tenant); err != nil {
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
			return j.record(ctx, sc, "system:flow-conversation", "flow.conversation.export_started", ref.operation, map[string]any{"instance_id": ref.instance, "generation": ref.generation, "purpose": "tenant_export"})
		})
	})
	return journalError(ctx, err)
}
