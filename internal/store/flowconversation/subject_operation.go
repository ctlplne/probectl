// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type subjectSourceLeaseKey struct{}
type subjectSourceLease struct {
	operation *operationLease
	pending   Invalidation
	authorize AuthorizeMaintenance
	mu        sync.Mutex
	readerErr error
}

var errSubjectSourceClosed = errors.New("flow conversation: subject matching admission is closed")

// withSubjectMatchSource is solely for destructive matching of the exact
// pending subject plan. It never reopens active-generation export/owner/model
// reads, filters out expired data, deletes anything or acknowledges a crash.
// Its entire callback and every nested matching reader must actually return
// before source-free retirement and the trailing zero-activity check.
func (j *Journal) withSubjectMatchSource(ctx context.Context, codec *Codec, pending Invalidation, authorize AuthorizeMaintenance, fn func(context.Context, SubjectErasurePlan) error) error {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return err
	}
	if pending.value == nil || pending.value.tenant != tenant || pending.value.generation == 0 || pending.value.request.Kind != MaintenanceSubjectErase || !validMaintenanceRequest(pending.value.request) || fn == nil {
		return ErrMessageDenied
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return err
	}
	installed, err := j.historyFamilyInstalled(ctx)
	if err != nil {
		return err
	}
	if !installed {
		return ErrJournalUnavailable
	}
	return j.WithDrainedInvalidation(ctx, pending, authorize, func(ctx context.Context) error {
		state, err := activityRuntimeFor(j.pool)
		if err != nil {
			return err
		}
		owner, err := crypto.UUIDv4()
		if err != nil {
			return ErrJournalUnavailable
		}
		ref, err := state.reserve(ctx, tenant, owner)
		if err != nil {
			return err
		}
		if err := j.registerSubjectActivity(ctx, pending, ref); err != nil {
			if !ref.attempted {
				state.abandonUnstarted(ref)
				return err
			}
			return errors.Join(err, j.finishActivity(ctx, ref))
		}
		// This identity is bookkeeping, not an impersonated historical owner.
		lease := &subjectSourceLease{operation: &operationLease{journal: j,
			owner: historyIdentity{tenant: tenant, owner: owner}, generation: pending.value.generation, activity: ref}, pending: pending, authorize: authorize}
		return func() (result error) {
			// A panic still unwinds the source join before known, source-free
			// retirement. An uncertain audit leaves the existing retry ref.
			defer func() { result = errors.Join(result, j.finishActivity(ctx, ref)) }()
			// The plan is opened only after audited durable registration. This
			// outer maintenance context grants no message source itself.
			current, plan, err := j.ResumeSubjectInvalidation(ctx, codec, pending.value.request.ID, authorize)
			if err != nil {
				return err
			}
			if current.value == nil || *current.value != *pending.value {
				clearSubjectSourcePlan(plan)
				return ErrJournalConflict
			}
			return j.runSubjectMatchSource(ctx, lease, plan, fn)
		}()
	})
}

func clearSubjectSourcePlan(plan SubjectErasurePlan) {
	if plan.value != nil {
		clear(plan.value.wire.Salt)
		clear(plan.value.wire.Aliases)
		clear(plan.value.wire.Application)
		plan.value.wire.Application = nil
		plan.value.wire.Subject = ""
	}
}

func (j *Journal) runSubjectMatchSource(parent context.Context, lease *subjectSourceLease, plan SubjectErasurePlan, fn func(context.Context, SubjectErasurePlan) error) (result error) {
	// The callback borrows this immutable selector. Releasing a standalone
	// resumed plan must not let a callback destroy its active source selector.
	plan.value.borrowed = true
	owned, cancel := context.WithCancelCause(parent)
	current := context.WithValue(owned, subjectSourceLeaseKey{}, lease)
	check := func(ctx context.Context) error { return j.checkSubjectSource(ctx, lease) }
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
					cancel(err)
					done <- err
					return
				}
			}
		}
	}()
	defer func() {
		lease.operation.finish(func() { cancel(context.Canceled) })
		watchErr := <-done
		// Clearing borrowed aliases follows actual nested-reader/watcher join.
		clearSubjectSourcePlan(plan)
		lease.mu.Lock()
		readerErr := lease.readerErr
		lease.mu.Unlock()
		if result == nil {
			result = readerErr
		}
		if result == nil && watchErr != nil && !errors.Is(watchErr, context.Canceled) && !errors.Is(watchErr, errSubjectSourceClosed) {
			result = watchErr
		}
		if result == nil {
			result = parent.Err()
		}
	}()
	if err := check(current); err != nil {
		return err
	}
	if err := fn(current, plan); err != nil {
		return err
	}
	return check(current)
}

// withSubjectReader joins the whole source-bearing callback, including decoded
// buffers after SQL returned. No canceled context or released SQL lease can
// retire it early. New readers cannot enter after the outer callback closes.
func (j *Journal) withSubjectReader(ctx context.Context, fn func(context.Context) error) (result error) {
	lease, ok := ctx.Value(subjectSourceLeaseKey{}).(*subjectSourceLease)
	if !ok || fn == nil || j.subjectSourceScope(ctx, lease) != nil || !lease.operation.enter() {
		return messageError(ctx, ErrMessageDenied)
	}
	defer func() {
		lease.mu.Lock()
		if result != nil && lease.readerErr == nil {
			lease.readerErr = result
		}
		lease.mu.Unlock()
		lease.operation.readers.Done()
	}()
	if err := j.checkSubjectSource(ctx, lease); err != nil {
		return err
	}
	if err := fn(ctx); err != nil {
		return err
	}
	return j.checkSubjectSource(ctx, lease)
}

func (j *Journal) subjectSourceScope(ctx context.Context, lease *subjectSourceLease) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || lease == nil || lease.operation == nil || lease.pending.value == nil || lease.authorize == nil || ctx.Value(subjectSourceLeaseKey{}) != lease || auth.PrincipalFrom(ctx) != nil || ctx.Value(operationLeaseKey{}) != nil || ctx.Value(tenantExportLeaseKey{}) != nil {
		return ErrMessageDenied
	}
	op, pending := lease.operation, lease.pending.value
	if op.journal != j || op.owner.tenant != tenant.String() || pending.tenant != tenant.String() || pending.request.Kind != MaintenanceSubjectErase || !validMaintenanceRequest(pending.request) || op.generation == 0 || op.generation != pending.generation || op.activity == nil || op.activity.runtime == nil || op.activity.tenant != tenant.String() || op.activity.owner != op.owner.owner || op.activity.generation != op.generation || !op.activity.runtime.isActive(op.activity) {
		return ErrMessageDenied
	}
	op.mu.Lock()
	closed := op.closed
	op.mu.Unlock()
	if closed {
		return errors.Join(ErrMessageDenied, errSubjectSourceClosed)
	}
	return nil
}

func (j *Journal) checkSubjectSource(ctx context.Context, lease *subjectSourceLease) error {
	if err := j.subjectSourceScope(ctx, lease); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, exportAuthorityTimeout)
	defer cancel()
	if err := lease.authorize(bounded, lease.pending.value.tenant); err != nil {
		return messageError(ctx, err)
	}
	// scoped checks the durable pending state and actual activity below. It
	// deliberately never calls an active-generation epoch helper.
	err := j.scoped(bounded, func(context.Context, tenancy.Scope) error { return nil })
	return journalError(ctx, err)
}

func (j *Journal) checkSubjectActivityContext(ctx context.Context, sc tenancy.Scope, lease *subjectSourceLease) error {
	if err := j.subjectSourceScope(ctx, lease); err != nil {
		return err
	}
	if sc.Tenant.String() != lease.pending.value.tenant {
		return ErrMessageDenied
	}
	if err := bindLifecycle(ctx, sc); err != nil {
		return err
	}
	if err := assertActivityGuard(ctx, sc); err != nil {
		return err
	}
	state, err := readConversationEpoch(ctx, sc, epochRead)
	if err != nil {
		return err
	}
	if !state.matches(lease.pending.value.request) || state.generation != lease.pending.value.generation {
		return ErrJournalGeneration
	}
	ref := lease.operation.activity
	var live bool
	if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND operation_id=$3::uuid AND instance_id=$4::uuid AND epoch=$5 AND drained_at IS NULL)`, ref.tenant, ref.owner, ref.operation, ref.instance, int64(ref.generation)).Scan(&live); err != nil {
		return err
	}
	if !live {
		return ErrJournalLease
	}
	return nil
}

func (j *Journal) registerSubjectActivity(ctx context.Context, pending Invalidation, ref *activityRef) error {
	err := j.fence.WithTenantWrites(ctx, []string{ref.tenant}, func(ctx context.Context) error {
		return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
			if sc.Tenant.String() != ref.tenant || pending.value.tenant != ref.tenant {
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
			state, err := readConversationEpoch(ctx, sc, epochUpdate)
			if err != nil {
				return err
			}
			if !state.matches(pending.value.request) || state.generation != pending.value.generation {
				return ErrJournalGeneration
			}
			var active bool
			if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND drained_at IS NULL)`, ref.tenant).Scan(&active); err != nil {
				return err
			}
			if active {
				return ErrJournalDraining
			}
			if err := ref.runtime.setAttempt(ref, state.generation); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO flow_conversation_activity(tenant_id,owner_id,operation_id,instance_id,epoch) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5)`, ref.tenant, ref.owner, ref.operation, ref.instance, int64(ref.generation)); err != nil {
				return err
			}
			return j.record(ctx, sc, "system:flow-conversation", "flow.conversation.subject_match_started", ref.operation, map[string]any{"instance_id": ref.instance, "generation": ref.generation, "pending_operation_id": pending.value.request.ID, "purpose": "subject_erase"})
		})
	})
	return journalError(ctx, err)
}
