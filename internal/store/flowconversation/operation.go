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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var operationAdmissions sync.Map // One budget across Journal instances sharing a pool.

// A lease connection is separate from the bounded working transactions. Keep
// working capacity for canonical writer, source and audit operations; a nested
// source operation reuses its lease rather than acquiring another connection.
func operationAdmission(pool *pgxpool.Pool) (chan struct{}, error) {
	if pool == nil || pool.Config().MaxConns < 4 {
		return nil, ErrJournalUnavailable
	}
	capacity := max(1, (int(pool.Config().MaxConns)-1)/3)
	gate, _ := operationAdmissions.LoadOrStore(pool, make(chan struct{}, capacity))
	return gate.(chan struct{}), nil
}

type operationLeaseKey struct{}
type operationLease struct {
	journal    *Journal
	owner      historyIdentity
	generation uint64
	activity   *activityRef
	mu         sync.Mutex
	closed     bool
	readers    sync.WaitGroup
}

func (lease *operationLease) enter() bool {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return false
	}
	lease.readers.Add(1)
	return true
}

// Stop accepting nested work before waiting. Context values can escape their
// original callback; retaining one never revives an already released SQL lease.
func (lease *operationLease) finish(cancel context.CancelFunc) {
	lease.mu.Lock()
	lease.closed = true
	lease.mu.Unlock()
	cancel()
	lease.readers.Wait()
}

// WithReadLease holds only the tenant-family read/drain lease while fn uses
// private source. It grants no permissions or execution authority. The callback
// must release its private buffers and drain actual IO before returning.
func (j *Journal) WithReadLease(ctx context.Context, authorize AuthorizeHistory, fn func(context.Context) error) error {
	id, err := historyIdentityFor(ctx)
	if err != nil {
		return err
	}
	if fn == nil {
		return ErrMessageIntegrity
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return err
	}
	if lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok {
		if lease == nil || lease.journal != j || lease.owner.tenant != id.tenant || lease.owner.owner != id.owner || !sameRequestOrigin(lease.owner.origin, id.origin) {
			return ErrMessageDenied
		}
		if !lease.enter() {
			return ErrMessageDenied
		}
		defer lease.readers.Done()
		if err := j.checkOperationEpoch(ctx, lease.generation); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		if err := j.checkOperationEpoch(ctx, lease.generation); err != nil {
			return err
		}
		return id.authorize(ctx, authorize)
	}
	err = j.operationLease(ctx, id.tenant, false, func(ctx context.Context) (operationError error) {
		if err := id.authorize(ctx, authorize); err != nil {
			return err
		}
		generation, err := j.CandidateEpoch(ctx)
		if err != nil {
			return err
		}
		state, err := activityRuntimeFor(j.pool)
		if err != nil {
			return err
		}
		ref, err := state.reserve(ctx, id.tenant, id.owner)
		if err != nil {
			return err
		}
		if err := j.registerActivity(ctx, id, ref, generation); err != nil {
			if !ref.attempted {
				state.abandonUnstarted(ref)
				return err
			}
			return errors.Join(err, j.finishActivity(ctx, ref))
		}
		lease := &operationLease{journal: j, owner: id, generation: generation, activity: ref}
		owned, cancel := context.WithCancel(ctx)
		defer func() { lease.finish(cancel); operationError = errors.Join(operationError, j.finishActivity(ctx, ref)) }()
		current := context.WithValue(owned, operationLeaseKey{}, lease)
		if err := j.checkOperationEpoch(current, generation); err != nil {
			return err
		}
		if err := fn(current); err != nil {
			return err
		}
		if err := j.checkOperationEpoch(ctx, generation); err != nil {
			return err
		}
		return id.authorize(ctx, authorize)
	})
	return err
}

// AuthorizeMaintenance reloads independent current tenant operational authority.
// It cannot borrow an old creator's credential, select lifecycle binding from a
// model/request flag, or imply permission to decrypt source. Concrete lifecycle
// methods must separately authorize/audit/count every operation they perform.
type AuthorizeMaintenance func(context.Context, string) error

// WithMaintenanceLease is only a bounded drain barrier, never an erasure proof.
// No callback enters until actual read/planner callbacks have returned. A
// canceled but still-running callback keeps the barrier closed. Ordinary owner
// and provider request contexts are refused before operational authority/SQL.
func (j *Journal) WithMaintenanceLease(ctx context.Context, authorize AuthorizeMaintenance, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return err
	}
	if authorize == nil || fn == nil {
		return ErrMessageDenied
	}
	check := func(ctx context.Context) error {
		current, err := maintenanceTenant(ctx)
		if err != nil || current != tenant {
			return messageError(ctx, ErrMessageDenied)
		}
		if err := authorize(ctx, tenant); err != nil {
			return messageError(ctx, ErrMessageDenied)
		}
		return ctx.Err()
	}
	if err := check(ctx); err != nil {
		return err
	}
	err = j.operationLease(ctx, tenant, true, func(ctx context.Context) error {
		if err := check(ctx); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		return check(ctx)
	})
	return err
}

func maintenanceTenant(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || !historyID(tenant.String()) || auth.PrincipalFrom(ctx) != nil || ctx.Value(operationLeaseKey{}) != nil {
		return "", ErrMessageDenied
	}
	return tenant.String(), nil
}

func (j *Journal) operationLease(ctx context.Context, tenant string, exclusive bool, fn func(context.Context) error) error {
	if err := j.available(); err != nil {
		return err
	}
	admission, err := operationAdmission(j.pool)
	if err != nil {
		return err
	}
	select {
	case admission <- struct{}{}:
		defer func() { <-admission }()
	case <-ctx.Done():
		return ctx.Err()
	}
	// No canonical writer, audit, epoch or job lock is held here. Nested
	// mutations retain their existing short lock order on other connections.
	var callbackError error
	err = j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if sc.Tenant.String() != tenant {
			return ErrMessageDenied
		}
		query := `SELECT pg_advisory_xact_lock_shared(hashtextextended('probectl.flow_conversations.operation:' || $1::text,0))`
		if exclusive {
			query = `SELECT pg_advisory_xact_lock(hashtextextended('probectl.flow_conversations.operation:' || $1::text,0))`
		}
		if _, err := sc.Q.Exec(ctx, query, tenant); err != nil {
			return err
		}
		callbackError = fn(ctx)
		return callbackError
	})
	if err := ctx.Err(); err != nil {
		return err
	}
	// The caller owns bounded application errors, including consent/audit and
	// source refusals. Only failures of this lease's SQL are storage errors.
	if callbackError != nil {
		return callbackError
	}
	return journalError(ctx, err)
}

func (j *Journal) checkOperationEpoch(ctx context.Context, generation uint64) error {
	if generation == 0 {
		return ErrJournalGeneration
	}
	current, err := j.CandidateEpoch(ctx)
	if err != nil {
		return err
	}
	if current != generation {
		return ErrJournalGeneration
	}
	return nil
}
