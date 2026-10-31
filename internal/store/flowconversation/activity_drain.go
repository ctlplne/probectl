// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrJournalDraining = errors.New("flow conversation: source operations have not acknowledged actual drain")

type ActivityBudget struct {
	Rows      int
	TimeLimit time.Duration
}
type ActivityRetry struct{ Acknowledged, Pending int }

func (ActivityRetry) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (ActivityRetry) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "flowconversation.ActivityRetry[private]")
}

// RetryDrainedOperations retries only private references whose actual callbacks
// already returned in this process. No database discovery adopts an old live
// operation or creator credential. Unknown/crashed work is never TTL-expired.
func (j *Journal) RetryDrainedOperations(ctx context.Context, budget ActivityBudget, authorize AuthorizeMaintenance) (ActivityRetry, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return ActivityRetry{}, err
	}
	if budget.Rows <= 0 || budget.TimeLimit <= 0 {
		return ActivityRetry{}, ErrMessageBudget
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return ActivityRetry{}, err
	}
	if err := j.available(); err != nil {
		return ActivityRetry{}, err
	}
	state, err := activityRuntimeFor(j.pool)
	if err != nil {
		return ActivityRetry{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.TimeLimit)
	defer cancel()
	refs, _ := state.retries(tenant, budget.Rows)
	var result ActivityRetry
	for _, ref := range refs {
		if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
			return ActivityRetry{}, err
		}
		if !state.claimRetry(ref) {
			continue
		}
		err := j.retireActivity(ctx, ref)
		state.finishRetirement(ref, err)
		if err != nil {
			return ActivityRetry{}, err
		}
		result.Acknowledged++
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return ActivityRetry{}, err
	}
	_, result.Pending = state.retries(tenant, budget.Rows)
	return result, nil
}

// WithDrainedInvalidation adds the durable actual-operation check to the exact
// intent/family barrier. Zero active jobs or a lost SQL family lease is not a
// drain proof. Artifact/key counts and a completed lifecycle remain separate.
func (j *Journal) WithDrainedInvalidation(ctx context.Context, pending Invalidation, authorize AuthorizeMaintenance, fn func(context.Context) error) error {
	if fn == nil {
		return messageError(ctx, ErrMessageDenied)
	}
	check := func(ctx context.Context) error {
		err := j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
			if err := bindLifecycle(ctx, sc); err != nil {
				return err
			}
			if err := assertActivityGuard(ctx, sc); err != nil {
				return err
			}
			var active bool
			if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND drained_at IS NULL)`, sc.Tenant.String()).Scan(&active); err != nil {
				return err
			}
			if active {
				return ErrJournalDraining
			}
			return nil
		})
		return journalError(ctx, err)
	}
	return j.WithInvalidationLease(ctx, pending, authorize, func(ctx context.Context) error {
		if err := check(ctx); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		return check(ctx)
	})
}
