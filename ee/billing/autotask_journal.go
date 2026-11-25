// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"context"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type autotaskAdjustmentKey struct {
	CompanyID         int64
	ContractID        int64
	ContractServiceID int64
}

type autotaskAdjustment struct {
	Key         autotaskAdjustmentKey
	EffectiveAt time.Time
	Previous    int64
	Desired     int64
}

type pendingAutotaskAdjustment struct {
	autotaskAdjustment
	Tenant   tenancy.ID
	Sequence int64
}

type autotaskAdjustmentJournal struct{ pool *pgxpool.Pool }

const (
	autotaskBillingActor    = "system:psa-billing"
	autotaskRequestedAction = "billing.autotask.adjustment.requested"
	autotaskResolvedAction  = "billing.autotask.adjustment.resolved"
)

var (
	errInvalidAutotaskAdjustment = errors.New("billing: invalid Autotask adjustment")
	errAutotaskAdjustmentPending = errors.New("billing: an Autotask adjustment is already pending")
)

func (a autotaskAdjustment) delta() (int64, error) {
	for _, id := range []int64{a.Key.CompanyID, a.Key.ContractID, a.Key.ContractServiceID} {
		if id <= 0 || id > math.MaxInt32 {
			return 0, errInvalidAutotaskAdjustment
		}
	}
	if a.EffectiveAt.IsZero() || a.Previous < 0 || a.Previous > math.MaxInt32 ||
		a.Desired < 0 || a.Desired > math.MaxInt32 || a.Previous == a.Desired {
		return 0, errInvalidAutotaskAdjustment
	}
	return a.Desired - a.Previous, nil
}

// reserve grants a new send claim only when its journal row and audit intent
// commit together. An existing row is recoverable by readback, never a new
// send claim. Callers may act only on the claim returned by this invocation.
func (j autotaskAdjustmentJournal) reserve(ctx context.Context, a autotaskAdjustment) (*pendingAutotaskAdjustment, error) {
	delta, err := a.delta()
	if err != nil {
		return nil, err
	}
	a.EffectiveAt = a.EffectiveAt.UTC().Truncate(time.Microsecond)
	var claim *pendingAutotaskAdjustment
	err = tenancy.InTenant(ctx, j.pool, func(ctx context.Context, scope tenancy.Scope) error {
		if err := tenancy.RequireTenantCollection(ctx, scope); err != nil {
			return err
		}
		if err := lockPSAJournal(ctx, scope); err != nil {
			return err
		}
		event, err := audit.TenantAppend(ctx, scope, autotaskBillingActor, autotaskRequestedAction,
			strconv.FormatInt(a.Key.ContractServiceID, 10), map[string]any{
				"company_id": a.Key.CompanyID, "contract_id": a.Key.ContractID,
				"effective_at": a.EffectiveAt, "previous_units": a.Previous, "desired_units": a.Desired, "unit_change": delta,
			})
		if err != nil {
			return err
		}
		tag, err := scope.Q.Exec(ctx, `
INSERT INTO psa_autotask_adjustment_pending
(tenant_id, company_id, contract_id, contract_service_id, requested_seq, effective_at, previous_units, desired_units)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, company_id, contract_id, contract_service_id) DO NOTHING`,
			scope.Tenant.String(), a.Key.CompanyID, a.Key.ContractID, a.Key.ContractServiceID, event.Seq, a.EffectiveAt, a.Previous, a.Desired)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errAutotaskAdjustmentPending
		}
		claim = &pendingAutotaskAdjustment{autotaskAdjustment: a, Tenant: scope.Tenant, Sequence: event.Seq}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

// The caller may read this within its already held egress transaction. The
// returned row cannot confer a new send claim.
func readAutotaskAdjustment(ctx context.Context, scope tenancy.Scope, key autotaskAdjustmentKey) (*pendingAutotaskAdjustment, error) {
	pending := pendingAutotaskAdjustment{
		autotaskAdjustment: autotaskAdjustment{Key: key},
		Tenant:             scope.Tenant,
	}
	err := scope.Q.QueryRow(ctx, `
SELECT requested_seq, effective_at, previous_units, desired_units
FROM psa_autotask_adjustment_pending
WHERE tenant_id=$1 AND company_id=$2 AND contract_id=$3 AND contract_service_id=$4`,
		scope.Tenant.String(), key.CompanyID, key.ContractID, key.ContractServiceID).
		Scan(&pending.Sequence, &pending.EffectiveAt, &pending.Previous, &pending.Desired)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &pending, nil
}

type autotaskResolution string

const (
	autotaskQuantityObserved autotaskResolution = "quantity_observed"
	autotaskAdjustmentUnsent autotaskResolution = "not_sent"
)

// resolve closes only the exact attempt that was observed or definitely stayed
// local. A stale closure cannot delete a newer attempt for the same service.
func (j autotaskAdjustmentJournal) resolve(ctx context.Context, a pendingAutotaskAdjustment, outcome autotaskResolution) (bool, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != a.Tenant || a.Sequence <= 0 {
		return false, tenancy.ErrNoTenant
	}
	if outcome != autotaskQuantityObserved && outcome != autotaskAdjustmentUnsent {
		return false, errInvalidAutotaskAdjustment
	}
	closed := false
	err := tenancy.InTenant(ctx, j.pool, func(ctx context.Context, scope tenancy.Scope) error {
		if err := tenancy.AcquireTenantWriteLease(ctx, scope); err != nil {
			return err
		}
		if err := lockPSAJournal(ctx, scope); err != nil {
			return err
		}
		var desired int64
		err := scope.Q.QueryRow(ctx, `
DELETE FROM psa_autotask_adjustment_pending
WHERE tenant_id=$1 AND company_id=$2 AND contract_id=$3 AND contract_service_id=$4 AND requested_seq=$5
RETURNING desired_units`, scope.Tenant.String(), a.Key.CompanyID, a.Key.ContractID, a.Key.ContractServiceID, a.Sequence).Scan(&desired)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		closed = true
		return audit.TenantRecord(ctx, scope, autotaskBillingActor, autotaskResolvedAction,
			strconv.FormatInt(a.Key.ContractServiceID, 10), map[string]any{
				"request_seq": a.Sequence, "outcome": string(outcome), "desired_units": desired,
			})
	})
	return closed && err == nil, err
}

func lockPSAJournal(ctx context.Context, scope tenancy.Scope) error {
	_, err := scope.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(`+psaTenantLockKey+`)`, scope.Tenant.String())
	return err
}
