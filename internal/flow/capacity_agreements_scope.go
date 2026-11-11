// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// CapacityAgreementInScope joins a serving calculation's existing RLS snapshot
// so current financial authority, immutable terms, source membership and original
// receipts can be revalidated at one database instant. A configured serving
// authorizer is mandatory; this method grants no lifecycle/background authority.
func (s *PostgresCapacityAgreements) CapacityAgreementInScope(ctx context.Context, sc tenancy.Scope, actor, id, version string, at *time.Time) (CapacityAgreement, error) {
	none := CapacityAgreement{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant != sc.Tenant || sc.Q == nil {
		return none, tenancy.ErrNoTenant
	}
	if s == nil || s.pool == nil || s.authorize == nil || s.stateBytes <= 0 || s.memoryBytes < 1<<20 || s.workUnits < 4096 || s.executionLimit <= 0 ||
		!capacityAgreementText(actor, true) || !capacityAgreementUUID(id) || at != nil && version != "" {
		return none, ErrCapacityAgreementInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.executionLimit)
	defer cancel()
	if err := s.authorize(ctx, sc, actor, false); err != nil {
		return none, err
	}
	var selected int64
	var effective string
	if version != "" {
		var err error
		selected, err = capacityAgreementVersion(version)
		if err != nil {
			return none, err
		}
	}
	if at != nil {
		effective = capacityAgreementNanos(*at)
	}
	return s.read(ctx, sc, id, selected, effective)
}

type CapacityBillingPeriod struct {
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	Timezone       string    `json:"timezone"`
	BillingDay     int       `json:"billing_day"`
	BoundaryPolicy string    `json:"boundary_policy"`
}

func CapacityBillingPeriodAt(ctx context.Context, definition CapacityAgreementDefinition, at time.Time, memoryBytes, workUnits int64) (CapacityBillingPeriod, error) {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound {
		return CapacityBillingPeriod{}, tenancy.ErrNoTenant
	}
	period, err := capacityBillingPeriodAt(ctx, capacityBillingCalendar{tenant: tenant.String(), timezone: definition.Timezone, day: definition.BillingDay}, at, memoryBytes, workUnits)
	if err != nil {
		return CapacityBillingPeriod{}, err
	}
	return CapacityBillingPeriod{From: period.from, To: period.to, Timezone: period.timezone, BillingDay: period.requestedDay, BoundaryPolicy: period.boundaryPolicy}, nil
}
