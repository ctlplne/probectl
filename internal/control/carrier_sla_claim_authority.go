// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"reflect"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type carrierSLAClaimRequirement struct {
	agreement flow.CapacityAgreement
	sources   []store.IncidentConfiguredTest
}

// Replaying circuits can take time. This final metadata-only pass checks every
// selected contract and source in one tenant snapshot, so an earlier circuit's
// grant cannot be withdrawn during a later replay and survive publication.
func (s *Server) revalidateCarrierSLAClaimInScope(ctx context.Context, sc tenancy.Scope, op capacityAgreementOperation, requirement carrierSLAClaimRequirement) error {
	current, err := readCurrentUserAuthorityScope(ctx, sc, op.actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, op.actor)
	if err != nil {
		return err
	}
	before := requirement.agreement
	after, err := op.store.CapacityAgreementInScope(ctx, sc, op.actor.UserID, before.ID, before.Version, nil)
	if err != nil {
		return err
	}
	if after.TenantID != before.TenantID || after.CurrentVersion != before.CurrentVersion || !after.TargetPresent || !after.SLASourceMetadataTrusted || !reflect.DeepEqual(after.Definition, before.Definition) {
		return apierror.Unavailable("claim terms or canonical source links changed; retry")
	}
	if _, _, err := s.capacityBillMembersInScope(ctx, sc, principal, after.Definition.Target, op.budget.MemoryBytes/8, func(ctx context.Context, record entity.ContextRecord) error {
		if record.TenantID != principal.TenantID {
			return entity.ErrScopeMismatch
		}
		return s.authorizeClientReportTests(ctx, principal, entityContextResource(record))
	}); err != nil {
		return err
	}
	return s.revalidateClientReportTestsInScope(ctx, sc, op.actor, requirement.sources, op.budget.MemoryBytes/8)
}
