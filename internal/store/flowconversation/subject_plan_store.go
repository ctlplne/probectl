// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// BeginSubjectInvalidation commits the encrypted immutable selector with its
// audited refusal marker. No source, destructive completion or clear authority
// follows from this reference. Exact retries use the same prepared plan.
func (j *Journal) BeginSubjectInvalidation(ctx context.Context, codec *Codec, plan SubjectErasurePlan, authorize AuthorizeMaintenance) (Invalidation, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return Invalidation{}, err
	}
	if plan.value == nil || plan.value.tenant != tenant {
		return Invalidation{}, ErrMessageDenied
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return Invalidation{}, err
	}
	stored, err := codec.sealSubjectPlan(ctx, plan)
	if err != nil {
		return Invalidation{}, err
	}
	pending, err := j.beginInvalidation(ctx, plan.value.request, stored, authorize)
	if err != nil {
		return Invalidation{}, err
	}
	// Even an exact marker retry must have a valid durable selector; a generic
	// marker with the same metadata alone cannot fabricate the plan envelope.
	current, _, err := j.ResumeSubjectInvalidation(ctx, codec, plan.value.request.ID, authorize)
	if err != nil {
		return Invalidation{}, err
	}
	if current.value == nil || *current.value != *pending.value {
		return Invalidation{}, ErrJournalConflict
	}
	return current, nil
}

// ResumeSubjectInvalidation reloads the exact durable encrypted plan without
// consulting mutable directory aliases. Independent current authority surrounds
// decryption. Returned private metadata still grants no message source access.
func (j *Journal) ResumeSubjectInvalidation(ctx context.Context, codec *Codec, operation string, authorize AuthorizeMaintenance) (Invalidation, SubjectErasurePlan, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return Invalidation{}, SubjectErasurePlan{}, err
	}
	if !historyID(operation) {
		return Invalidation{}, SubjectErasurePlan{}, ErrMessageIntegrity
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return Invalidation{}, SubjectErasurePlan{}, err
	}
	if err := codec.available(); err != nil {
		return Invalidation{}, SubjectErasurePlan{}, err
	}
	var request MaintenanceRequest
	var generation uint64
	var stored *string
	err = j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if sc.Tenant.String() != tenant {
			return ErrMessageDenied
		}
		state, err := readConversationEpoch(ctx, sc, epochRead)
		if err != nil {
			return err
		}
		if !state.invalidating || state.operation == nil || *state.operation != operation || state.kind == nil || *state.kind != string(MaintenanceSubjectErase) {
			return ErrJournalConflict
		}
		request = MaintenanceRequest{ID: operation, Kind: MaintenanceSubjectErase, Binding: bindingArray(state.binding)}
		generation = state.generation
		var size int64
		// A bounded transfer is required before decrypt/JSON allocation. No
		// caller SQL, owner impersonation or source-table SELECT is involved.
		if err := sc.Q.QueryRow(ctx, `SELECT COALESCE(octet_length(operation_plan),0),CASE WHEN octet_length(operation_plan)<=$5 THEN operation_plan ELSE NULL END FROM flow_conversation_epochs WHERE tenant_id=$1::uuid AND operation_id=$2::uuid AND operation_kind='subject_erase' AND operation_binding=$3 AND generation=$4 AND invalidating`, tenant, operation, request.Binding[:], int64(generation), codec.budget.StoredBytes).Scan(&size, &stored); err != nil {
			return err
		}
		if size <= 0 {
			return ErrMessageIntegrity
		}
		if size > int64(codec.budget.StoredBytes) {
			return ErrMessageBudget
		}
		if stored == nil {
			return ErrMessageIntegrity
		}
		return nil
	})
	if err != nil {
		return Invalidation{}, SubjectErasurePlan{}, journalError(ctx, err)
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return Invalidation{}, SubjectErasurePlan{}, err
	}
	plan, err := codec.openSubjectPlan(ctx, request, *stored)
	if err != nil {
		return Invalidation{}, SubjectErasurePlan{}, err
	}
	pending, err := j.ResumeInvalidation(ctx, request, authorize)
	if err != nil {
		return Invalidation{}, SubjectErasurePlan{}, err
	}
	if pending.value == nil || pending.value.generation != generation {
		return Invalidation{}, SubjectErasurePlan{}, ErrJournalGeneration
	}
	return pending, plan, nil
}
