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

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type MaintenanceKind string

const (
	MaintenanceTenantErase  MaintenanceKind = "tenant_erase"
	MaintenanceSubjectErase MaintenanceKind = "subject_erase"
	MaintenanceRetention    MaintenanceKind = "retention"
	MaintenanceKeyRotation  MaintenanceKind = "key_rotation"
)

// MaintenanceRequest is internal lifecycle metadata. Binding identifies the
// separately authorized immutable operation plan, never a permission grant or
// raw subject selector. Public transports must not accept this representation.
type MaintenanceRequest struct {
	ID      string
	Kind    MaintenanceKind
	Binding [32]byte
}

func (MaintenanceRequest) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*MaintenanceRequest) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (MaintenanceRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "flowconversation.MaintenanceRequest[private]")
}
func validMaintenanceRequest(request MaintenanceRequest) bool {
	if !historyID(request.ID) || request.Binding == ([32]byte{}) {
		return false
	}
	switch request.Kind {
	case MaintenanceTenantErase, MaintenanceSubjectErase, MaintenanceRetention, MaintenanceKeyRotation:
		return true
	default:
		return false
	}
}

// Invalidation is a private reference to pending work, never a completed
// erasure/drain receipt or authority to open source. Every use reloads current
// independent authority and the exact durable plan binding.
type Invalidation struct{ value *invalidation }
type invalidation struct {
	tenant     string
	request    MaintenanceRequest
	generation uint64
}

func (Invalidation) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*Invalidation) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (Invalidation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "flowconversation.Invalidation[pending/private]")
}

func authorizeMaintenance(ctx context.Context, tenant string, authorize AuthorizeMaintenance) error {
	current, err := maintenanceTenant(ctx)
	if err != nil || current != tenant || authorize == nil {
		return messageError(ctx, ErrMessageDenied)
	}
	if err := authorize(ctx, tenant); err != nil {
		return messageError(ctx, ErrMessageDenied)
	}
	return ctx.Err()
}

// BeginInvalidation commits a short audited refusal marker before waiting for
// actual IO drain. It does not delete data, claim all job metadata canceled or
// clear itself on timeout. Full-tenant callers begin before their audit fence;
// later phases require separately authorized lifecycle receipts.
func (j *Journal) BeginInvalidation(ctx context.Context, request MaintenanceRequest, authorize AuthorizeMaintenance) (Invalidation, error) {
	return j.beginInvalidation(ctx, request, "", authorize)
}

func (j *Journal) beginInvalidation(ctx context.Context, request MaintenanceRequest, plan string, authorize AuthorizeMaintenance, validate ...func(context.Context, tenancy.Scope) error) (Invalidation, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return Invalidation{}, err
	}
	if !validMaintenanceRequest(request) {
		return Invalidation{}, ErrMessageIntegrity
	}
	if len(validate) > 1 || len(validate) == 1 && validate[0] == nil {
		return Invalidation{}, ErrMessageDenied
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return Invalidation{}, err
	}
	if err := j.available(); err != nil {
		return Invalidation{}, err
	}
	var result Invalidation
	err = j.fence.WithTenantWrites(ctx, []string{tenant}, func(ctx context.Context) error {
		return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
			if sc.Tenant.String() != tenant {
				return ErrMessageDenied
			}
			if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO flow_conversation_epochs(tenant_id,generation) VALUES($1::uuid,1) ON CONFLICT (tenant_id) DO NOTHING`, tenant); err != nil {
				return err
			}
			state, err := readConversationEpoch(ctx, sc, epochUpdate)
			if err != nil {
				return err
			}
			if state.invalidating {
				if !state.matches(request) {
					return ErrJournalConflict
				}
				if len(validate) == 1 {
					if err := validate[0](ctx, sc); err != nil {
						return err
					}
				}
				result = Invalidation{&invalidation{tenant, request, state.generation}}
				return nil
			}
			if state.generation >= math.MaxInt64 {
				return ErrJournalGeneration
			}
			if len(validate) == 1 {
				if err := validate[0](ctx, sc); err != nil {
					return err
				}
			}
			next := state.generation + 1
			query := `UPDATE flow_conversation_epochs SET generation=$2,invalidating=true,operation_id=$3::uuid,operation_kind=$4,operation_binding=$5 WHERE tenant_id=$1::uuid AND generation=$6 AND NOT invalidating`
			args := []any{tenant, int64(next), request.ID, string(request.Kind), request.Binding[:], int64(state.generation)}
			if plan != "" {
				if request.Kind != MaintenanceSubjectErase {
					return ErrMessageIntegrity
				}
				query = `UPDATE flow_conversation_epochs SET generation=$2,invalidating=true,operation_id=$3::uuid,operation_kind=$4,operation_binding=$5,operation_plan=$7 WHERE tenant_id=$1::uuid AND generation=$6 AND NOT invalidating`
				args = append(args, plan)
			}
			changed, err := sc.Q.Exec(ctx, query, args...)
			if err != nil {
				return err
			}
			if changed.RowsAffected() != 1 {
				return ErrJournalGeneration
			}
			if err := j.record(ctx, sc, "system:flow-conversation", "flow.conversation.invalidate_intent", request.ID, map[string]any{"purpose": string(request.Kind), "generation": next}); err != nil {
				return err
			}
			result = Invalidation{&invalidation{tenant, request, next}}
			return nil
		})
	})
	if err != nil {
		return Invalidation{}, journalError(ctx, err)
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return Invalidation{}, err
	}
	return result, nil
}

func (state conversationEpoch) matches(request MaintenanceRequest) bool {
	return state.invalidating && state.operation != nil && *state.operation == request.ID && state.kind != nil && *state.kind == string(request.Kind) && len(state.binding) == 32 && bindingArray(state.binding) == request.Binding
}

// ResumeInvalidation reloads only the exact pending operation. A restart or
// successor operational credential cannot adopt another plan's pending marker.
// No creator credential, private payload or decryption key is required.
func (j *Journal) ResumeInvalidation(ctx context.Context, request MaintenanceRequest, authorize AuthorizeMaintenance) (Invalidation, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return Invalidation{}, err
	}
	if !validMaintenanceRequest(request) {
		return Invalidation{}, ErrMessageIntegrity
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return Invalidation{}, err
	}
	var result Invalidation
	err = j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if sc.Tenant.String() != tenant {
			return ErrMessageDenied
		}
		state, err := readConversationEpoch(ctx, sc, epochRead)
		if err != nil {
			return err
		}
		if !state.matches(request) {
			return ErrJournalConflict
		}
		result = Invalidation{&invalidation{tenant, request, state.generation}}
		return nil
	})
	if err != nil {
		return Invalidation{}, journalError(ctx, err)
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return Invalidation{}, err
	}
	return result, nil
}

// WithInvalidationLease validates the exact pending intent around an exclusive
// family lease and callback. It neither certifies actual distributed drain nor
// clears the durable flag: counted lifecycle/positive acknowledgements must
// precede any future completion operation.
func (j *Journal) WithInvalidationLease(ctx context.Context, pending Invalidation, authorize AuthorizeMaintenance, fn func(context.Context) error) error {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return err
	}
	if pending.value == nil || pending.value.tenant != tenant || !validMaintenanceRequest(pending.value.request) || pending.value.generation == 0 || fn == nil {
		return ErrMessageDenied
	}
	check := func(ctx context.Context) error {
		current, err := j.ResumeInvalidation(ctx, pending.value.request, authorize)
		if err != nil {
			return err
		}
		if current.value.tenant != tenant || current.value.generation != pending.value.generation {
			return ErrJournalGeneration
		}
		return nil
	}
	// Pending-state SQL is independent from operational authority. Never pass
	// its retryable storage error through the authorization-denial normalizer.
	if err := check(ctx); err != nil {
		return err
	}
	return j.WithMaintenanceLease(ctx, authorize, func(ctx context.Context) error {
		if err := check(ctx); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		return check(ctx)
	})
}
