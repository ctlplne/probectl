// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func validOwnerScope(ctx context.Context, scope tenancy.Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ambient, ok := tenancy.FromContext(ctx)
	parsed, err := uuid.Parse(scope.Tenant.String())
	if !ok || ambient != scope.Tenant || err != nil || parsed.String() != scope.Tenant.String() {
		return ErrMessageIntegrity
	}
	if scope.Q == nil {
		return ErrMessageUnavailable
	}
	return nil
}

// bindOwner never adopts a lifecycle mode left by another operation. Caller
// authority comes from the current request or exact claimed job, before use.
func bindOwner(ctx context.Context, scope tenancy.Scope, owner string) error {
	if err := validOwnerScope(ctx, scope); err != nil {
		return err
	}
	parsed, err := uuid.Parse(owner)
	if err != nil || parsed.String() != owner {
		return ErrMessageIntegrity
	}
	_, err = scope.Q.Exec(ctx, `SELECT set_config('probectl.flow_history_owner',$1,true),
        set_config('probectl.flow_history_lifecycle','',true)`, owner)
	return err
}

// bindLifecycle is deliberately private to storage maintenance composition.
// The eventual lifecycle methods must authorize/audit their operation before
// invoking it; it cannot be selected by a query, model flag or provider grant.
func bindLifecycle(ctx context.Context, scope tenancy.Scope) error {
	if err := validOwnerScope(ctx, scope); err != nil {
		return err
	}
	_, err := scope.Q.Exec(ctx, `SELECT set_config('probectl.flow_history_owner','',true),
        set_config('probectl.flow_history_lifecycle','authorized',true)`)
	return err
}
