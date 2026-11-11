// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package sourceepoch shares the existing derived-source lifecycle epoch
// without importing snapshot readers, renderers or audit implementations.
package sourceepoch

import (
	"context"
	"errors"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ErrInvalidating is shared by every existing derived-source consumer.
var ErrInvalidating = errors.New("flow snapshot lifecycle transition in progress")

func canonicalID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, ch := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// PrepareInScope uses the existing tenant-write trigger before callers take
// the audit lock. It changes neither the table nor the lifecycle lock order.
func PrepareInScope(ctx context.Context, sc tenancy.Scope) error {
	if err := sourceGenerationScope(ctx, sc); err != nil {
		return err
	}
	_, err := sc.Q.Exec(ctx, `INSERT INTO flow_snapshot_epochs(tenant_id,generation,invalidating) VALUES($1::uuid,1,false) ON CONFLICT (tenant_id) DO NOTHING`, sc.Tenant.String())
	return err
}

func sourceGenerationScope(ctx context.Context, sc tenancy.Scope) error {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant || sc.Q == nil || !canonicalID(tenant.String()) {
		return tenancy.ErrNoTenant
	}
	return ctx.Err()
}

// SourceGenerationInScope captures the existing lifecycle generation before
// derived-source IO. It creates no snapshot object or durable reader grant.
func SourceGenerationInScope(ctx context.Context, sc tenancy.Scope) (int64, error) {
	if err := sourceGenerationScope(ctx, sc); err != nil {
		return 0, err
	}
	if err := PrepareInScope(ctx, sc); err != nil {
		return 0, err
	}
	return readSourceGeneration(ctx, sc)
}

func readSourceGeneration(ctx context.Context, sc tenancy.Scope) (int64, error) {
	var generation int64
	var invalidating bool
	if err := sc.Q.QueryRow(ctx, `SELECT generation,invalidating FROM flow_snapshot_epochs WHERE tenant_id=$1::uuid`, sc.Tenant.String()).Scan(&generation, &invalidating); err != nil {
		return 0, err
	}
	if generation <= 0 || invalidating {
		return 0, ErrInvalidating
	}
	return generation, nil
}

// MatchSourceGenerationInScope is a publication check. The caller holds the
// tenant audit lock, shared in order with lifecycle mutations; it must never
// use this check as a frozen-reader grant or hold it across source IO.
func MatchSourceGenerationInScope(ctx context.Context, sc tenancy.Scope, captured int64) error {
	if err := sourceGenerationScope(ctx, sc); err != nil {
		return err
	}
	if captured <= 0 {
		return ErrInvalidating
	}
	current, err := readSourceGeneration(ctx, sc)
	if err != nil {
		return err
	}
	if current != captured {
		return ErrInvalidating
	}
	return nil
}

// InvalidateSourceGenerationInScope closes the interval between validated
// Postgres subject deletion and the existing telemetry/cache erasure. The
// caller already holds the tenant audit lock. The existing invalidation
// workflow replaces this token and clears it only after successful erasure.
func InvalidateSourceGenerationInScope(ctx context.Context, sc tenancy.Scope) error {
	if err := sourceGenerationScope(ctx, sc); err != nil {
		return err
	}
	token, err := crypto.UUIDv4()
	if err != nil {
		return err
	}
	_, err = sc.Q.Exec(ctx, `INSERT INTO flow_snapshot_epochs(tenant_id,generation,invalidating,transition_token,observation_erasing)
 VALUES($1::uuid,1,true,$2::uuid,true) ON CONFLICT(tenant_id) DO UPDATE
 SET generation=flow_snapshot_epochs.generation+1,invalidating=true,transition_token=EXCLUDED.transition_token,observation_erasing=true`, sc.Tenant.String(), token)
	return err
}
