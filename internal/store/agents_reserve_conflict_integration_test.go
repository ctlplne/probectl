// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func randAgentUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// TestReserveNameCollisionIsConflictNotServerError proves CRY-09: a second
// Reserve that collides on (tenant_id, name) with a DIFFERENT agent id returns
// a typed 409 Conflict (recoverable — the savepoint keeps the transaction
// alive), not a raw unique-violation that surfaces as an internal 500.
func TestReserveNameCollisionIsConflictNotServerError(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("cry09-%d", time.Now().UnixNano()), "cry09")
	if err != nil {
		t.Fatal(err)
	}

	agentA := randAgentUUID(t)
	agentB := randAgentUUID(t)
	var secondErr error
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tn.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, e := (Agents{}).Reserve(ctx, sc, agentA, "shared-host", "shared-host", "v1", "spiffe://probectl/A", nil); e != nil {
			return fmt.Errorf("first reserve: %w", e)
		}
		// Different agent id, same (defaulted) name — the collision.
		_, secondErr = (Agents{}).Reserve(ctx, sc, agentB, "shared-host", "shared-host", "v1", "spiffe://probectl/B", nil)
		// The transaction must still be usable after the handled conflict.
		_, e := (Agents{}).Get(ctx, sc, agentA)
		return e
	})
	if err != nil {
		t.Fatalf("transaction poisoned by the name collision (CRY-09): %v", err)
	}
	domain, ok := apierror.As(secondErr)
	if !ok || domain.Kind != apierror.KindConflict {
		t.Fatalf("name collision error = %v, want a typed 409 Conflict", secondErr)
	}
}
