// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-082: a registered agent reads online while its heartbeat is fresh and
// offline once it is older than the window; a heartbeat (or a verified
// collector batch, which calls the same method) brings it back.
func TestAgentStatusDecaysWithoutHeartbeats(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("fleet-%d", time.Now().UnixNano()), "fleet")
	if err != nil {
		t.Fatal(err)
	}
	// DPR-232: a FRESH id per run. `agents.id` is the primary key and is global,
	// while this test mints a new tenant every time, so a hard-coded id makes the
	// second run against the same database re-register another tenant's row:
	// Register's ON CONFLICT (id) DO UPDATE hits a row RLS will not let this
	// tenant see, and Postgres refuses with 42501 "new row violates row-level
	// security policy (USING expression)". The integration job does exactly that
	// — `make test-integration` then a second internal/store run for the U-057
	// coverage floor — so it only stayed hidden while the first run was failing.
	id := covUUID(t)
	status := func() string {
		var st string
		inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
			a, err := (Agents{}).Get(ctx, sc, id)
			if err != nil {
				return err
			}
			st = a.Status
			return nil
		})
		return st
	}
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (Agents{}).Register(ctx, sc, id, "ebpf-node-1", "node-1", "0.0.0", "spiffe://probectl/"+tn.ID+"/agent/"+id, []string{"collector", "ebpf"})
		return err
	})
	if got := status(); got != "online" {
		t.Fatalf("freshly registered agent reads %q, want online", got)
	}
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agents SET last_seen_at = now() - interval '5 hours' WHERE id = $1`, id)
		return err
	})
	if got := status(); got != "offline" {
		t.Fatalf("agent last seen five hours ago reads %q, want offline (the stored column still says online)", got)
	}
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (Agents{}).Heartbeat(ctx, sc, id)
		return err
	})
	if got := status(); got != "online" {
		t.Fatalf("after a heartbeat the agent reads %q, want online", got)
	}
}
