// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// A transaction may start before a fault is observed, then assign a source
// after that fault. The assignment must carry the statement clock rather than
// PostgreSQL's transaction-start now(), or the old fault could acquire a
// routing context retroactively.
func TestEntityAssignmentsCannotPreDateTheirInsertStatement(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	tenant, err := NewTenants(pool).Create(ctx,
		fmt.Sprintf("entity-clock-%d", time.Now().UnixNano()), "Entity Clock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
			t.Errorf("remove entity clock tenant: %v", err)
		}
	})
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var txStarted time.Time
			if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&txStarted); err != nil {
				return err
			}
			area, err := NewEntityRegistry(pool).CreateEntityContext(ctx, sc, "clock-lab", "vrf-a")
			if err != nil {
				return err
			}
			var faultObservedAt time.Time
			if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&faultObservedAt); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,'agent-clock',$2)`, tenant.ID, area.ContextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id)
				VALUES ($1,'agent-clock','device_target','10.42.0.1',$2)`, tenant.ID, area.ContextID); err != nil {
				return err
			}
			var agentAt, sourceAt time.Time
			if err := sc.Q.QueryRow(ctx, `SELECT a.assigned_at,s.assigned_at
				FROM entity_agent_contexts a JOIN entity_source_contexts s
				  ON (a.tenant_id,a.agent_id,a.context_id)=(s.tenant_id,s.agent_id,s.context_id)
				WHERE a.tenant_id=$1 AND a.agent_id='agent-clock'`, tenant.ID).
				Scan(&agentAt, &sourceAt); err != nil {
				return err
			}
			if !txStarted.Before(faultObservedAt) || !faultObservedAt.Before(agentAt) ||
				!faultObservedAt.Before(sourceAt) {
				t.Errorf("retroactive assignment: tx=%s fault=%s agent=%s source=%s",
					txStarted, faultObservedAt, agentAt, sourceAt)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}
