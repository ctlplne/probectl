// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The healthy samples come from actual sockets and issued mTLS. Loss, partial
// IO and equal-clock disagreement below are deliberate authenticated fixtures;
// the separate real upstream-failure/recovery lab is still required.
func TestICMPHealthCurrentSnapshotAndTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	server := startTestServer(ctx, t, pool, func(s *agenttransport.Server) { s.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)) })
	area, router := newUUID(t), newUUID(t)
	lanes := []icmpWireLane{seedICMPWireLane(ctx, t, pool, server, area, router), seedICMPWireLane(ctx, t, pool, server, area, router)}
	registry := store.NewEntityRegistry(pool)
	read := func(lane icmpWireLane, want string, freshness time.Duration, bytes int64) store.ICMPHealth {
		t.Helper()
		var got store.ICMPHealth
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var super, bypass bool
			if err := sc.Q.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&super, &bypass); err != nil {
				return err
			}
			if super || bypass {
				return fmt.Errorf("health reader escaped the app-role RLS boundary")
			}
			var err error
			got, err = registry.ReadICMPHealthInScope(ctx, sc, entity.Scope{TenantID: lane.tenant, ContextID: area}, entity.SourceKey{AgentID: lane.sender, Kind: entity.PathAgent, SourceRef: lane.definition.ID}, router, freshness, bytes)
			return err
		})
		if err != nil || got.State != want {
			t.Fatalf("current health = %s (%s), want %s: %v", got.State, got.Reason, want, err)
		}
		return got
	}
	submit := func(lane icmpWireLane, claim entity.Observation) {
		t.Helper()
		if a, u, err := lane.client.Submit(ctx, []entity.Observation{claim}); err != nil || a != 1 || u != 0 {
			t.Fatal("sample refused", a, u, err)
		}
	}
	mutate := func(lane icmpWireLane, query string, args ...any) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, query, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	const memory = 8 << 20
	for _, lane := range lanes {
		read(lane, "unknown", time.Minute, memory)
		claim := lane.observe(ctx, t, newUUID(t))
		submit(lane, claim)
		got := read(lane, "up", time.Minute, memory)
		if got.SenderSerial != lane.serial || got.Observation.ID != claim.ID || got.FreshUntil.IsZero() || got.AsOf.Before(claim.ObservedAt) {
			t.Fatal("current health lost its exact source receipt", got)
		}
	}
	// A live tenant cannot select its sibling's source or scope, even with
	// identical routing context/entity UUIDs and overlapping destination IPs.
	foreign := lanes[0]
	foreign.sender, foreign.definition = lanes[1].sender, lanes[1].definition
	read(foreign, "unknown", time.Minute, memory)
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lanes[0].tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := registry.ReadICMPHealthInScope(ctx, sc, entity.Scope{TenantID: lanes[1].tenant, ContextID: area}, entity.SourceKey{AgentID: lanes[1].sender, Kind: entity.PathAgent, SourceRef: lanes[1].definition.ID}, router, time.Minute, memory)
		if err != entity.ErrScopeMismatch {
			return fmt.Errorf("foreign tenant scope was accepted: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	read(lanes[0], "unknown", time.Nanosecond, memory)
	read(lanes[0], "unknown", time.Minute, 4096) // admitted before JSON transfer

	loss := lanes[0].observe(ctx, t, newUUID(t))
	loss.ICMP.Replies, loss.ICMP.Responders = 0, []string{}
	submit(lanes[0], loss)
	read(lanes[0], "down", time.Minute, memory)
	read(lanes[1], "up", time.Minute, memory)

	partial := lanes[0].observe(ctx, t, newUUID(t))
	partial.ICMP.Replies, partial.ICMP.Responders = 0, []string{}
	partial.ICMP.ReadComplete, partial.ICMP.IOFailed = false, true
	submit(lanes[0], partial)
	read(lanes[0], "unknown", time.Minute, memory) // must not fall back to loss

	latest := lanes[0].observe(ctx, t, newUUID(t))
	submit(lanes[0], latest)
	read(lanes[0], "up", time.Minute, memory)
	conflict := latest
	conflict.ID = newUUID(t)
	conflict.ICMP = new(entity.ICMPMeasurement)
	*conflict.ICMP = *latest.ICMP
	conflict.ICMP.Replies, conflict.ICMP.Responders = 0, []string{}
	submit(lanes[0], conflict)
	read(lanes[0], "unknown", time.Minute, memory)
	read(lanes[1], "up", time.Minute, memory)

	// New evidence clears clock ambiguity. A same-profile edit still invalidates
	// an earlier measurement; reverting the digest must not resurrect it.
	submit(lanes[0], lanes[0].observe(ctx, t, newUUID(t)))
	read(lanes[0], "up", time.Minute, memory)
	mutate(lanes[0], `UPDATE tests SET updated_at=clock_timestamp() WHERE id=$1`, lanes[0].definition.ID)
	read(lanes[0], "unknown", time.Minute, memory)
	submit(lanes[0], lanes[0].observe(ctx, t, newUUID(t)))
	read(lanes[0], "up", time.Minute, memory)
	mutate(lanes[0], `UPDATE tests SET enabled=false,updated_at=clock_timestamp() WHERE id=$1`, lanes[0].definition.ID)
	read(lanes[0], "unknown", time.Minute, memory)
	mutate(lanes[0], `UPDATE tests SET enabled=true,updated_at=clock_timestamp() WHERE id=$1`, lanes[0].definition.ID)
	read(lanes[0], "unknown", time.Minute, memory)
	submit(lanes[0], lanes[0].observe(ctx, t, newUUID(t)))
	read(lanes[0], "up", time.Minute, memory)
	mutate(lanes[0], `DELETE FROM entity_test_contexts WHERE test_id=$1`, lanes[0].definition.ID)
	read(lanes[0], "unknown", time.Minute, memory)
	read(lanes[1], "up", time.Minute, memory)
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lanes[1].tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sourceepoch.PrepareInScope(ctx, sc); err != nil {
			return err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		if err := sourceepoch.InvalidateSourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET generation=generation+1,invalidating=false,transition_token=NULL,observation_erasing=false WHERE tenant_id=$1`, lanes[1].tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	read(lanes[1], "unknown", time.Minute, memory)
	submit(lanes[1], lanes[1].observe(ctx, t, newUUID(t)))
	read(lanes[1], "up", time.Minute, memory)
	mutate(lanes[1], `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='test' WHERE agent_id=$1 AND serial=$2`, lanes[1].sender, lanes[1].serial)
	read(lanes[1], "unknown", time.Minute, memory)
}
