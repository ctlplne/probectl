// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual concurrent application-role transactions; source identities are
// modeled registry rows, not authenticated BMP transport.
func TestBGPRoutingWritesSerializeSourceChangesAndRejectStaleSnapshots(t *testing.T) {
	for _, change := range []struct{ name, sql string }{
		{"sender", `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"origin", `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND agent_id='role-router'`},
		{"source", `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND source_kind='bmp_peer'`},
		{"assignment", `UPDATE entity_agent_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND agent_id='role-listener'`},
	} {
		t.Run(change.name, func(t *testing.T) {
			f := newRoleInputsFixture(t, 8)
			ctx, cancel := context.WithTimeout(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), 15*time.Second)
			defer cancel()
			var observed time.Time
			f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed)
			})
			source := BGPRoutingSource{Scope: entity.Scope{TenantID: f.tenants[0], ContextID: f.contextID}, RouterID: f.routerID,
				CollectorAgentID: "role-listener", SourceRef: "role-router", SenderSerial: f.serials[f.tenants[0]+"role-listener"], OriginSerial: f.serials[f.tenants[0]+"role-router"], ObservedAt: observed}
			mutated := make(chan error, 1)
			pid := make(chan int, 1)
			err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
				return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
					if _, err := (BGPRouting{}).BeginViewInScope(ctx, sc, source, routingViewFixture(), observed.Add(time.Minute), routingViewBudget()); err != nil {
						return err
					}
					go func() {
						mutated <- tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
							return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
								var backend int
								if err := sc.Q.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backend); err != nil {
									return err
								}
								pid <- backend
								_, err := sc.Q.Exec(ctx, change.sql, source.TenantID)
								return err
							})
						})
					}()
					select {
					case backend := <-pid:
						return waitBGPRoutingSourceLock(ctx, f, backend, mutated)
					case err := <-mutated:
						return fmt.Errorf("source mutation never acquired a transaction: %w", err)
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			})
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			if err := <-mutated; err != nil {
				t.Fatal("serialized source mutation failed", err)
			}
			if err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := (BGPRouting{}).SourceAuthorityInScope(ctx, sc, source)
				return err
			}); !errors.Is(err, ErrBGPRoutingSourceUnavailable) {
				t.Fatal("committed source mutation retained routing authority", err)
			}
			// The sibling reuses every context/router/source key. Neither locks
			// nor revocation are allowed to cross the tenant boundary.
			sibling := source
			sibling.TenantID = f.tenants[1]
			sibling.SenderSerial, sibling.OriginSerial = f.serials[f.tenants[1]+"role-listener"], f.serials[f.tenants[1]+"role-router"]
			f.in(sibling.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := (BGPRouting{}).SourceAuthorityInScope(ctx, sc, sibling)
				return err
			})
		})
	}
	t.Run("stale-snapshot", testBGPRoutingStaleSourceSnapshot)
}

func waitBGPRoutingSourceLock(ctx context.Context, f *roleInputsFixture, pid int, done <-chan error) error {
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-done:
			return fmt.Errorf("source mutation escaped routing write lock: %v", err)
		default:
		}
		var blocked bool
		if err := f.pool.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&blocked); err != nil {
			return err
		}
		if blocked {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("source mutation never waited for routing authority")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func testBGPRoutingStaleSourceSnapshot(t *testing.T) {
	f := newRoleInputsFixture(t, 8)
	source := BGPRoutingSource{Scope: entity.Scope{TenantID: f.tenants[0], ContextID: f.contextID}, RouterID: f.routerID,
		CollectorAgentID: "role-listener", SourceRef: "role-router", SenderSerial: f.serials[f.tenants[0]+"role-listener"], OriginSerial: f.serials[f.tenants[0]+"role-router"]}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID))
	err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenantWriteSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&source.ObservedAt); err != nil {
				return err
			}
			if err := tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture'
 WHERE tenant_id=$1 AND serial=$2`, source.TenantID, source.OriginSerial)
				return err
			}); err != nil {
				return err
			}
			_, err := (BGPRouting{}).SourceAuthorityForWriteInScope(ctx, sc, source)
			if err == nil {
				return errors.New("stale snapshot acknowledged revoked routing authority")
			}
			return err
		})
	})
	var postgres *pgconn.PgError
	if !errors.Is(err, ErrBGPRoutingSourceUnavailable) && (!errors.As(err, &postgres) || postgres.Code != "40001") {
		t.Fatal("stale snapshot acknowledged revoked routing authority", err)
	}
}

func TestBGPRoutingQuotaWaitUsesFreshTenantAccountAndRefusesOldSnapshots(t *testing.T) {
	f := newRoleInputsFixture(t, 8)
	source := BGPRoutingSource{Scope: entity.Scope{TenantID: f.tenants[0], ContextID: f.contextID}, RouterID: f.routerID,
		CollectorAgentID: "role-listener", SourceRef: "role-router", SenderSerial: f.serials[f.tenants[0]+"role-listener"], OriginSerial: f.serials[f.tenants[0]+"role-router"], ObservedAt: time.Now()}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID)), 15*time.Second)
	defer cancel()
	// Refuse the mode before creating any private generation. A transaction
	// that established an old snapshot cannot refresh SUM after its lock wait.
	err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenantWriteSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (BGPRouting{}).BeginViewInScope(ctx, sc, source, routingViewFixture(), source.ObservedAt.Add(time.Minute), routingViewBudget())
			return err
		})
	})
	if !errors.Is(err, ErrBGPRoutingWriteSnapshot) {
		t.Fatal("routing quota accepted a potentially stale transaction snapshot", err)
	}
	second := make(chan error, 1)
	pid := make(chan int, 1)
	err = tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			view, err := (BGPRouting{}).BeginViewInScope(ctx, sc, source, routingViewFixture(), source.ObservedAt.Add(time.Minute), routingViewBudget())
			if err != nil {
				return err
			}
			var bytes int64
			if err := sc.Q.QueryRow(ctx, `SELECT charged_bytes FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2`, source.TenantID, view.ID).Scan(&bytes); err != nil {
				return err
			}
			go func() {
				second <- tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
					return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
						var backend int
						if err := sc.Q.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backend); err != nil {
							return err
						}
						pid <- backend
						profile, definition := routingViewBudget(), routingViewFixture()
						profile.StateBytes = bytes
						definition.Peer.Address = netip.MustParseAddr("192.0.2.14")
						_, err := (BGPRouting{}).BeginViewInScope(ctx, sc, source, definition, source.ObservedAt.Add(time.Minute), profile)
						return err
					})
				})
			}()
			select {
			case backend := <-pid:
				return waitBGPRoutingSourceLock(ctx, f, backend, second)
			case err := <-second:
				return fmt.Errorf("quota writer never acquired a transaction: %w", err)
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, ErrBGPRoutingBudget) {
		t.Fatal("concurrent routing generations exceeded retained tenant bytes", err)
	}
	f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id=$1`, source.TenantID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatal("refused quota transaction retained partial routing generation", count)
		}
		return nil
	})
}
