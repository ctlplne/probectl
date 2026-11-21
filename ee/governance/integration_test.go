// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package governance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// The S-EE3 integration leg (live Postgres): the governance policy round-trips
// through tenant_governance via the provider role (classification overrides +
// redaction floor + redact-export), the resolver feeds the core govern seam,
// and tenant-side RLS confines a tenant to its OWN policy row.
func itPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.PostgresDSN()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func itTenant(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (slug, name) VALUES ($1, $1)
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id::text`, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGovernancePolicyRoundTripPG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	tnA := itTenant(t, pool, fmt.Sprintf("it-gov-a-%d", suffix))
	tnB := itTenant(t, pool, fmt.Sprintf("it-gov-b-%d", suffix))
	store := NewStore(pool)

	// No row → defaults.
	if _, ok, err := store.PolicyFor(ctx, tnA); err != nil || ok {
		t.Fatalf("missing row: ok=%v err=%v", ok, err)
	}

	// Upsert a policy with a classification override + redaction floor.
	in := govern.Policy{
		Overrides:    map[govern.Category]govern.Class{govern.CatHostname: govern.ClassPII},
		RedactFrom:   govern.ClassConfidential,
		RedactExport: true,
	}
	if err := store.Upsert(ctx, tnA, in, "op@msp.example"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.PolicyFor(ctx, tnA)
	if err != nil || !ok {
		t.Fatalf("read back: ok=%v err=%v", ok, err)
	}
	if got.RedactFrom != govern.ClassConfidential || !got.RedactExport ||
		got.Overrides[govern.CatHostname] != govern.ClassPII {
		t.Fatalf("policy round-trip: %+v", got)
	}

	// The resolver feeds the core seam: hostname is now PII for tnA, so it
	// redacts under the merged policy.
	govern.SetSource(store)
	defer govern.Reset()
	pol := govern.PolicyFor(ctx, tnA)
	if pol.StrategyFor(govern.CatHostname) == govern.StrategyNone {
		t.Fatal("re-classified hostname must redact via the resolver")
	}

	// Update narrows the floor; no override.
	if err := store.Upsert(ctx, tnA, govern.Policy{RedactFrom: govern.ClassPII}, "op@msp.example"); err != nil {
		t.Fatal(err)
	}
	got, _, _ = store.PolicyFor(ctx, tnA)
	if got.RedactFrom != govern.ClassPII || len(got.Overrides) != 0 {
		t.Fatalf("update: %+v", got)
	}

	// Tenant-side RLS: tenant B sees only its OWN governance row.
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tnB)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		var n int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM tenant_governance`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("tenant B must not see other tenants' governance rows: %d", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProviderGovernanceEditUsesTheCommittedTenantPolicy(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	store := NewStore(pool)
	tenantStore := govern.NewPolicyStore(pool)
	for _, name := range []string{"existing-policy", "first-tenant-policy"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			stamp := time.Now().UnixNano()
			owner := itTenant(t, pool, fmt.Sprintf("it-gov-owner-%d", stamp))
			sibling := itTenant(t, pool, fmt.Sprintf("it-gov-peer-%d", stamp))
			t.Cleanup(func() {
				if _, err := pool.Exec(context.Background(), "DELETE FROM tenants WHERE id IN ($1,$2)", owner, sibling); err != nil {
					t.Error(err)
				}
			})
			existing := name == "existing-policy"
			if existing {
				original := govern.Policy{
					AIRemoteEgress: true,
					Overrides:      map[govern.Category]govern.Class{govern.CatHostname: govern.ClassInternal},
				}
				if err := store.Upsert(ctx, owner, original, "setup"); err != nil {
					t.Fatal(err)
				}
			}
			current := govern.Policy{
				AIRemoteEgress: !existing,
				Overrides:      map[govern.Category]govern.Class{govern.CatHostname: govern.ClassRestricted},
			}
			writerID := make(chan int32, 1)
			release := make(chan struct{})
			tenantDone := make(chan error, 1)
			go func() {
				tenantDone <- tenantStore.SetTenantPolicy(ctx, owner, current, "tenant-admin",
					func(ctx context.Context, sc tenancy.Scope) error {
						var id int32
						if err := sc.Q.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&id); err != nil {
							return err
						}
						writerID <- id
						select {
						case <-release:
							_, err := audit.TenantAppend(ctx, sc, "tenant-admin", "governance.policy_set", owner, nil)
							return err
						case <-ctx.Done():
							return ctx.Err()
						}
					})
			}()
			var pid int32
			select {
			case pid = <-writerID:
			case err := <-tenantDone:
				t.Fatal("tenant writer did not hold the policy transaction", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}

			forceRedaction := func(prior govern.Policy) (govern.Policy, error) {
				prior.RedactExport = true
				return prior, nil
			}
			providerDone := make(chan error, 1)
			go func() {
				providerDone <- store.ChangeAudited(ctx, owner, "provider-admin", forceRedaction,
					func(ctx context.Context, q tenancy.Querier, prior govern.Policy, found bool, next govern.Policy) error {
						if !found || prior.AIRemoteEgress != current.AIRemoteEgress ||
							prior.Overrides[govern.CatHostname] != govern.ClassRestricted ||
							prior.RedactExport || !next.RedactExport || next.AIRemoteEgress != prior.AIRemoteEgress {
							return fmt.Errorf("provider audit used stale policy: prior=%+v next=%+v", prior, next)
						}
						_, err := audit.ProviderAppendTx(ctx, q, "provider-admin", "provider.governance_set", owner, map[string]any{
							"redact_export":    next.RedactExport,
							"ai_remote_egress": prior.AIRemoteEgress,
						})
						return err
					})
			}()
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				var waiting bool
				if err := pool.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
					AND query LIKE '%tenant_governance%')`, pid).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("provider write did not wait for the tenant policy transaction")
				}
			}
			if err := store.ChangeAudited(ctx, sibling, "provider-admin", forceRedaction,
				func(_ context.Context, _ tenancy.Querier, _ govern.Policy, found bool, after govern.Policy) error {
					if found || after.AIRemoteEgress || len(after.Overrides) != 0 {
						return fmt.Errorf("sibling inherited the owner's policy: %+v", after)
					}
					return nil
				}); err != nil {
				t.Fatal("unrelated sibling edit could not proceed", err)
			}
			close(release)
			if err := <-tenantDone; err != nil {
				t.Fatal(err)
			}
			if err := <-providerDone; err != nil {
				t.Fatal(err)
			}
			got, found, err := tenantStore.TenantPolicy(ctx, owner)
			if err != nil || !found || !got.RedactExport || got.AIRemoteEgress != current.AIRemoteEgress ||
				got.Overrides[govern.CatHostname] != govern.ClassRestricted {
				t.Fatalf("provider did not preserve the committed tenant-owned settings: %+v, %v", got, err)
			}
		})
	}
}

func TestProviderGovernanceFirstEditRollsBackOnAuditFailure(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	store := NewStore(pool)
	owner := itTenant(t, pool, fmt.Sprintf("it-gov-first-edit-%d", time.Now().UnixNano()))
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", owner); err != nil {
			t.Error(err)
		}
	})
	rejected := errors.New("fixture audit refused the change")
	err := store.ChangeAudited(t.Context(), owner, "provider-admin",
		func(prior govern.Policy) (govern.Policy, error) {
			prior.RedactExport = true
			return prior, nil
		},
		func(ctx context.Context, q tenancy.Querier, _ govern.Policy, _ bool, _ govern.Policy) error {
			if _, err := audit.ProviderAppendTx(ctx, q, "provider-admin", "provider.governance_set", owner, nil); err != nil {
				return err
			}
			return rejected
		})
	if !errors.Is(err, rejected) {
		t.Fatalf("audit refusal lost: %v", err)
	}
	if _, found, err := store.PolicyFor(t.Context(), owner); err != nil || found {
		t.Fatalf("failed first edit left a policy row: found=%t, %v", found, err)
	}
	if err := tenancy.InProvider(t.Context(), pool, func(ctx context.Context, q tenancy.Querier) error {
		var count int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM provider_audit_events WHERE action='provider.governance_set' AND target=$1`, owner).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("failed first edit left %d provider audit events", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
