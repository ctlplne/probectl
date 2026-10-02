// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrTenantWritesFenced is returned before an external-store write when the
// tenant registry says that tenant is absent, offboarding, deleted, or already
// carries the durable erasure marker.
var ErrTenantWritesFenced = errors.New("tenancy: tenant writes are fenced")

// WriterFence holds the durable shared tenant-writer lease across one external
// datastore mutation. Implementations acquire leases in deterministic order
// and invoke write only after every tenant is eligible, so a mixed-tenant batch
// cannot partially enter the backend because one tenant is fenced.
type WriterFence interface {
	WithTenantWrites(
		ctx context.Context,
		tenantIDs []string,
		write func(context.Context) error,
	) error
}

// PartitionedWriterFence evaluates each tenant's lifecycle lease INDEPENDENTLY
// within one coalesced multi-tenant batch (docs/guardrails.md G7-1). The
// all-or-nothing WithTenantWrites is correct for a single caller's own atomic
// write, but a batching writer coalesces the INDEPENDENT writes of many tenants
// into one shared mutation; checking that shared batch as a unit lets one
// offboarding tenant's fence reject every co-batched tenant — one tenant's
// lifecycle state deciding another tenant's write, the exact G7-1 violation.
// This seam acquires every distinct tenant's shared lease, determines which
// tenants are fenced, and invokes write ONCE with that per-tenant verdict so
// the caller stores every eligible tenant's rows and rejects ONLY the fenced
// tenants'. An infrastructure failure that prevents verifying eligibility fails
// the whole batch closed (returned error), never silently.
type PartitionedWriterFence interface {
	WriterFence
	WithPartitionedTenantWrites(
		ctx context.Context,
		tenantIDs []string,
		write func(ctx context.Context, fenced map[string]error) error,
	) error
}

// PostgresWriterFence is the canonical deployment-wide writer fence. The
// tenant registry and transaction-scoped advisory locks are durable and shared
// by every control-plane replica; no process-local lifecycle cache participates.
type PostgresWriterFence struct {
	pool *pgxpool.Pool
}

// NewPostgresWriterFence builds the external-store writer side of the erasure
// barrier. The pool must be the control plane's PostgreSQL writer pool.
func NewPostgresWriterFence(pool *pgxpool.Pool) *PostgresWriterFence {
	return &PostgresWriterFence{pool: pool}
}

// WithTenantWrites acquires a shared advisory lease for every tenant, verifies
// durable lifecycle state, then holds those leases until write returns. Full
// erasure takes the matching exclusive lock before it commits offboarding, so
// it drains a write already inside this callback and every later caller sees
// the committed fence before touching its external backend.
func (f *PostgresWriterFence) WithTenantWrites(
	ctx context.Context,
	tenantIDs []string,
	write func(context.Context) error,
) error {
	if f == nil || f.pool == nil {
		return errors.New("tenancy: tenant writer fence is unavailable")
	}
	if write == nil {
		return errors.New("tenancy: tenant writer callback is nil")
	}
	canonical, err := canonicalWriterTenantIDs(tenantIDs)
	if err != nil {
		return err
	}
	if len(canonical) == 0 {
		return ErrNoTenant
	}

	return InProvider(ctx, f.pool, func(ctx context.Context, q Querier) error {
		for _, tenantID := range canonical {
			if err := lockTenantWriterLease(ctx, q, tenantID); err != nil {
				return err
			}
		}
		for _, tenantID := range canonical {
			var status string
			var fenced bool
			if err := q.QueryRow(
				ctx,
				`SELECT status, audit_write_fenced_at IS NOT NULL
				   FROM public.tenants
				  WHERE id = $1::uuid`,
				tenantID,
			).Scan(&status, &fenced); err != nil {
				return fmt.Errorf(
					"%w: tenant %s registry lookup: %v",
					ErrTenantWritesFenced,
					tenantID,
					err,
				)
			}
			if fenced || (status != "active" && status != "suspended") {
				return fmt.Errorf(
					"%w: tenant %s status=%s",
					ErrTenantWritesFenced,
					tenantID,
					status,
				)
			}
		}
		return write(ctx)
	})
}

// WithPartitionedTenantWrites implements PartitionedWriterFence. It acquires a
// shared advisory lease for every DISTINCT tenant (deterministic order), reads
// each tenant's durable lifecycle state, then invokes write exactly once while
// holding all leases — passing a map of exactly the tenants that are fenced so
// the caller writes only the eligible tenants' rows (docs/guardrails.md G7-1:
// one tenant's lifecycle state must never decide another tenant's write). A
// registry lookup failure is infrastructure, not a lifecycle decision, so it
// fails the whole batch closed rather than masquerading as one tenant's fence.
// Full erasure takes the matching EXCLUSIVE lock before it commits offboarding,
// so an eligible tenant's rows written here finish before its fence commits and
// a later caller sees the committed fence — identical lease discipline to
// WithTenantWrites, only the verdict is per-tenant instead of all-or-nothing.
func (f *PostgresWriterFence) WithPartitionedTenantWrites(
	ctx context.Context,
	tenantIDs []string,
	write func(ctx context.Context, fenced map[string]error) error,
) error {
	if f == nil || f.pool == nil {
		return errors.New("tenancy: tenant writer fence is unavailable")
	}
	if write == nil {
		return errors.New("tenancy: tenant writer callback is nil")
	}
	distinct, err := distinctWriterTenantIDs(tenantIDs)
	if err != nil {
		return err
	}
	if len(distinct) == 0 {
		return ErrNoTenant
	}

	return InProvider(ctx, f.pool, func(ctx context.Context, q Querier) error {
		for _, tenantID := range distinct {
			if err := lockTenantWriterLease(ctx, q, tenantID); err != nil {
				return err
			}
		}
		var fenced map[string]error
		for _, tenantID := range distinct {
			var status string
			var isFenced bool
			if err := q.QueryRow(
				ctx,
				`SELECT status, audit_write_fenced_at IS NOT NULL
				   FROM public.tenants
				  WHERE id = $1::uuid`,
				tenantID,
			).Scan(&status, &isFenced); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					// Absent tenant (fully erased or never existed): fence THIS
					// tenant per-tenant, never fail the batch — an absent tenant
					// must not reject its co-batched neighbours (G7-1).
					if fenced == nil {
						fenced = make(map[string]error, 1)
					}
					fenced[tenantID] = fmt.Errorf(
						"%w: tenant %s status=absent",
						ErrTenantWritesFenced,
						tenantID,
					)
					continue
				}
				// Infrastructure failure, not a lifecycle decision: one tenant's
				// registry lookup error must not silently drop that tenant while
				// the batch proceeds. Fail the whole batch closed.
				return fmt.Errorf(
					"%w: tenant %s registry lookup: %v",
					ErrTenantWritesFenced,
					tenantID,
					err,
				)
			}
			if isFenced || (status != "active" && status != "suspended") {
				if fenced == nil {
					fenced = make(map[string]error, 1)
				}
				fenced[tenantID] = fmt.Errorf(
					"%w: tenant %s status=%s",
					ErrTenantWritesFenced,
					tenantID,
					status,
				)
			}
		}
		return write(ctx, fenced)
	})
}

func canonicalWriterTenantIDs(tenantIDs []string) ([]string, error) {
	unique := make(map[string]struct{}, len(tenantIDs))
	for _, raw := range tenantIDs {
		if err := validateWriterTenantID(raw); err != nil {
			return nil, err
		}
		unique[strings.ToLower(raw)] = struct{}{}
	}
	canonical := make([]string, 0, len(unique))
	for tenantID := range unique {
		canonical = append(canonical, tenantID)
	}
	sort.Strings(canonical)
	return canonical, nil
}

// distinctWriterTenantIDs validates and de-duplicates tenant writer ids WITHOUT
// case-folding, so the per-tenant fence verdict is keyed by the exact string
// the caller used for each row and the batching writer can match a rejected
// tenant back to its own series. The advisory lock casts to ::uuid, so Postgres
// normalizes the lock key regardless of the string's case.
func distinctWriterTenantIDs(tenantIDs []string) ([]string, error) {
	unique := make(map[string]struct{}, len(tenantIDs))
	for _, raw := range tenantIDs {
		if err := validateWriterTenantID(raw); err != nil {
			return nil, err
		}
		unique[raw] = struct{}{}
	}
	distinct := make([]string, 0, len(unique))
	for tenantID := range unique {
		distinct = append(distinct, tenantID)
	}
	sort.Strings(distinct)
	return distinct, nil
}

// validateWriterTenantID rejects any id that is not a canonical hyphenated UUID
// before it reaches a ::uuid cast in Postgres.
func validateWriterTenantID(raw string) error {
	if len(raw) != 36 ||
		raw[8] != '-' ||
		raw[13] != '-' ||
		raw[18] != '-' ||
		raw[23] != '-' {
		return fmt.Errorf(
			"tenancy: invalid tenant writer id %q",
			raw,
		)
	}
	compact := raw[0:8] +
		raw[9:13] +
		raw[14:18] +
		raw[19:23] +
		raw[24:36]
	if _, err := hex.DecodeString(compact); err != nil {
		return fmt.Errorf(
			"tenancy: invalid tenant writer id %q: %w",
			raw,
			err,
		)
	}
	return nil
}

func lockTenantWriterLease(
	ctx context.Context,
	q Querier,
	tenantID string,
) error {
	_, err := q.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock_shared(
		     hashtextextended('tenant-write:' || $1::uuid::text, 0)
		 )`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("lock tenant writer lease: %w", err)
	}
	return nil
}

// LockTenantWrites acquires the canonical transaction-scoped exclusive tenant
// writer lock. Full erasure takes this lock before committing the durable
// offboarding fence, so storage writers that already hold the matching shared
// lock finish first and later writers observe the committed fence.
func LockTenantWrites(
	ctx context.Context,
	q Querier,
	tenantID string,
) error {
	_, err := q.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(
		     hashtextextended('tenant-write:' || $1::uuid::text, 0)
		 )`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("lock tenant writers: %w", err)
	}
	return nil
}
