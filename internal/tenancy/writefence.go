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

func canonicalWriterTenantIDs(tenantIDs []string) ([]string, error) {
	unique := make(map[string]struct{}, len(tenantIDs))
	for _, raw := range tenantIDs {
		if len(raw) != 36 ||
			raw[8] != '-' ||
			raw[13] != '-' ||
			raw[18] != '-' ||
			raw[23] != '-' {
			return nil, fmt.Errorf(
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
			return nil, fmt.Errorf(
				"tenancy: invalid tenant writer id %q: %w",
				raw,
				err,
			)
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
