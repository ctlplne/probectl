// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package tenantkeys

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// PGStore persists key chains via the probectl_provider role (the explicit
// provider policy from migration 0030) — key management is control-plane
// security state, and the erase engine destroys chains through the same
// role.
type PGStore struct{ pool *pgxpool.Pool }

// NewPGStore wraps a pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

func (s *PGStore) in(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
	return tenancy.InProvider(ctx, s.pool, fn)
}

const keyCols = `tenant_id::text, version, mode, state, coalesce(wrapped_kek, ''::bytea),
	byok_ref, created_at, retired_at, destroyed_at`

func scanKey(row pgx.Row) (*KeyVersion, error) {
	var kv KeyVersion
	err := row.Scan(&kv.TenantID, &kv.Version, &kv.Mode, &kv.State, &kv.WrappedKEK,
		&kv.BYOKRef, &kv.CreatedAt, &kv.RetiredAt, &kv.DestroyedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &kv, nil
}

func (s *PGStore) ActiveVersion(ctx context.Context, tenantID string) (*KeyVersion, error) {
	var kv *KeyVersion
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		kv, e = scanKey(q.QueryRow(ctx,
			`SELECT `+keyCols+` FROM tenant_keys WHERE tenant_id = $1 AND state = 'active'`, tenantID))
		return e
	})
	return kv, err
}

func (s *PGStore) Version(ctx context.Context, tenantID string, version int) (*KeyVersion, error) {
	var kv *KeyVersion
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		kv, e = scanKey(q.QueryRow(ctx,
			`SELECT `+keyCols+` FROM tenant_keys WHERE tenant_id = $1 AND version = $2`, tenantID, version))
		return e
	})
	return kv, err
}

func (s *PGStore) Insert(ctx context.Context, kv KeyVersion) error {
	return s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO tenant_keys (tenant_id, version, mode, state, wrapped_kek, byok_ref, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			kv.TenantID, kv.Version, kv.Mode, kv.State, kv.WrappedKEK, kv.BYOKRef, kv.CreatedAt)
		return err
	})
}

func (s *PGStore) Retire(ctx context.Context, tenantID string, at time.Time) error {
	return s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			UPDATE tenant_keys SET state = 'retired', retired_at = $2
			 WHERE tenant_id = $1 AND state = 'active'`, tenantID, at)
		return err
	})
}

func (s *PGStore) DestroyAll(ctx context.Context, tenantID, by string, at time.Time) (int, error) {
	var n int
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		tag, err := q.Exec(ctx, `
			UPDATE tenant_keys SET state = 'destroyed', wrapped_kek = NULL, byok_ref = '',
			       destroyed_at = $2, destroyed_by = $3
			 WHERE tenant_id = $1 AND state <> 'destroyed'`, tenantID, at, by)
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		return nil
	})
	return n, err
}

func (s *PGStore) Chain(ctx context.Context, tenantID string) ([]KeyVersion, error) {
	var out []KeyVersion
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx,
			`SELECT `+keyCols+` FROM tenant_keys WHERE tenant_id = $1 ORDER BY version DESC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			kv, err := scanKey(rows)
			if err != nil {
				return err
			}
			out = append(out, *kv)
		}
		return rows.Err()
	})
	return out, err
}

// --- In-memory implementation (unit tests) ---

// MemStore is a thread-safe in-memory Store.
type MemStore struct {
	mu   sync.Mutex
	keys map[string][]KeyVersion // tenant -> versions
	fail bool
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore { return &MemStore{keys: map[string][]KeyVersion{}} }

// FailAll makes every call fail (fail-safe tests).
func (m *MemStore) FailAll(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = fail
}

func (m *MemStore) ActiveVersion(_ context.Context, tenantID string) (*KeyVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	for i := range m.keys[tenantID] {
		if m.keys[tenantID][i].State == StateActive {
			cp := m.keys[tenantID][i]
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *MemStore) Version(_ context.Context, tenantID string, version int) (*KeyVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	for i := range m.keys[tenantID] {
		if m.keys[tenantID][i].Version == version {
			cp := m.keys[tenantID][i]
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *MemStore) Insert(_ context.Context, kv KeyVersion) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return context.DeadlineExceeded
	}
	m.keys[kv.TenantID] = append(m.keys[kv.TenantID], kv)
	return nil
}

func (m *MemStore) Retire(_ context.Context, tenantID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return context.DeadlineExceeded
	}
	for i := range m.keys[tenantID] {
		if m.keys[tenantID][i].State == StateActive {
			m.keys[tenantID][i].State = StateRetired
			t := at
			m.keys[tenantID][i].RetiredAt = &t
		}
	}
	return nil
}

func (m *MemStore) DestroyAll(_ context.Context, tenantID, _ string, at time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return 0, context.DeadlineExceeded
	}
	n := 0
	for i := range m.keys[tenantID] {
		if m.keys[tenantID][i].State != StateDestroyed {
			m.keys[tenantID][i].State = StateDestroyed
			m.keys[tenantID][i].WrappedKEK = nil
			m.keys[tenantID][i].BYOKRef = ""
			t := at
			m.keys[tenantID][i].DestroyedAt = &t
			n++
		}
	}
	return n, nil
}

func (m *MemStore) Chain(_ context.Context, tenantID string) ([]KeyVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	out := append([]KeyVersion(nil), m.keys[tenantID]...)
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, nil
}
