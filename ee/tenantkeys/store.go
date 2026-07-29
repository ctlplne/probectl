// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package tenantkeys

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type rotationAuditFunc func(context.Context, tenancy.Scope, string, KeyVersion) error

// PGStore persists key chains. Ordinary key loading and offboarding use the
// restricted provider policy from migration 0030. Interactive rotation uses a
// tenant-scoped transaction so the tenant's RLS-confined audit stream and the
// public control-plane key row commit together.
type PGStore struct {
	pool  *pgxpool.Pool
	audit rotationAuditFunc
}

// NewPGStore wraps a pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool, audit: appendRotationAudit}
}

func appendRotationAudit(ctx context.Context, sc tenancy.Scope, actor string, kv KeyVersion) error {
	_, err := audit.TenantAppend(ctx, sc, actor, "security.key_rotate", kv.TenantID, map[string]any{
		"version": kv.Version,
		"mode":    kv.Mode,
	})
	return err
}

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

// RotateAtomic commits predecessor retirement, successor insertion, and the
// tenant audit event in one RLS-bound transaction. The advisory lock makes
// version assignment linearizable without blocking rotations for other
// tenants.
func (s *PGStore) RotateAtomic(
	ctx context.Context,
	tenantID, actor string,
	at time.Time,
	build RotationBuilder,
) (*KeyVersion, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(actor) == "" || build == nil {
		return nil, errors.New("tenantkeys: tenant, actor, and rotation builder are required")
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != tenantID {
		return nil, errors.New("tenantkeys: rotation tenant does not match request scope")
	}
	if s.audit == nil {
		return nil, errors.New("tenantkeys: mandatory rotation audit is unavailable")
	}

	var out KeyVersion
	scoped := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	err := tenancy.InTenant(scoped, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended('tenant-key-rotate:'||$1::text, 0))`,
			tenantID); err != nil {
			return fmt.Errorf("lock tenant key rotation: %w", err)
		}

		var maxVersion int
		var destroyed bool
		if err := sc.Q.QueryRow(ctx, `
			SELECT coalesce(max(version), 0), coalesce(bool_or(state = 'destroyed'), false)
			  FROM public.tenant_keys
			 WHERE tenant_id = $1`, tenantID).Scan(&maxVersion, &destroyed); err != nil {
			return fmt.Errorf("read tenant key chain: %w", err)
		}
		if destroyed {
			return ErrKeyDestroyed
		}

		kv, err := build(ctx, maxVersion+1)
		if err != nil {
			return fmt.Errorf("build successor: %w", err)
		}
		if kv.TenantID != tenantID || kv.Version != maxVersion+1 ||
			kv.State != StateActive || (kv.Mode != ModeManaged && kv.Mode != ModeBYOK) {
			return errors.New("tenantkeys: rotation builder returned an invalid successor")
		}

		if _, err := sc.Q.Exec(ctx, `
			UPDATE public.tenant_keys
			   SET state = 'retired', retired_at = $2
			 WHERE tenant_id = $1 AND state = 'active'`, tenantID, at); err != nil {
			return fmt.Errorf("retire predecessor: %w", err)
		}
		if _, err := sc.Q.Exec(ctx, `
			INSERT INTO public.tenant_keys
			       (tenant_id, version, mode, state, wrapped_kek, byok_ref, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			kv.TenantID, kv.Version, kv.Mode, kv.State, kv.WrappedKEK, kv.BYOKRef, kv.CreatedAt); err != nil {
			return fmt.Errorf("insert successor: %w", err)
		}
		if err := s.audit(ctx, sc, actor, kv); err != nil {
			return fmt.Errorf("append rotation audit: %w", err)
		}
		out = kv
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// --- In-memory implementation (unit tests) ---

// MemStore is a thread-safe in-memory Store.
type MemStore struct {
	mu                      sync.Mutex
	keys                    map[string][]KeyVersion // tenant -> versions
	fail                    bool
	failNextRotationInsert  error
	failNextRotationAudit   error
	committedRotationAudits []rotationAuditRecord
}

type rotationAuditRecord struct {
	TenantID string
	Actor    string
	Version  int
	Mode     string
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore { return &MemStore{keys: map[string][]KeyVersion{}} }

// FailAll makes every call fail (fail-safe tests).
func (m *MemStore) FailAll(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = fail
}

// FailNextRotationInsert injects a successor-insert failure after the staged
// predecessor retirement. It proves the live chain is not published.
func (m *MemStore) FailNextRotationInsert(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNextRotationInsert = err
}

// FailNextRotationAudit injects a mandatory-audit failure after both staged key
// mutations. It proves the entire staged transaction is discarded.
func (m *MemStore) FailNextRotationAudit(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNextRotationAudit = err
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

// RotateAtomic gives unit tests the same publish-after-audit semantics as the
// PostgreSQL transaction. The live map is replaced only after every staged
// step succeeds.
func (m *MemStore) RotateAtomic(
	ctx context.Context,
	tenantID, actor string,
	at time.Time,
	build RotationBuilder,
) (*KeyVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(actor) == "" || build == nil {
		return nil, errors.New("tenantkeys: tenant, actor, and rotation builder are required")
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != tenantID {
		return nil, errors.New("tenantkeys: rotation tenant does not match request scope")
	}

	staged := cloneKeyMap(m.keys)
	maxVersion := 0
	for _, current := range staged[tenantID] {
		if current.State == StateDestroyed {
			return nil, ErrKeyDestroyed
		}
		if current.Version > maxVersion {
			maxVersion = current.Version
		}
	}
	kv, err := build(ctx, maxVersion+1)
	if err != nil {
		return nil, fmt.Errorf("build successor: %w", err)
	}
	if kv.TenantID != tenantID || kv.Version != maxVersion+1 ||
		kv.State != StateActive || (kv.Mode != ModeManaged && kv.Mode != ModeBYOK) {
		return nil, errors.New("tenantkeys: rotation builder returned an invalid successor")
	}

	for i := range staged[tenantID] {
		if staged[tenantID][i].State == StateActive {
			staged[tenantID][i].State = StateRetired
			retiredAt := at
			staged[tenantID][i].RetiredAt = &retiredAt
		}
	}
	if m.failNextRotationInsert != nil {
		err := m.failNextRotationInsert
		m.failNextRotationInsert = nil
		return nil, fmt.Errorf("insert successor: %w", err)
	}
	kv.WrappedKEK = append([]byte(nil), kv.WrappedKEK...)
	staged[tenantID] = append(staged[tenantID], kv)
	if m.failNextRotationAudit != nil {
		err := m.failNextRotationAudit
		m.failNextRotationAudit = nil
		return nil, fmt.Errorf("append rotation audit: %w", err)
	}

	m.keys = staged
	m.committedRotationAudits = append(m.committedRotationAudits, rotationAuditRecord{
		TenantID: tenantID,
		Actor:    actor,
		Version:  kv.Version,
		Mode:     kv.Mode,
	})
	out := kv
	out.WrappedKEK = append([]byte(nil), kv.WrappedKEK...)
	return &out, nil
}

func cloneKeyMap(in map[string][]KeyVersion) map[string][]KeyVersion {
	out := make(map[string][]KeyVersion, len(in))
	for tenantID, chain := range in {
		cp := make([]KeyVersion, len(chain))
		copy(cp, chain)
		for i := range cp {
			cp[i].WrappedKEK = append([]byte(nil), cp[i].WrappedKEK...)
		}
		out[tenantID] = cp
	}
	return out
}
