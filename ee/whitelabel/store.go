// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package whitelabel

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// PGStore persists brands via the probectl_provider role (the explicit
// provider policies from migration 0027).
type PGStore struct{ pool *pgxpool.Pool }

// NewPGStore wraps a pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

func (s *PGStore) in(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
	return tenancy.InProvider(ctx, s.pool, fn)
}

const tenantBrandCols = `tenant_id::text, product_name, logo_data_uri, login_message,
	token_overrides, email_from_name, email_footer, coalesce(custom_domain, ''), updated_by`

func scanBrand(row pgx.Row, withTenant bool) (*Record, error) {
	var rec Record
	var overrides []byte
	var err error
	if withTenant {
		err = row.Scan(&rec.TenantID, &rec.ProductName, &rec.LogoDataURI, &rec.LoginMessage,
			&overrides, &rec.EmailFromName, &rec.EmailFooter, &rec.CustomDomain, &rec.UpdatedBy)
	} else {
		err = row.Scan(&rec.ProductName, &rec.LogoDataURI, &rec.LoginMessage,
			&overrides, &rec.EmailFromName, &rec.EmailFooter, &rec.UpdatedBy)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // absent, not an error
		}
		return nil, err
	}
	if len(overrides) > 0 {
		if err := json.Unmarshal(overrides, &rec.TokenOverrides); err != nil {
			return nil, err
		}
	}
	return &rec, nil
}

func (s *PGStore) TenantBrand(ctx context.Context, tenantID string) (*Record, error) {
	var rec *Record
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		rec, e = scanBrand(q.QueryRow(ctx,
			`SELECT `+tenantBrandCols+` FROM tenant_branding WHERE tenant_id = $1`, tenantID), true)
		return e
	})
	return rec, err
}

func (s *PGStore) TenantByDomain(ctx context.Context, host string) (*Record, error) {
	var rec *Record
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		rec, e = scanBrand(q.QueryRow(ctx,
			`SELECT `+tenantBrandCols+` FROM tenant_branding WHERE custom_domain = $1`, normalizeDomain(host)), true)
		return e
	})
	return rec, err
}

func (s *PGStore) ProviderBrand(ctx context.Context) (*Record, error) {
	var rec *Record
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		rec, e = scanBrand(q.QueryRow(ctx,
			`SELECT product_name, logo_data_uri, login_message, token_overrides,
			        email_from_name, email_footer, updated_by FROM provider_branding`), false)
		return e
	})
	return rec, err
}

func (s *PGStore) SetTenantBrand(ctx context.Context, rec Record) error {
	overrides, err := json.Marshal(orEmptyMap(rec.TokenOverrides))
	if err != nil {
		return err
	}
	var domain any
	if d := normalizeDomain(rec.CustomDomain); d != "" {
		domain = d
	}
	return s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO tenant_branding (tenant_id, product_name, logo_data_uri, login_message,
			                             token_overrides, email_from_name, email_footer, custom_domain, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, now())
			ON CONFLICT (tenant_id) DO UPDATE SET
			  product_name = EXCLUDED.product_name, logo_data_uri = EXCLUDED.logo_data_uri,
			  login_message = EXCLUDED.login_message, token_overrides = EXCLUDED.token_overrides,
			  email_from_name = EXCLUDED.email_from_name, email_footer = EXCLUDED.email_footer,
			  custom_domain = EXCLUDED.custom_domain, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			rec.TenantID, rec.ProductName, rec.LogoDataURI, rec.LoginMessage,
			string(overrides), rec.EmailFromName, rec.EmailFooter, domain, rec.UpdatedBy)
		return err
	})
}

func (s *PGStore) SetProviderBrand(ctx context.Context, rec Record) error {
	overrides, err := json.Marshal(orEmptyMap(rec.TokenOverrides))
	if err != nil {
		return err
	}
	return s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO provider_branding (singleton, product_name, logo_data_uri, login_message,
			                               token_overrides, email_from_name, email_footer, updated_by, updated_at)
			VALUES (true, $1, $2, $3, $4::jsonb, $5, $6, $7, now())
			ON CONFLICT (singleton) DO UPDATE SET
			  product_name = EXCLUDED.product_name, logo_data_uri = EXCLUDED.logo_data_uri,
			  login_message = EXCLUDED.login_message, token_overrides = EXCLUDED.token_overrides,
			  email_from_name = EXCLUDED.email_from_name, email_footer = EXCLUDED.email_footer,
			  updated_by = EXCLUDED.updated_by, updated_at = now()`,
			rec.ProductName, rec.LogoDataURI, rec.LoginMessage,
			string(overrides), rec.EmailFromName, rec.EmailFooter, rec.UpdatedBy)
		return err
	})
}

func orEmptyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// --- In-memory implementation (unit tests) ---

// MemStore is a thread-safe in-memory Store.
type MemStore struct {
	mu       sync.Mutex
	tenants  map[string]Record
	byDomain map[string]string // host -> tenant id
	master   *Record
	fail     bool
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{tenants: map[string]Record{}, byDomain: map[string]string{}}
}

// FailAll makes every read fail (degrade tests).
func (m *MemStore) FailAll(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = fail
}

func (m *MemStore) TenantBrand(_ context.Context, tenantID string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	if rec, ok := m.tenants[tenantID]; ok {
		cp := rec
		return &cp, nil
	}
	return nil, nil
}

func (m *MemStore) TenantByDomain(_ context.Context, host string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	if id, ok := m.byDomain[normalizeDomain(host)]; ok {
		rec := m.tenants[id]
		cp := rec
		return &cp, nil
	}
	return nil, nil
}

func (m *MemStore) ProviderBrand(context.Context) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	if m.master == nil {
		return nil, nil
	}
	cp := *m.master
	return &cp, nil
}

func (m *MemStore) SetTenantBrand(_ context.Context, rec Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for host, id := range m.byDomain {
		if id == rec.TenantID {
			delete(m.byDomain, host)
		}
	}
	if d := normalizeDomain(rec.CustomDomain); d != "" {
		m.byDomain[d] = rec.TenantID
	}
	m.tenants[rec.TenantID] = rec
	return nil
}

func (m *MemStore) SetProviderBrand(_ context.Context, rec Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec.TenantID = ""
	m.master = &rec
	return nil
}
