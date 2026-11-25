// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package whitelabel

import (
	"context"
	"errors"
	"maps"
	"math"
	"net/url"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/branding"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrTenantUnavailable = errors.New("branding tenant unavailable")
	ErrRevisionConflict  = errors.New("branding changed since it was read")
	ErrDomainInUse       = errors.New("branding domain is already assigned")
)

type Store struct {
	pool       *pgxpool.Pool
	deployment map[string]string
	sharedHost string
}

func NewStore(pool *pgxpool.Pool, deployment map[string]string, sharedCallback string) *Store {
	var host string
	if callback, err := url.Parse(sharedCallback); err == nil && callback.Scheme == "https" {
		host = domainName(callback.Hostname())
	}
	return &Store{pool: pool, deployment: maps.Clone(deployment), sharedHost: host}
}

// ForTenant resolves presentation inside the tenant storage partition. The
// tenant identity comes from the authenticated principal or frozen output job.
func (s *Store) ForTenant(ctx context.Context, tenantID string) (branding.Branding, error) {
	scope, ok := tenancy.FromContext(ctx)
	if !ok || scope.String() != tenantID {
		return branding.Branding{}, tenancy.ErrNoTenant
	}
	var brand Brand
	// Scheduled outputs carry a write fence for publication. A cold silo
	// router reads the provider registry before starting the tenant snapshot.
	// Neither read needs the output job's write lease.
	readCtx := tenancy.WithTxGuard(ctx, nil)
	err := tenancy.InTenantReadSnapshot(readCtx, s.pool, func(ctx context.Context, scoped tenancy.Scope) error {
		err := scoped.Q.QueryRow(ctx, `SELECT product_name, logo_data_uri, token_overrides,
		    coalesce(brand_domain, '') FROM public.tenant_branding
		    WHERE tenant_id = $1 AND brand_revision > 0`, scoped.Tenant.String()).
			Scan(&brand.Name, &brand.LogoDataURI, &brand.Colors, &brand.Domain)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	brand.Domain = s.customerDomain(domainName(brand.Domain))
	return brand.Presentation(s.deployment, false), err
}

func (s *Store) customerDomain(domain string) string {
	if domain == s.sharedHost {
		return ""
	}
	return domain
}

// TenantForHost resolves the owner of an exact hostname. The assignment
// remains reserved throughout suspension and offboarding.
func (s *Store) TenantForHost(ctx context.Context, host string) (string, error) {
	domain := s.customerDomain(requestDomain(host))
	if domain == "" {
		return "", nil
	}
	var tenantID string
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		err := q.QueryRow(ctx, `SELECT tenant_id::text FROM public.tenant_branding
		    WHERE brand_domain=$1 AND brand_revision>0`, domain).Scan(&tenantID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return tenantID, err
}

// HostForTenant returns an active customer's published sign-in host for a
// shared-console login link. It reads only the public routing assignment.
func (s *Store) HostForTenant(ctx context.Context, tenantID string) (string, error) {
	var domain string
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		err := q.QueryRow(ctx, `SELECT b.brand_domain
		    FROM public.tenant_branding b JOIN public.tenants t ON t.id=b.tenant_id
		    WHERE b.tenant_id=$1 AND b.brand_domain IS NOT NULL AND b.brand_revision>0 AND t.status='active'`, tenantID).
			Scan(&domain)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return s.customerDomain(domainName(domain)), err
}

// ForHost exposes only the active, public presentation on an exact domain.
func (s *Store) ForHost(ctx context.Context, host string) (string, branding.Branding, error) {
	domain := s.customerDomain(requestDomain(host))
	if domain == "" {
		return "", branding.Deployment(s.deployment), nil
	}
	var tenantID string
	var active bool
	var brand Brand
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		err := q.QueryRow(ctx, `SELECT b.tenant_id::text, t.status='active',
		    CASE WHEN t.status='active' THEN b.product_name ELSE '' END,
		    CASE WHEN t.status='active' THEN b.logo_data_uri ELSE '' END,
		    CASE WHEN t.status='active' THEN b.token_overrides ELSE '{}'::jsonb END
		    FROM public.tenant_branding b JOIN public.tenants t ON t.id=b.tenant_id
		    WHERE b.brand_domain=$1 AND b.brand_revision>0`, domain).
			Scan(&tenantID, &active, &brand.Name, &brand.LogoDataURI, &brand.Colors)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil || tenantID == "" {
		return "", branding.Deployment(s.deployment), err
	}
	if !active {
		presentation := branding.Deployment(s.deployment)
		presentation.CustomerDomain = true
		return tenantID, presentation, nil
	}
	brand.Domain = domain
	return tenantID, brand.Presentation(s.deployment, true), nil
}

func (s *Store) Validate(input Brand) (Brand, error) {
	brand, err := Normalize(input, s.deployment)
	if err != nil {
		return Brand{}, err
	}
	if brand.Domain != "" && s.customerDomain(brand.Domain) == "" {
		return Brand{}, errors.New("brand domain is reserved for the shared console")
	}
	return brand, nil
}

func (s *Store) ReadAdmin(ctx context.Context, tenantID string) (Brand, int64, error) {
	var brand Brand
	var revision int64
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		var err error
		brand, revision, err = read(ctx, q, tenantID)
		return err
	})
	return brand, revision, err
}

func read(ctx context.Context, q tenancy.Querier, tenantID string) (Brand, int64, error) {
	id, err := uuid.Parse(tenantID)
	if err != nil || id == uuid.Nil || id.String() != tenantID {
		return Brand{}, 0, ErrTenantUnavailable
	}
	var brand Brand
	var revision int64
	err = q.QueryRow(ctx, `SELECT coalesce(b.product_name,''), coalesce(b.logo_data_uri,''),
	    coalesce(b.token_overrides,'{}'::jsonb), coalesce(b.brand_domain,''), coalesce(b.brand_revision,0)
	    FROM public.tenants t LEFT JOIN public.tenant_branding b ON b.tenant_id=t.id AND b.brand_revision>0
	    WHERE t.id=$1`, tenantID).Scan(&brand.Name, &brand.LogoDataURI, &brand.Colors, &brand.Domain, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Brand{}, 0, ErrTenantUnavailable
	}
	return brand, revision, err
}

// Replace stores one complete validated customer brand. The caller owns the
// audited provider transaction. The tenant row serializes the first write and
// subsequent revisions even while no brand exists yet.
func Replace(ctx context.Context, q tenancy.Querier, tenantID, actor string, expected int64, brand Brand) (int64, error) {
	id, err := uuid.Parse(tenantID)
	if err != nil || id == uuid.Nil || id.String() != tenantID {
		return 0, ErrTenantUnavailable
	}
	var state string
	err = q.QueryRow(ctx, `SELECT status FROM public.tenants WHERE id=$1 FOR UPDATE`, tenantID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrTenantUnavailable
	}
	if err != nil {
		return 0, err
	}
	if state != "active" && state != "suspended" {
		return 0, ErrTenantUnavailable
	}
	_, revision, err := read(ctx, q, tenantID)
	if err != nil {
		return 0, err
	}
	if revision != expected || revision == math.MaxInt64 {
		return 0, ErrRevisionConflict
	}
	revision++
	if brand.Colors == nil {
		brand.Colors = map[string]string{}
	}
	_, err = q.Exec(ctx, `INSERT INTO public.tenant_branding
	    (tenant_id, product_name, logo_data_uri, token_overrides, brand_domain, brand_revision, updated_by)
	    VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7)
	    ON CONFLICT (tenant_id) DO UPDATE SET product_name=excluded.product_name, logo_data_uri=excluded.logo_data_uri,
	      token_overrides=excluded.token_overrides, brand_domain=excluded.brand_domain, brand_revision=excluded.brand_revision,
	      updated_by=excluded.updated_by, updated_at=clock_timestamp()`, tenantID, brand.Name,
		brand.LogoDataURI, brand.Colors, brand.Domain, revision, actor)
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "23505" &&
		databaseError.ConstraintName == "tenant_branding_active_domain_idx" {
		return 0, ErrDomainInUse
	}
	return revision, err
}
