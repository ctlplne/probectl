// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package whitelabel

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/ee/silo"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestCustomerBrandStorageKeepsTwoTenantsAndHostsSeparate(t *testing.T) {
	ctx := t.Context()
	pool, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	testsupport.LockPostgresPublicCatalog(t, pool)
	first, second := uuid.NewString(), uuid.NewString()
	for _, id := range []string{first, second} {
		if _, err := pool.Exec(ctx, `INSERT INTO public.tenants (id,slug,name) VALUES ($1,$2,'Brand fixture')`,
			id, "branding-"+id); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM public.tenants WHERE id=ANY($1::uuid[])`, []string{first, second}); err != nil {
			t.Error(err)
		}
	})
	if _, err := pool.Exec(ctx, `UPDATE public.tenants SET isolation_model='siloed' WHERE id=$1`, second); err != nil {
		t.Fatal(err)
	}
	provisioner := silo.NewProvisioner(pool, silo.CHPlanes{}, nil, 0, nil)
	t.Cleanup(func() {
		if err := provisioner.Teardown(context.Background(), second, "", tenancy.IsolationSiloed); err != nil {
			t.Error(err)
		}
	})
	if err := provisioner.Provision(ctx, second, "", tenancy.IsolationSiloed); err != nil {
		t.Fatal(err)
	}
	previousRouter := tenancy.CurrentRouter()
	router := silo.NewRouter(pool, nil, 0)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(previousRouter) })
	for id, schema := range map[string]string{first: "", second: silo.SchemaName(second)} {
		targets, err := router.TargetsFor(ctx, id)
		if err != nil || targets.PGSchema != schema {
			t.Fatalf("tenant %s did not route to its expected PostgreSQL target: %+v, %v", id, targets, err)
		}
	}
	const sharedHost = "console.example"
	s := NewStore(pool, nil, "https://"+sharedHost+":8443/auth/callback")
	if _, err := pool.Exec(ctx, `INSERT INTO public.tenant_branding (tenant_id,product_name,custom_domain)
		VALUES ($1,'Dormant legacy brand','legacy.example')`, first); err != nil {
		t.Fatal(err)
	}
	if _, rev, err := s.ReadAdmin(ctx, first); err != nil || rev != 0 {
		t.Fatal("legacy brand reactivated", rev, err)
	}
	replace := func(tenant string, expected int64, brand Brand) error {
		return tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
			_, err := Replace(ctx, q, tenant, "operator@example.test", expected, brand)
			return err
		})
	}
	for _, row := range []struct {
		id, name, host, primary string
		logoWidth               int
	}{
		{first, "Northstar", "northstar-" + first + ".example", "28 85% 30%", 4},
		{second, "Riverside", "riverside-" + second + ".example", "28 85% 29%", 5},
	} {
		brand, err := s.Validate(Brand{
			Name: row.name, Domain: row.host, LogoDataURI: customerBrandFixtureLogo(t, row.logoWidth),
			Colors: map[string]string{"--primary": row.primary, "--primary-foreground": "0 0% 100%"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := replace(row.id, 0, brand); err != nil {
			t.Fatal(err)
		}
		tid, public, err := s.ForHost(ctx, row.host)
		if err != nil || tid != row.id || public.Customer == nil || public.Customer.Name != row.name ||
			public.Customer.LogoDataURI != brand.LogoDataURI || !maps.Equal(public.TokenOverrides, brand.Colors) ||
			!public.CustomerDomain || public.AttributionLine() == "" {
			t.Fatal("wrong domain presentation", tid, err)
		}
		if host, err := s.HostForTenant(ctx, row.id); err != nil || host != row.host {
			t.Fatal("sign-in link selected another customer's domain", host, err)
		}
		scoped := tenancy.WithTenant(ctx, tenancy.ID(row.id))
		guarded := tenancy.WithTxGuard(scoped, func(context.Context, tenancy.Querier) error {
			return errors.New("fixture rejected the write lease")
		})
		router.Invalidate()
		got, err := s.ForTenant(guarded, row.id)
		if err != nil || got.Customer == nil || got.Customer.Name != row.name ||
			got.Customer.LogoDataURI != brand.LogoDataURI || !maps.Equal(got.TokenOverrides, brand.Colors) ||
			got.CustomerDomain || got.AttributionLine() != public.AttributionLine() {
			t.Fatal("tenant presentation lookup changed or took the output job's write lease", err)
		}
	}
	owned := tenancy.WithTenant(ctx, tenancy.ID(first))
	if _, err := s.ForTenant(owned, second); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatal("foreign scope accepted", err)
	}
	if err := tenancy.InTenant(owned, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var rows int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM public.tenant_branding WHERE tenant_id=$1`, second).Scan(&rows); err != nil {
			return err
		}
		if rows != 0 {
			t.Fatal("RLS exposed the other customer's brand")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := replace(first, 1, Brand{Domain: "riverside-" + second + ".example"}); !errors.Is(err, ErrDomainInUse) {
		t.Fatal("duplicate domain accepted", err)
	}
	if err := replace(first, 0, Brand{Name: "new brand"}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatal("stale edit accepted", err)
	}
	if tid, got, err := s.ForHost(ctx, "legacy.example"); err != nil || tid != "" || got.Customer != nil {
		t.Fatal("inactive legacy domain resolved", tid, err)
	}
	// Simulate a stored assignment from before validation or a hostname that
	// became reserved after a deployment URL change.
	secondHost := "riverside-" + second + ".example"
	for _, input := range []struct{ host, reason string }{
		{"192.0.513", "an IPv4 alias"},
		{sharedHost, "the shared console"},
	} {
		if _, err := pool.Exec(ctx, `UPDATE public.tenant_branding SET brand_domain=$1 WHERE tenant_id=$2`,
			input.host, first); err != nil {
			t.Fatal(err)
		}
		if host, err := s.HostForTenant(ctx, first); err != nil || host != "" {
			t.Fatalf("shared sign-in forwarded to %s: %q, %v", input.reason, host, err)
		}
		requestHost := input.host + ":8443"
		if owner, err := s.TenantForHost(ctx, requestHost); err != nil || owner != "" {
			t.Fatalf("%s selected a sign-in tenant: %q, %v", input.reason, owner, err)
		}
		if owner, got, err := s.ForHost(ctx, requestHost); err != nil || owner != "" || got.Customer != nil {
			t.Fatalf("%s selected a tenant's presentation: %q, %v", input.reason, owner, err)
		}
		if host, err := s.HostForTenant(ctx, second); err != nil || host != secondHost {
			t.Fatal("invalid assignment affected the sibling's sign-in host", host, err)
		}
	}
	firstHost := "northstar-" + first + ".example"
	if err := replace(first, 1, Brand{Name: "Northstar", Domain: firstHost}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE public.tenants SET status='suspended' WHERE id=$1`, first); err != nil {
		t.Fatal(err)
	}
	if owner, err := s.TenantForHost(ctx, firstHost); err != nil || owner != first {
		t.Fatal("suspended domain lost its owner", owner, err)
	}
	if host, err := s.HostForTenant(ctx, first); err != nil || host != "" {
		t.Fatal("shared sign-in forwarded to a suspended customer", host, err)
	}
	if owner, got, err := s.ForHost(ctx, firstHost); err != nil || owner != first || got.Customer != nil || !got.CustomerDomain {
		t.Fatal("suspended domain exposed customer presentation or lost its reservation", owner, err)
	}
	if owner, got, err := s.ForHost(ctx, secondHost); err != nil || owner != second || got.CustomerName() != "Riverside" {
		t.Fatal("suspending one customer affected its sibling", owner, err)
	}
}
