//go:build !probectl_core

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
//
// This file is THE sanctioned ee attach seam (allowlisted in
// scripts/check_editions_imports.sh): the one place core meets ee/. The
// default build links the commercial tree (one repo, one binary lineage —
// runtime activation is license-gated, never source-gated); the core-only CI
// build (-tags probectl_core) compiles the no-op twin in ee_attach_core.go
// instead, proving core stands alone with ee/ absent.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/ee/billing"
	"github.com/imfeelingtheagi/probectl/ee/provider"
	"github.com/imfeelingtheagi/probectl/ee/silo"
	"github.com/imfeelingtheagi/probectl/ee/tenantkeys"
	"github.com/imfeelingtheagi/probectl/ee/whitelabel"
	"github.com/imfeelingtheagi/probectl/internal/branding"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/control"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
	"github.com/imfeelingtheagi/probectl/internal/usage"
)

// attachEE wires licensed ee/ features onto the core server — the Build* seam
// pattern (CLAUDE.md §6, editions): one Has() check per feature, here and
// nowhere else. Unlicensed features are simply never constructed; their
// surfaces stay hidden (404).
func attachEE(ctx context.Context, srv *control.Server, cfg *config.Config, log *slog.Logger,
	lic *license.Manager, pool *pgxpool.Pool, results *control.LatestResults,
	flowStore flowstore.Store, life *tenantlife.Engine,
	resolveSecret func(context.Context, string) (string, error),
	fairGate *fairness.Gate) error {
	// Siloed/hybrid isolation (S-T2). Attached BEFORE the provider plane so
	// tenant provisioning can create isolated stores from the first call.
	var siloOps provider.SiloOps
	var routerInvalidate func()
	if lic.Has(license.FeatureSiloedIsolation) {
		planes, err := silo.ParseDataPlanes(cfg.DataPlanes)
		if err != nil {
			return err
		}
		// The ClickHouse leg exists only when the deployment runs ClickHouse;
		// the memory flow store is process-local (logically tenant-keyed).
		var flows silo.FlowDDL
		var chRouter *flowstore.ClickHouse
		if ch, ok := flowStore.(*flowstore.ClickHouse); ok {
			flows, chRouter = ch, ch
		}
		prov := silo.NewProvisioner(pool, flows, planes, cfg.FlowRetentionDays, log)
		router := silo.NewRouter(pool, planes, 0)
		tenancy.SetRouter(router) // Postgres search_path + bus lanes + object prefixes
		if chRouter != nil {
			chRouter.WithRouter(func(tenantID string) (flowstore.Target, error) {
				t, err := router.TargetsFor(context.Background(), tenantID)
				if err != nil {
					return flowstore.Target{}, err
				}
				return flowstore.Target{BaseURL: t.CHBaseURL, Database: t.CHDatabase}, nil
			})
		}
		// Startup catch-up: bring every siloed tenant's schema up to the
		// current public shape (new tables/columns from later migrations) —
		// the S-T2 migration-multiplication answer (docs/isolation.md).
		go func() {
			if err := siloCatchUpAll(context.Background(), pool, prov, log); err != nil {
				log.Warn("silo catch-up failed", "error", err.Error())
			}
		}()
		siloOps, routerInvalidate = prov, router.Invalidate
		log.Info("siloed/hybrid isolation attached (S-T2)",
			"data_planes", silo.PlaneNames(planes), "clickhouse_routed", chRouter != nil)
	}

	// Per-tenant metering + quotas (S-T3). The recorder hooks the core usage
	// seam (results/flows/AI calls meter as they already flow); the collector
	// snapshots per-tenant gauges INSIDE each tenant's own scope; the quota
	// checker gates resource creation (telemetry is never quota-dropped).
	var metering *provider.Metering
	if lic.Has(license.FeatureMetering) {
		bstore := billing.NewPGStore(pool)
		recorder := billing.NewRecorder(bstore, log)
		usage.SetRecorder(recorder)
		checker := billing.NewQuotaChecker(bstore, billing.PGTenantCounter(pool), 30*time.Second)
		usage.SetQuotaChecker(checker)
		collector := billing.NewCollector(bstore, billing.PGTenantLister(pool), billing.PGTenantCounter(pool), log)
		go recorder.Run(ctx, time.Minute)
		go collector.Run(ctx, 15*time.Minute)
		metering = &provider.Metering{Store: bstore, Quotas: checker}
		log.Info("per-tenant metering attached (S-T3)", "flush", "1m", "snapshot", "15m")
	}

	// White-label branding (S-T4): the resolver installs onto the core
	// branding seam (the public /branding endpoint + custom-domain login);
	// the provider console gets the configuration surface. Unlicensed
	// deployments keep the default probectl brand.
	var wl *provider.WhiteLabel
	if lic.Has(license.FeatureWhiteLabel) {
		wstore := whitelabel.NewPGStore(pool)
		resolver := whitelabel.NewResolver(wstore, 0)
		branding.SetSource(resolver)
		wl = &provider.WhiteLabel{Store: wstore, Invalidate: resolver.Invalidate}
		log.Info("white-label branding attached (S-T4)")
	}

	// Per-tenant key isolation / BYOK (S-T6). The keyring replaces the
	// deployment envelope as the PRIMARY sealer; the deployment sealer stays
	// registered as an opener (main installed it), so pre-existing dv1 rows
	// keep decrypting — decrypt-on-read, no migration. BYOK references
	// resolve through the S41 secrets resolver at use time and are validated
	// resolvable BEFORE activation (the lockout guard in ee/tenantkeys).
	if lic.Has(license.FeatureBYOK) {
		if cfg.EnvelopeKey == "" {
			// Fail loudly: a licensed byok deployment without a master KEK
			// would silently store managed tenant KEKs unprotectable.
			return fmt.Errorf("byok is licensed but PROBECTL_ENVELOPE_KEY is not set (the deployment master wraps managed tenant keys)")
		}
		kp, err := crypto.NewStaticKeyProviderFromBase64(cfg.EnvelopeKeyID, cfg.EnvelopeKey)
		if err != nil {
			return fmt.Errorf("byok master key: %w", err)
		}
		ring, err := tenantkeys.NewKeyring(tenantkeys.NewPGStore(pool), crypto.NewEnvelope(kp), tenantkeys.RefResolver(resolveSecret))
		if err != nil {
			return err
		}
		tenantcrypto.SetPrimary(ring) // dv1 opener stays registered (main)
		srv.WithKeyManager(tenantkeys.NewManager(ring))
		log.Info("per-tenant key isolation attached (S-T6)", "scheme", "tk1", "modes", "managed|byok")
	}

	if lic.Has(license.FeatureProviderPlane) {
		h, err := provider.Build(cfg, provider.Deps{
			Pool:     pool,
			License:  lic,
			Log:      log,
			Results:  results,
			Sessions: srv.SessionManager(),
			Perms:    srv.PermissionLoader(),
			Silo:     siloOps,
			SiloInvalidate: func() {
				if routerInvalidate != nil {
					routerInvalidate()
				}
			},
			Metering:   metering,
			WhiteLabel: wl,
			Lifecycle:  life,
			// S-T7: operator fairness views over the CORE gate (enforcement
			// is core; only the views/tuning ride the provider plane).
			Fairness: &provider.Fairness{Gate: fairGate, Store: fairness.NewPGStore(pool)},
		})
		if err != nil {
			return err
		}
		srv.WithProviderPlane(h)
		log.Info("provider plane attached (S-T1)",
			"tier", lic.Tier(), "state", lic.State(), "tenant_band", lic.TenantBand())
	}
	return nil
}

// siloCatchUpAll runs the schema catch-up for every siloed tenant.
func siloCatchUpAll(ctx context.Context, pool *pgxpool.Pool, prov *silo.Provisioner, log *slog.Logger) error {
	var ids []string
	err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx,
			`SELECT id::text FROM tenants WHERE isolation_model = 'siloed' AND status IN ('active','suspended')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := prov.CatchUp(ctx, id); err != nil {
			log.Warn("silo catch-up failed for tenant", "tenant", id, "error", err.Error())
		}
	}
	return nil
}
