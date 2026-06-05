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
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/ee/provider"
	"github.com/imfeelingtheagi/probectl/ee/silo"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/control"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// attachEE wires licensed ee/ features onto the core server — the Build* seam
// pattern (CLAUDE.md §6, editions): one Has() check per feature, here and
// nowhere else. Unlicensed features are simply never constructed; their
// surfaces stay hidden (404).
func attachEE(srv *control.Server, cfg *config.Config, log *slog.Logger,
	lic *license.Manager, pool *pgxpool.Pool, results *control.LatestResults,
	flowStore flowstore.Store) error {
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
