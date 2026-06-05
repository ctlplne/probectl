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
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/ee/provider"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/control"
	"github.com/imfeelingtheagi/probectl/internal/license"
)

// attachEE wires licensed ee/ features onto the core server — the Build* seam
// pattern (CLAUDE.md §6, editions): one Has() check per feature, here and
// nowhere else. Unlicensed features are simply never constructed; their
// surfaces stay hidden (404).
func attachEE(srv *control.Server, cfg *config.Config, log *slog.Logger,
	lic *license.Manager, pool *pgxpool.Pool, results *control.LatestResults) error {
	if lic.Has(license.FeatureProviderPlane) {
		h, err := provider.Build(cfg, provider.Deps{
			Pool:     pool,
			License:  lic,
			Log:      log,
			Results:  results,
			Sessions: srv.SessionManager(),
			Perms:    srv.PermissionLoader(),
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
