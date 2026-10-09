// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build probectl_core

package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/cluster"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/secrets"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/topology"
)

// attachEE is the core-only no-op twin of the ee attach seam: the
// -tags probectl_core build links zero ee/ code, and this stub keeps main.go
// identical across both variants (one binary lineage, two link sets). The
// editions gate builds this variant in CI to prove core stands alone.
func attachEE(context.Context, *control.Server, *config.Config, *slog.Logger,
	*license.Manager, *pgxpool.Pool, *control.LatestResults, flowstore.Store,
	*pathstore.ClickHouse, ebpfstore.Store, otelstore.Store, endpointstore.Store,
	*tenantlife.Engine, *audit.WormExporter,
	*secrets.Resolver,
	*fairness.Gate, topology.Store,
	*cluster.Coordinator) error {
	return nil
}

// rewrapTenantKeysEnvelope is the core-only no-op twin: a core build has no
// managed per-tenant KEKs (the tenant_keys store ships only with ee/), so the
// deployment envelope rewrap has nothing to re-seal here (CRY-02).
func rewrapTenantKeysEnvelope(context.Context, *config.Config, *store.DB, string, string, bool, bool) (store.EnvelopeRewrapStats, error) {
	return store.EnvelopeRewrapStats{Store: "tenant_keys.wrapped_kek (ee absent)"}, nil
}

// rewrapProviderTOTPEnvelope is the core-only no-op twin (PLAT-04): the provider
// plane (and its operator TOTP secrets) ships only with ee/, so a core build has
// nothing to re-seal here.
func rewrapProviderTOTPEnvelope(context.Context, *config.Config, *store.DB, string, string, bool, bool) (store.EnvelopeRewrapStats, error) {
	return store.EnvelopeRewrapStats{Store: "provider_operators.totp (ee absent)"}, nil
}

// attachEETenancyRouter is the core-only no-op twin (DPR-045): a core build
// has no siloed tenants, so every tenant already routes to the pooled schema.
func attachEETenancyRouter(*config.Config, *pgxpool.Pool, *slog.Logger) error { return nil }

// attachQuotaChecker is inert in the core-only build: no metering, no quotas.
func attachQuotaChecker(*license.Manager, *pgxpool.Pool) any { return nil }
