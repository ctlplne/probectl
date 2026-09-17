// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	func(context.Context, string) ([]byte, func(), error),
	*fairness.Gate, topology.Store,
	*cluster.Coordinator) error {
	return nil
}

// attachEETenancyRouter is the core-only no-op twin (DPR-045): a core build
// has no siloed tenants, so every tenant already routes to the pooled schema.
func attachEETenancyRouter(*config.Config, *pgxpool.Pool, *slog.Logger) error { return nil }

// attachQuotaChecker is inert in the core-only build: no metering, no quotas.
func attachQuotaChecker(*license.Manager, *pgxpool.Pool) any { return nil }
