// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build probectl_core

package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/control"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

// attachEE is the core-only no-op twin of the ee attach seam: the
// -tags probectl_core build links zero ee/ code, and this stub keeps main.go
// identical across both variants (one binary lineage, two link sets). The
// editions gate builds this variant in CI to prove core stands alone.
func attachEE(context.Context, *control.Server, *config.Config, *slog.Logger,
	*license.Manager, *pgxpool.Pool, *control.LatestResults, flowstore.Store,
	*pathstore.ClickHouse, ebpfstore.Store, otelstore.Store,
	*tenantlife.Engine, func(context.Context, string) (string, error),
	*fairness.Gate, topology.Store) error {
	return nil
}
