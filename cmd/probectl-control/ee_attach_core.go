//go:build probectl_core

package main

import (
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/control"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

// attachEE is the core-only no-op twin of the ee attach seam: the
// -tags probectl_core build links zero ee/ code, and this stub keeps main.go
// identical across both variants (one binary lineage, two link sets). The
// editions gate builds this variant in CI to prove core stands alone.
func attachEE(*control.Server, *config.Config, *slog.Logger,
	*license.Manager, *pgxpool.Pool, *control.LatestResults, flowstore.Store) error {
	return nil
}
