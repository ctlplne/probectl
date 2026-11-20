// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package shipped

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RestartControlOnPostgresCopy switches the fixture's control plane to an
// independent copy of its own Postgres state. Preserve its deployment keys
// and least-privilege runtime role so stored encryption can be tested after
// restore. It returns the copy's administrative DSN for scoped readback.
func (s *Stack) RestartControlOnPostgresCopy(t *testing.T, label string) string {
	t.Helper()
	if t != s.owner {
		t.Fatal("the fixture owner must manage the copied database and control process cleanup")
	}
	admin, err := url.Parse(s.AdminDSN)
	if err != nil || admin.User == nil {
		t.Fatal("could not identify the receipt's Postgres database", err)
	}
	original := strings.TrimPrefix(admin.Path, "/")
	if !strings.HasPrefix(original, "probectl_") || strings.Contains(original, "/") || len(original) > 53 {
		t.Fatal("expected a database owned by this shipped receipt")
	}
	const runtimeKey = "PROBECTL_DATABASE_URL="
	var runtimeDSN string
	for _, setting := range s.serveEnv {
		if value, ok := strings.CutPrefix(setting, runtimeKey); ok {
			runtimeDSN = value
		}
	}
	runtime, err := url.Parse(runtimeDSN)
	if err != nil || runtime.User == nil || runtime.User.Username() != s.serveRole || runtime.Path != admin.Path || runtime.Host != admin.Host {
		t.Fatal("expected the fixture's runtime role on its own source database")
	}
	s.Stop(t, s.controlLabel)
	server := *admin
	server.Path = "/postgres"
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, server.String())
	if err != nil {
		t.Fatal("open the fixture PostgreSQL server", err)
	}
	copyName := original + "_copy"
	quoted := pgx.Identifier{copyName}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE DATABASE "+quoted+" TEMPLATE "+pgx.Identifier{original}.Sanitize()); err != nil {
		pool.Close()
		t.Fatal("copy the stopped fixture database", err)
	}
	t.Cleanup(func() {
		defer pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Error("remove the fixture restore", err)
		}
	})
	admin.Path = "/" + copyName
	runtime.Path = admin.Path
	s.serveEnv = append(s.serveEnv, runtimeKey+runtime.String(), "PROBECTL_MIGRATE_DATABASE_URL="+admin.String())
	s.RestartControl(t, label, nil)
	return admin.String()
}
