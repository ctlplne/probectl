// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
)

// Keep the complete library proof on an actual restricted login even when CI
// supplies only its migration connection. The owned role inherits the verified
// TLS connection settings; it never falls back to the administrator for data.
func queryLibraryRuntime(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	config := admin.Config().Copy()
	if dsn := os.Getenv("PROBECTL_FLOW_FILTER_TEST_DATABASE_URL"); dsn != "" {
		var err error
		config, err = pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal("library application-role connection configuration invalid")
		}
	} else {
		password, err := crypto.Random(32)
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.User = "probectl-qa-beta-library-" + hex.EncodeToString(password[:6])
		config.ConnConfig.Password = hex.EncodeToString(password)
		clear(password)
		role := pgx.Identifier{config.ConnConfig.User}.Sanitize()
		if _, err := admin.Exec(t.Context(), `CREATE ROLE `+role+` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD '`+config.ConnConfig.Password+`'`); err != nil {
			t.Fatal("owned library fixture role creation failed")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := admin.Exec(ctx, `DROP ROLE `+role); err != nil {
				t.Error("owned library fixture role cleanup failed")
			}
		})
		for _, statement := range []string{`GRANT probectl_app TO ` + role, `GRANT probectl_provider TO ` + role + ` WITH INHERIT FALSE, SET TRUE`} {
			if _, err := admin.Exec(t.Context(), statement); err != nil {
				t.Fatal("owned library fixture role membership unavailable")
			}
		}
	}
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal("library runtime pool unavailable")
	}
	t.Cleanup(pool.Close)
	var super, bypass, tls bool
	if err := pool.QueryRow(t.Context(), `SELECT rolsuper,rolbypassrls,COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false) FROM pg_roles WHERE rolname=current_user`).Scan(&super, &bypass, &tls); err != nil || super || bypass {
		t.Fatal("library proof requires actual NOSUPERUSER NOBYPASSRLS runtime")
	}
	if tls {
		t.Log("library restricted runtime TLS transport verified")
	}
	return pool
}
