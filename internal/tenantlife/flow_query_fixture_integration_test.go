// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
)

// flowQueryRuntime exercises saved-query RLS with an actual restricted login.
// Its disposable role and pool belong solely to this integration fixture.
func flowQueryRuntime(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	config := admin.Config().Copy()
	password, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = "probectl-qa-beta-flow-query-" + hex.EncodeToString(password[:6])
	config.ConnConfig.Password = hex.EncodeToString(password)
	clear(password)
	role := pgx.Identifier{config.ConnConfig.User}.Sanitize()
	if _, err := admin.Exec(t.Context(), `CREATE ROLE `+role+` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD '`+config.ConnConfig.Password+`'`); err != nil {
		t.Fatal("owned saved-query fixture role creation failed")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, `DROP ROLE `+role); err != nil {
			t.Error("owned saved-query fixture role cleanup failed")
		}
	})
	for _, statement := range []string{`GRANT probectl_app TO ` + role, `GRANT probectl_provider TO ` + role + ` WITH INHERIT FALSE, SET TRUE`} {
		if _, err := admin.Exec(t.Context(), statement); err != nil {
			t.Fatal("owned saved-query fixture role membership unavailable")
		}
	}
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal("saved-query fixture runtime pool unavailable")
	}
	t.Cleanup(pool.Close)
	var super, bypass, tls bool
	if err := pool.QueryRow(t.Context(), `SELECT rolsuper,rolbypassrls,COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false) FROM pg_roles WHERE rolname=current_user`).Scan(&super, &bypass, &tls); err != nil || super || bypass {
		t.Fatal("saved-query fixture requires actual NOSUPERUSER NOBYPASSRLS login")
	}
	if tls {
		t.Log("saved-query fixture runtime TLS transport verified")
	}
	return pool
}

func flowQueryUUID(t *testing.T) string {
	t.Helper()
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
