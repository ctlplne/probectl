// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package shipped

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ApplicationReadPool uses this stack's real serve login, never its migration
// login. RLS proofs must not accidentally succeed through privileged SQL.
func (s *Stack) ApplicationReadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	var dsn string
	for _, entry := range s.serveEnv {
		if value, ok := strings.CutPrefix(entry, "PROBECTL_DATABASE_URL="); ok {
			dsn = value
		}
	}
	config, err := pgxpool.ParseConfig(dsn)
	if dsn == "" || err != nil || config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.InsecureSkipVerify || config.ConnConfig.TLSConfig.ServerName == "" {
		t.Fatal("application proof requires certificate-verified TLS database credentials")
	}
	// A weaker fallback connection cannot qualify the TLS/RLS receipt.
	if len(config.ConnConfig.Fallbacks) != 0 {
		t.Fatal("application proof cannot use a weaker database transport fallback")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal("open application proof database pool")
	}
	t.Cleanup(pool.Close)
	var role string
	var superuser, bypass, tls bool
	if err := pool.QueryRow(t.Context(), `SELECT current_user,r.rolsuper,r.rolbypassrls,s.ssl FROM pg_roles r JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE r.rolname=current_user`).Scan(&role, &superuser, &bypass, &tls); err != nil || role != s.serveRole || superuser || bypass || !tls {
		t.Fatal("application proof lost exact TLS, non-superuser, NOBYPASSRLS serve identity")
	}
	return pool
}
