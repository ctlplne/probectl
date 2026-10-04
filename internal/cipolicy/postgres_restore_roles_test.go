// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"strings"
	"testing"
)

// TestPostgresBackupRestoreCarriesRoles closes RTO-15: restoring a logical
// pg_dump onto a BRAND-NEW Postgres cluster aborted, because a logical dump does
// not carry cluster ROLES and the schema's owners / GRANTs / RLS policies
// reference probectl + probectl_app + the NOLOGIN auth roles (created by
// migrations, not in the dump). pg_restore died on the first `CREATE POLICY …
// TO probectl_app` and the control could not boot.
//
// The fix: backup_postgres.sh writes a `<dump>.roles.sql` companion
// (pg_dumpall --roles-only --no-role-passwords, probectl* only — no secret
// leaves the source), and restore_postgres.sh applies it, as the bootstrap
// superuser, before the data restore, then sets the login role's password from
// the operator's own credentials. Proven with a real fresh-cluster restore
// drill (6 roles recreated, 89 tables + 418 RLS policies restored, app connects).
//
// Fail-before: the original scripts have no roles companion and connect as the
// (absent) app role, so these assertions fire.
func TestPostgresBackupRestoreCarriesRoles(t *testing.T) {
	backup := readRepoFile(t, "scripts", "backup_postgres.sh")
	if !strings.Contains(backup, "pg_dumpall") || !strings.Contains(backup, "--roles-only") {
		t.Error("RTO-15: backup_postgres.sh must emit a roles companion via `pg_dumpall --roles-only`")
	}
	if !strings.Contains(backup, "--no-role-passwords") {
		t.Error("RTO-15: the roles companion must use --no-role-passwords so no password hash leaves the source")
	}
	if !strings.Contains(backup, ".roles.sql") {
		t.Error("RTO-15: backup_postgres.sh must write the <dump>.roles.sql companion")
	}

	restore := readRepoFile(t, "scripts", "restore_postgres.sh")
	if !strings.Contains(restore, ".roles.sql") {
		t.Error("RTO-15: restore_postgres.sh must apply the carried <dump>.roles.sql before the data restore")
	}
	// It must bootstrap as a SUPERUSER (a fresh cluster has no app role to
	// connect as) and (re)set the login role's password from the operator env.
	if !strings.Contains(restore, "PGSUPERUSER") {
		t.Error("RTO-15: restore_postgres.sh must act as the bootstrap superuser to recreate roles on a fresh cluster")
	}
	if !strings.Contains(restore, "PGAPPPASSWORD") {
		t.Error("RTO-15: restore_postgres.sh must (re)set the login role's password from the operator credentials")
	}
}
