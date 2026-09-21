// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestRestoreJobMigratesTheDatabaseItRestored (DPR-107): the restore Job used
// to hand its migrate step PROBECTL_DATABASE_URL from the release secret — the
// LIVE database — while pg_restore wrote into restore.database. Restoring into
// a scratch database (the safe rehearsal those values exist for) therefore
// migrated production and left the restored copy unmigrated, and a release
// whose DSN names TLS material the Job does not mount failed the whole Job
// after the data had already landed. Both steps now read one libpq
// environment, so they cannot disagree, and credentials never enter the URL.
func TestRestoreJobMigratesTheDatabaseItRestored(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	out, err := renderHelmAgentListener(t, "templates/restore-job.yaml",
		"--set", "restore.enabled=true",
		"--set", "restore.backupFile=postgres-probectl-20260917T133511Z.dump.pbk",
		"--set", "restore.host=pg-scratch.probectl.svc.cluster.local",
		"--set", "restore.port=5433",
		"--set", "restore.database=probectl_restore_drill",
	)
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}

	for _, want := range []string{
		`- name: PGHOST`,
		`value: "pg-scratch.probectl.svc.cluster.local"`,
		`- name: PGPORT`,
		`value: "5433"`,
		`- name: PGDATABASE`,
		`value: "probectl_restore_drill"`,
		`-h "${PGHOST}" -p "${PGPORT}" -U "$PGUSER" -d "${PGDATABASE}"`,
		`export PROBECTL_DATABASE_URL="postgres://${PGHOST}:${PGPORT}/${PGDATABASE}"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("restore Job must restore and migrate the same target: missing %q", want)
		}
	}

	// The release's live DSN must not reach this Job at all: taking it from the
	// secret is what pointed migrate at production.
	if strings.Contains(out, "key: PROBECTL_DATABASE_URL") {
		t.Error("the restore Job must not read the release's live PROBECTL_DATABASE_URL")
	}
	// §7.6: credentials stay in PGUSER/PGPASSWORD, never in a connection URL
	// (which lands in process listings and error text).
	if strings.Contains(out, "${PGPASSWORD}@") || strings.Contains(out, "$PGPASSWORD@") {
		t.Error("the constructed DSN must not embed the password")
	}
	// A default install restores in place: same host and database as the live
	// deployment, so the in-place path is unchanged by the fix.
	inPlace, err := renderHelmAgentListener(t, "templates/restore-job.yaml",
		"--set", "restore.enabled=true",
		"--set", "restore.backupFile=postgres-probectl-20260917T133511Z.dump.pbk",
	)
	if err != nil {
		t.Fatalf("render in-place: %v\n%s", err, inPlace)
	}
	for _, want := range []string{`value: "probectl-postgres"`, `value: "5432"`, `value: "probectl"`} {
		if !strings.Contains(inPlace, want) {
			t.Errorf("the default in-place restore must keep the live target: missing %q", want)
		}
	}
}
