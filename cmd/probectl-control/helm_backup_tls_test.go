// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestBackupAndRestoreReachTheDatastoresOverTLS (DPR-108): the chart's own
// Jobs used to connect to Postgres with libpq's default sslmode (prefer — it
// accepts plaintext and never verifies the server) and to ClickHouse on the
// plaintext native port 9000, while the control plane next to them connects
// verify-full. Those Jobs carry the entire tenant database and all tenant
// telemetry, and on a hardened ClickHouse — which does not listen on 9000 at
// all — the backup simply could not run. §7.12: datastore TLS in transit,
// outbound validates certs.
func TestBackupAndRestoreReachTheDatastoresOverTLS(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	backup := func(extra ...string) string {
		t.Helper()
		out, err := renderHelmAgentListener(t, "templates/backup-cronjobs.yaml", append([]string{
			"--set", "backup.enabled=true",
			"--set", "backup.objectStore.enabled=false",
			"--set", "backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target",
		}, extra...)...)
		if err != nil {
			t.Fatalf("render backup: %v\n%s", err, out)
		}
		return out
	}
	restore := func(extra ...string) string {
		t.Helper()
		out, err := renderHelmAgentListener(t, "templates/restore-job.yaml", append([]string{
			"--set", "restore.enabled=true",
			"--set", "restore.backupFile=postgres-probectl-20260917T133511Z.dump.pbk",
		}, extra...)...)
		if err != nil {
			t.Fatalf("render restore: %v\n%s", err, out)
		}
		return out
	}

	// Without a deployment trust bundle there is no CA to verify against, so
	// the strongest available posture is an encrypted session.
	for name, out := range map[string]string{"backup": backup(), "restore": restore()} {
		if !strings.Contains(out, `- name: PGSSLMODE`) || !strings.Contains(out, `value: "require"`) {
			t.Errorf("%s Job must require TLS to Postgres by default", name)
		}
		if strings.Contains(out, "PGSSLROOTCERT") {
			t.Errorf("%s Job must not name a CA file it does not mount", name)
		}
	}

	// With one, the Jobs verify the server exactly as the control plane does,
	// and the bundle is mounted so the driver can read it — naming a CA file
	// that is not mounted is what broke the restore Job (DPR-107).
	trust := []string{"--set", "control.trustBundle.existingConfigMap=probectl-trust"}
	for name, out := range map[string]string{"backup": backup(trust...), "restore": restore(trust...)} {
		for _, want := range []string{
			`value: "verify-full"`,
			`- name: PGSSLROOTCERT`,
			`value: "/etc/probectl/trust/ca-bundle.crt"`,
			`name: trust-bundle`,
			`mountPath: "/etc/probectl/trust"`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s Job must verify Postgres against the deployment trust bundle: missing %q", name, want)
			}
		}
	}

	// An operator override wins over both defaults.
	if out := backup("--set", "backup.postgres.sslmode=verify-ca"); !strings.Contains(out, `value: "verify-ca"`) {
		t.Error("backup.postgres.sslmode must override the resolved default")
	}

	// ClickHouse: native TLS port with a verified certificate. The client takes
	// TLS settings from a config file, so one must be mounted.
	chOn := backup(trust...)
	for _, want := range []string{
		"--port 9440",
		"--secure --config-file=/etc/probectl/ch/client.xml",
		"name: ch-client",
	} {
		if !strings.Contains(chOn, want) {
			t.Errorf("ClickHouse backup must use the native TLS port: missing %q", want)
		}
	}
	chOff := backup("--set", "backup.clickhouse.secure=false", "--set", "backup.clickhouse.port=null")
	if strings.Contains(chOff, "--secure") || !strings.Contains(chOff, "--port 9000") {
		t.Error("an explicitly plaintext ClickHouse must fall back to 9000 without --secure")
	}
	// `helm upgrade --reuse-values` from a release that predates this keeps the
	// old values, which have no secure flag at all (DPR-090). Absent must mean
	// on, or the upgrade quietly keeps streaming telemetry in the clear.
	reused := backup("--set", "backup.clickhouse.secure=null", "--set", "backup.clickhouse.port=null")
	if !strings.Contains(reused, "--secure") || !strings.Contains(reused, "--port 9440") {
		t.Error("an absent backup.clickhouse.secure (reused values) must still mean TLS")
	}

	cfg, err := renderHelmAgentListener(t, "templates/ch-client-config.yaml",
		"--set", "backup.enabled=true",
		"--set", "backup.objectStore.enabled=false",
		"--set", "backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target",
		"--set", "control.trustBundle.existingConfigMap=probectl-trust",
	)
	if err != nil {
		t.Fatalf("render ch client config: %v\n%s", err, cfg)
	}
	for _, want := range []string{
		"<secure>1</secure>",
		"<caConfig>/etc/probectl/trust/ca-bundle.crt</caConfig>",
		"<verificationMode>strict</verificationMode>",
		"RejectCertificateHandler",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("the ClickHouse client config must verify the server: missing %q", want)
		}
	}
}
