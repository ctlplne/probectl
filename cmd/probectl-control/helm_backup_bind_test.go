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

// TestHelmBackupsClaimIsBoundOnInstall (DPR-090): when the chart creates the
// backups claim, a one-shot Job mounts it in the same release so it binds
// immediately — on storage classes that bind on first consumer (GKE, EKS,
// AKS, kind) a CronJob is no consumer until it first fires, and
// `helm --wait` fails the release on a Pending claim. The Job is per release
// revision, off with backup.persistence.bind=false, and absent when the
// operator brings their own claim.
func TestHelmBackupsClaimIsBoundOnInstall(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	render := func(extra ...string) string {
		t.Helper()
		out, err := renderHelmAgentListener(t, "templates/backup-cronjobs.yaml", append([]string{
			"--set", "backup.enabled=true",
			"--set", "backup.clickhouse.enabled=false",
			"--set", "backup.objectStore.enabled=false",
		}, extra...)...)
		if err != nil {
			t.Fatalf("render: %v\n%s", err, out)
		}
		return out
	}

	on := render("--set", "backup.persistence.create=true")
	for _, want := range []string{
		"kind: PersistentVolumeClaim",
		"name: probectl-backups-bind-1",
		"claimName: probectl-backups",
		`command: ["/usr/local/bin/app"]`,
		`args: ["version"]`,
		"ttlSecondsAfterFinished: 600",
	} {
		if !strings.Contains(on, want) {
			t.Errorf("chart-created claim must ship a bind Job: missing %q", want)
		}
	}
	if strings.Contains(on, "/bin/sh") {
		t.Error("the bind Job runs on the distroless control image and must not need a shell")
	}
	if off := render("--set", "backup.persistence.create=true", "--set", "backup.persistence.bind=false"); strings.Contains(off, "backups-bind") {
		t.Error("backup.persistence.bind=false must drop the bind Job")
	}
	if own := render(); strings.Contains(own, "backups-bind") || strings.Contains(own, "kind: PersistentVolumeClaim") {
		t.Error("an operator-supplied claim must get neither a chart claim nor a bind Job")
	}
}
