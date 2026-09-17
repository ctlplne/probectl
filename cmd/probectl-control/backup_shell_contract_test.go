// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBackupAndRestoreJobShellsFailClosed (DPR-091): every shell the backup
// CronJobs and restore Jobs run — the chart's and the standalone manifests —
// must be bash with errexit, nounset and pipefail. Under `sh -ec` a refused
// pg_dump piped into backup-seal still exited 0: the CronJob sealed nothing
// and reported a successful backup.
func TestBackupAndRestoreJobShellsFailClosed(t *testing.T) {
	const want = `command: ["/bin/bash", "-euo", "pipefail", "-c"]`
	for _, f := range []string{
		"deploy/helm/probectl/templates/backup-cronjobs.yaml",
		"deploy/helm/probectl/templates/restore-job.yaml",
		"deploy/backup/k8s-cronjob-postgres.yaml",
		"deploy/backup/k8s-cronjob-clickhouse.yaml",
	} {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		shells := 0
		for i, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "command:") || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, "/bin/sh") || strings.Contains(trimmed, `"sh"`) {
				t.Errorf("%s:%d runs a job script under sh (no pipefail): %s", f, i+1, trimmed)
			}
			if strings.Contains(trimmed, "bash") {
				shells++
				if trimmed != want {
					t.Errorf("%s:%d job shell must be exactly %s, got %s", f, i+1, want, trimmed)
				}
			}
		}
		if shells == 0 {
			t.Errorf("%s: no bash job script found — the contract no longer covers it", f)
		}
	}
}
