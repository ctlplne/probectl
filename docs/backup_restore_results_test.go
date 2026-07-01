// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"encoding/csv"
	"os"
	"strconv"
	"testing"
)

func TestBackupRestoreTranscriptHasNamedProfilesAndRPORTO(t *testing.T) {
	f, err := os.Open("ops/backup-restore-results.csv")
	if err != nil {
		t.Fatalf("open backup restore transcript: %v", err)
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read backup restore transcript: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("backup restore transcript must contain at least one measured row")
	}
	header := map[string]int{}
	for i, name := range rows[0] {
		header[name] = i
	}
	for _, col := range []string{
		"run_at",
		"git_sha",
		"profile",
		"pg_rows",
		"ch_rows",
		"artifact_bytes",
		"backup_secs",
		"restore_secs",
		"rpo_seconds",
		"rto_budget_seconds",
	} {
		if _, ok := header[col]; !ok {
			t.Fatalf("backup restore transcript missing column %q", col)
		}
	}

	required := map[string]bool{"small": false, "medium": false, "large": false}
	for _, row := range rows[1:] {
		profile := row[header["profile"]]
		if _, ok := required[profile]; !ok {
			continue
		}
		required[profile] = true
		if row[header["run_at"]] == "" || row[header["git_sha"]] == "" {
			t.Fatalf("profile %s missing run timestamp or git sha", profile)
		}
		for _, col := range []string{"pg_rows", "ch_rows", "artifact_bytes", "rpo_seconds", "rto_budget_seconds"} {
			if parsePositive(t, profile, col, row[header[col]]) <= 0 {
				t.Fatalf("profile %s column %s must be positive", profile, col)
			}
		}
		for _, col := range []string{"backup_secs", "restore_secs"} {
			if parseNonNegative(t, profile, col, row[header[col]]) < 0 {
				t.Fatalf("profile %s column %s must be non-negative", profile, col)
			}
		}
	}
	for profile, seen := range required {
		if !seen {
			t.Fatalf("backup restore transcript missing measured %s profile", profile)
		}
	}
}

func parsePositive(t *testing.T, profile, col, value string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatalf("profile %s column %s is not an integer: %q", profile, col, value)
	}
	return n
}

func parseNonNegative(t *testing.T, profile, col, value string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatalf("profile %s column %s is not an integer: %q", profile, col, value)
	}
	return n
}
