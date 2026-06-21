// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readPRDv1(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "probectl-PRD-v1.0.md"),
		filepath.Join("..", "..", "probectl-PRD-v1.0.md"),
	}
	for _, path := range candidates {
		b, err := os.ReadFile(path)
		if err == nil {
			return string(b)
		}
		if !os.IsNotExist(err) {
			t.Fatalf("read %s: %v", path, err)
		}
	}
	t.Fatalf("probectl-PRD-v1.0.md not found in %s or %s", candidates[0], candidates[1])
	return ""
}

// TestPRDOTLPContractMatchesAllSignalImplementation keeps the product contract
// aligned with the shipped OTLP receiver/exporter. The implementation accepts
// and forwards metrics, traces, and logs; the PRD must not keep describing
// traces/logs as an undecided GA item.
func TestPRDOTLPContractMatchesAllSignalImplementation(t *testing.T) {
	prd := readPRDv1(t)

	for _, stale := range []string{
		"traces/logs decision",
		"re-scoped metrics-only claim",
		"metrics-only claim",
		"OTLP traces/logs (if",
	} {
		if strings.Contains(prd, stale) {
			t.Fatalf("probectl-PRD-v1.0.md still contains stale OTLP contract wording %q", stale)
		}
	}
	for _, want := range []string{
		"metrics/traces/logs ingest/export",
		"the three-signal OTLP path is delivered",
		"Remaining GA work is edge-case conformance and hardening, not a traces/logs product decision",
	} {
		if !strings.Contains(prd, want) {
			t.Fatalf("probectl-PRD-v1.0.md missing all-signal OTLP contract wording %q", want)
		}
	}
}

// TestPRDAlertOpsContractMatchesPersistenceImplementation keeps the GA steering
// list from asking for alert silence/ack persistence after the tenant-RLS table,
// store, handler writes, and boot restore path have shipped.
func TestPRDAlertOpsContractMatchesPersistenceImplementation(t *testing.T) {
	prd := readPRDv1(t)

	for _, stale := range []string{
		"currently die with the process",
		"persist them like alert rules",
		"Alert silences/acks persistence",
	} {
		if strings.Contains(prd, stale) {
			t.Fatalf("probectl-PRD-v1.0.md still contains stale alert-ops contract wording %q", stale)
		}
	}
	for _, want := range []string{
		"Alert operation UX/evidence polish",
		"silences/acks persistence is delivered",
		"migrations/0043_alert_ops.sql",
		"internal/store/alertops.go",
		"internal/control/alertsactive.go",
		"internal/control/alerteval.go",
		"not the persistence mechanism itself",
	} {
		if !strings.Contains(prd, want) {
			t.Fatalf("probectl-PRD-v1.0.md missing alert-ops contract wording %q", want)
		}
	}
}
