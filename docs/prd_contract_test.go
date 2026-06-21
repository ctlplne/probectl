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

// TestPRDEBPFContractMatchesIPv6Implementation keeps the GA steering list from
// asking for IPv6 L4 capture after the BPF program, userspace decoder, and
// live-kernel smoke already cover it. Go crypto/tls remains an explicit L7
// strategy follow-up, not a hidden L4 IPv6 gap.
func TestPRDEBPFContractMatchesIPv6Implementation(t *testing.T) {
	prd := readPRDv1(t)

	for _, stale := range []string{
		"measured IPv4-only blind spot",
		"IPv6 capture (blind spot currently *measured*",
	} {
		if strings.Contains(prd, stale) {
			t.Fatalf("probectl-PRD-v1.0.md still contains stale eBPF contract wording %q", stale)
		}
	}
	for _, want := range []string{
		"IPv4/IPv6 CO-RE L4 flow capture",
		"unsupported non-IPv4/IPv6 family counter",
		"IPv6 L4 capture is delivered",
		"internal/ebpf/bpf/l4flow.bpf.c",
		"internal/ebpf/l4event.go",
		"internal/ebpf/live_smoke_ebpf_test.go",
		"Remaining GA steering is the Go-TLS L7 strategy decision",
	} {
		if !strings.Contains(prd, want) {
			t.Fatalf("probectl-PRD-v1.0.md missing eBPF IPv6/Go-TLS contract wording %q", want)
		}
	}
}

// TestPRDFleetRolloutContractMatchesCLISurface keeps F28 from drifting back to
// "operator surface pending" now that the probectl rollout CLI group and
// /v1/rollouts API make the rollout engine operator-usable.
func TestPRDFleetRolloutContractMatchesCLISurface(t *testing.T) {
	prd := readPRDv1(t)

	for _, stale := range []string{
		"operator console wiring ⏳",
		"wire the delivered rollout engine",
	} {
		if strings.Contains(prd, stale) {
			t.Fatalf("probectl-PRD-v1.0.md still contains stale fleet-rollout wording %q", stale)
		}
	}
	for _, want := range []string{
		"operator CLI/API surface ✅",
		"`probectl rollout`",
		"`/v1/rollouts`",
		"`docs/ops/fleet-rollout.md`",
		"Fleet rollout polish",
		"Remaining GA work is UX/evidence polish around scripted fleet workflows",
		"not the missing operator surface itself",
	} {
		if !strings.Contains(prd, want) {
			t.Fatalf("probectl-PRD-v1.0.md missing fleet-rollout contract wording %q", want)
		}
	}
}
