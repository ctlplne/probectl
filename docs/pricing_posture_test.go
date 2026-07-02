// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPricingDocsPublishFixedLicensePosture(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(b)
	}

	pricing := read("pricing.md")
	readme := read(filepath.Join("..", "README.md"))
	editions := read("editions.md")
	metering := read("metering.md")
	combined := pricing + "\n" + readme + "\n" + editions + "\n" + metering
	normalized := strings.Join(strings.Fields(combined), " ")

	for _, stale := range []string{
		"**Quote-based**",
		"per-host billing",
		"per-flow billing",
		"per-GB billing",
	} {
		if strings.Contains(combined, stale) {
			t.Fatalf("pricing posture must not reintroduce consumption/quote framing %q", stale)
		}
	}

	for _, want := range []string{
		"Fixed annual license by support/governance band",
		"Fixed annual tenant-band license",
		"Enterprise-Support",
		"Enterprise-Governance",
		"Enterprise-Regulated",
		"Provider-25",
		"Provider-100",
		"Provider-500",
		"Provider-Unlimited",
		"not probectl billing units",
		"showback",
		"capacity planning",
		"tenant_band",
		"fixed-license",
		"per-host, per-flow, or per-GB tolls",
	} {
		if !strings.Contains(combined, want) && !strings.Contains(normalized, want) {
			t.Fatalf("pricing posture missing %q", want)
		}
	}
}
