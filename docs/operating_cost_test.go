// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/perf"
)

func TestOperatingCostModelDocumentsTierWorksheet(t *testing.T) {
	b, err := os.ReadFile("operating-cost.md")
	if err != nil {
		t.Fatalf("read operating-cost.md: %v", err)
	}
	doc := string(b)

	for _, profile := range perf.Profiles(1) {
		hosts := profile.Ingest.Tenants * profile.Ingest.AgentsPerTenant
		want := fmt.Sprintf("| %s |", profile.Tier)
		if !strings.Contains(doc, want) {
			t.Errorf("operating-cost.md missing tier row %q", want)
		}
		if !strings.Contains(doc, commaInt(hosts)) {
			t.Errorf("operating-cost.md missing host count %s for tier %s", commaInt(hosts), profile.Tier)
		}
	}

	for _, want := range []string{
		"Pending `make scale-fullstack TIER=L` receipt",
		"Pending `make scale-fullstack TIER=XL` receipt",
		"cost claim moves with the performance claim",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("operating-cost.md must tie costs to capacity receipts: missing %q", want)
		}
	}
}

func TestOperatingCostModelDocumentsCostFormulas(t *testing.T) {
	b, err := os.ReadFile("operating-cost.md")
	if err != nil {
		t.Fatalf("read operating-cost.md: %v", err)
	}
	doc := string(b)

	for _, want := range []string{
		"compute_month = vcpu * vcpu_month + ram_gib * ram_gib_month",
		"retention_day_delta = rows_per_second * 86,400 * bytes_per_row * replicas * storage_gib_month / 1,073,741,824",
		"query_vcpu = query_per_second * cpu_seconds_per_query / target_cpu_utilization",
		"rca_remote_usd = calls * ((input_tokens / 1,000,000) * input_price + (output_tokens / 1,000,000) * output_price)",
		"docs/capacity.md",
		"docs/scale-gate.md",
		"ai-egress.md",
		"Do not solve cost by weakening tenant isolation",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("operating-cost.md missing required formula/cross-link %q", want)
		}
	}
}
