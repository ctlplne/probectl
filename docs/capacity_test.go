// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/perf"
)

func TestCapacityModelDocumentsScaleProfiles(t *testing.T) {
	b, err := os.ReadFile("capacity.md")
	if err != nil {
		t.Fatalf("read capacity.md: %v", err)
	}
	doc := string(b)

	for _, profile := range perf.Profiles(1) {
		hosts := profile.Ingest.Tenants * profile.Ingest.AgentsPerTenant
		for _, want := range []string{
			fmt.Sprintf("| %s |", profile.Tier),
			fmt.Sprintf("| %s | %d | %s |", profile.Tier, profile.Ingest.Tenants, commaInt(hosts)),
			fmt.Sprintf("%s results/s", commaInt(int(profile.SLO.MinIngestThroughput))),
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("capacity.md missing profile %s evidence %q", profile.Tier, want)
			}
		}
	}

	for _, want := range []string{
		"Pending `make scale-fullstack TIER=L` receipt",
		"Pending `make scale-fullstack TIER=XL` receipt",
		"Do not sell or capacity-plan L/XL from the provisional numbers alone",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("capacity.md must keep L/XL receipt caveat %q", want)
		}
	}
}

func TestCapacityModelDocumentsRowsRetentionAndSplits(t *testing.T) {
	b, err := os.ReadFile("capacity.md")
	if err != nil {
		t.Fatalf("read capacity.md: %v", err)
	}
	doc := string(b)

	for _, want := range []string{
		"| Synthetic result | 1,536 B/result |",
		"| Flow/eBPF record | 512 B/row |",
		"| Control/event row | 2,048 B/event |",
		"| Audit row | 4,096 B/event |",
		"GiB = rows_per_second * 86,400 * retention_days * bytes_per_row * replicas / 1,073,741,824",
		"Scale-Out Triggers",
		"Shard-Split Rules",
		"tenant scope first, then RBAC",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("capacity.md missing required capacity-model text %q", want)
		}
	}
}

func commaInt(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	first := len(s) % 3
	if first == 0 {
		first = 3
	}
	out = append(out, s[:first]...)
	for i := first; i < len(s); i += 3 {
		out = append(out, ',')
		out = append(out, s[i:i+3]...)
	}
	return string(out)
}
