// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"os"
	"strings"
	"testing"
)

func TestBuyerMemoPackagesAdoptionDecision(t *testing.T) {
	b, err := os.ReadFile("buyer-memo.md")
	if err != nil {
		t.Fatalf("read buyer-memo.md: %v", err)
	}
	body := string(b)
	normalized := strings.Join(strings.Fields(body), " ")

	for _, want := range []string{
		"see everything, send nothing",
		"custody",
		"pricing",
		"scale",
		"limitations",
		"Kentik",
		"ThousandEyes",
		"Datadog",
		"MSP",
		"fixed annual tenant band",
		"not probectl billing units",
		"source-available, not open source yet",
		"pending `make scale-gate TIER=L`, `XL`, `XXL`",
		"regional WAN, DNS, proxy, fence, ClickHouse, and object-store recovery",
		"limitations.md#built-not-yet-served-edges",
	} {
		if !strings.Contains(body, want) && !strings.Contains(normalized, want) {
			t.Fatalf("buyer memo missing %q", want)
		}
	}
}
