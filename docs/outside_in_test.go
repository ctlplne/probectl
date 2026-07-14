// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"os"
	"strings"
	"testing"
)

func TestOwnedOutsideInGuidePackagesReplacementMotion(t *testing.T) {
	b, err := os.ReadFile("outside-in.md")
	if err != nil {
		t.Fatalf("read outside-in.md: %v", err)
	}
	body := string(b)
	normalized := strings.Join(strings.Fields(body), " ")

	for _, want := range []string{
		"owned-vantage",
		"site",
		"region",
		"coverage map",
		"probe pack",
		"MSP resale",
		"consumption basis",
		"operator-run export",
		"probectl banner",
		"does not operate a global probe fleet",
		"no-phone-home",
		"no vendor-managed shared probe pool",
		"ThousandEyes-style",
		"GET /v1/outages",
		"POST /v1/a2a/mesh",
		"PROBECTL_OUTAGE_FEEDS_ENABLED",
	} {
		if !strings.Contains(body, want) && !strings.Contains(normalized, want) {
			t.Fatalf("outside-in guide missing %q", want)
		}
	}
}
