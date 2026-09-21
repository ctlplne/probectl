// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPricingDocsPublishEnterpriseAndMSPPosture(t *testing.T) {
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
		"Fixed annual tenant-band license",
		"Provider-25",
		"white_label",
	} {
		if strings.Contains(combined, stale) {
			t.Fatalf("pricing posture contains retired packaging %q", stale)
		}
	}

	for _, want := range []string{
		"Flat-rate self-hosted license",
		"Consumption-based self-hosted resale license",
		"strict superset",
		"probectl banner",
		"operator-run export",
		"never phones home",
		"showback",
		"capacity planning",
		"tenant_band",
		"results_ingested",
		"ingest_bytes",
		"pricing_model",
	} {
		if !strings.Contains(combined, want) && !strings.Contains(normalized, want) {
			t.Fatalf("pricing posture missing %q", want)
		}
	}
}
