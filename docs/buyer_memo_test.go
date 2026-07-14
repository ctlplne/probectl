// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
		"flat-rate self-hosted license",
		"MSP is consumption-based",
		"operator-run export",
		"probectl banner",
		"Core is licensed under MPL-2.0",
		"pending `make scale-gate TIER=L`, `XL`, `XXL`",
		"regional WAN, DNS, proxy, fence, ClickHouse, and object-store recovery",
		"limitations.md#built-not-yet-served-edges",
	} {
		if !strings.Contains(body, want) && !strings.Contains(normalized, want) {
			t.Fatalf("buyer memo missing %q", want)
		}
	}
}
