// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"os"
	"strings"
	"testing"
)

func TestScaleGateDocumentsReferenceTargetSplit(t *testing.T) {
	b, err := os.ReadFile("scale-gate.md")
	if err != nil {
		t.Fatalf("read scale-gate.md: %v", err)
	}
	doc := string(b)
	normalized := strings.Join(strings.Fields(doc), " ")

	for _, want := range []string{
		"PERF-REF-M1MAX",
		"Apple M1 Max MacBook Pro",
		"64 GB RAM",
		"single-host performance reference target",
		"PERF-REF-CLUSTER-L",
		"PERF-REF-CLUSTER-XL",
		"PERF-REF-CLUSTER-XXL",
		"cannot promote L/XL/XXL SLOs",
		"not runnable on a single M1 Max/laptop",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("scale-gate.md must keep the PERF reference target split: missing %q", want)
		}
	}
}
