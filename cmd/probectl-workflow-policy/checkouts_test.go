// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"strings"
	"testing"
)

// TestRunCheckoutsReportsSemanticPersistCredentials closes the SUP-04 adversarial
// gap: the persist-credentials value must be read as a REAL YAML mapping value,
// so a commented-out line (the input is actually unset; GitHub defaults to
// persisting the credential) reports "unset" rather than being fooled by the
// textual string, and quoted / flow shapes are honored.
func TestRunCheckoutsReportsSemanticPersistCredentials(t *testing.T) {
	path := writeWorkflow(t, `
jobs:
  good:
    steps:
      - uses: actions/checkout@`+zeroActionSHA+`
        with:
          persist-credentials: false
  commented:
    steps:
      - uses: actions/checkout@`+zeroActionSHA+`
        with:
          fetch-depth: 0
          # persist-credentials: false
  nowith:
    steps:
      - uses: actions/checkout@`+zeroActionSHA+`
  explicit-true:
    steps:
      - uses: actions/checkout@`+zeroActionSHA+`
        with:
          persist-credentials: true
  quoted-false:
    steps:
      - uses: actions/checkout@`+zeroActionSHA+`
        with:
          persist-credentials: "false"
  flow:
    steps:
      - {uses: "actions/checkout@`+zeroActionSHA+`", with: {persist-credentials: false}}
  not-a-checkout:
    steps:
      - uses: actions/setup-go@`+zeroActionSHA+`
`)
	var stdout, stderr strings.Builder
	if code := run([]string{"checkouts", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(checkouts) = %d, stderr = %q", code, stderr.String())
	}
	// Collect job -> persist from the TSV output.
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			t.Fatalf("malformed TSV line %q", line)
		}
		got[f[1]] = f[3]
	}
	want := map[string]string{
		"good":          "false",
		"commented":     "unset", // the comment must NOT read as false
		"nowith":        "unset",
		"explicit-true": "true",
		"quoted-false":  "false",
		"flow":          "false",
	}
	for job, exp := range want {
		if got[job] != exp {
			t.Errorf("job %s: persist-credentials = %q, want %q (full output:\n%s)", job, got[job], exp, stdout.String())
		}
	}
	if _, ok := got["not-a-checkout"]; ok {
		t.Errorf("setup-go step must not be reported as a checkout: %q", stdout.String())
	}
}
