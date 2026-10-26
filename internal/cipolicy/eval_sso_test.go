// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// First-data stores the agent CA encrypted with this key. Switching the same
// evaluation database to SSO must still supply it; a missing key correctly
// stops enrollment-service startup instead of falling back to plaintext.
func TestEvalSSOPreservesEnrollmentEnvelope(t *testing.T) {
	var overlay struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "deploy", "compose", "eval-sso.yml")), &overlay); err != nil {
		t.Fatal(err)
	}
	got := overlay.Services["control"].Environment["PROBECTL_ENVELOPE_KEY"]
	if got != "${PROBECTL_EVAL_ENVELOPE_KEY:-}" {
		t.Fatalf("SSO drops the first-data envelope key: PROBECTL_ENVELOPE_KEY = %q", got)
	}
}
