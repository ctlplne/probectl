// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strings"
	"testing"
)

// AUTHZ-24: the provider bootstrap endpoint is public and gated only by the
// static PROBECTL_PROVIDER_BOOTSTRAP_TOKEN, so a short or degenerate token must
// refuse startup (fail closed). An empty token means bootstrap is simply not
// configured and loads clean.
func TestProviderBootstrapTokenEntropyFloor(t *testing.T) {
	// A fixed, high-entropy 64-hex secret (256 bits) — well over the floor.
	const strongToken = testSessionHMACKeyHex
	// Exactly 32 bytes, 16 distinct symbols (128 bits) — the accepted boundary.
	const boundaryToken = "0123456789abcdef0123456789abcdef"

	cases := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"unset is allowed (bootstrap not configured)", "", false},
		{"too short", "boot-secret-0123456789", true}, // 22 bytes < 32
		{"long but degenerate (near-zero entropy)", strings.Repeat("a", 48), true},
		{"32-byte boundary is accepted", boundaryToken, false},
		{"strong random-looking secret is accepted", strongToken, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{
				"PROBECTL_DEPLOYMENT_PROFILE":       "single",
				"PROBECTL_AUTH_MODE":                "session",
				"PROBECTL_PROVIDER_BOOTSTRAP_TOKEN": tc.token,
			}
			_, err := Load(envFunc(env))
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "PROBECTL_PROVIDER_BOOTSTRAP_TOKEN") {
					t.Fatalf("weak bootstrap token %q must fail closed and name the key; got %v", tc.token, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("bootstrap token %q should load clean; got %v", tc.token, err)
			}
		})
	}
}
