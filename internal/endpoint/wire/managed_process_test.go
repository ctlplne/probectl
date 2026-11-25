// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package wire

import (
	"strings"
	"testing"
)

func TestManagedProcessMetadataValidatesPlatformIdentityAndSequence(t *testing.T) {
	const run = "12345678-1234-42ab-8234-1234567890ab"
	mac := "cdhash:" + strings.Repeat("a", 40)
	windows := "sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct {
		payload string
		valid   bool
	}{
		{"darwin/arm64|" + run + "|0|", true},
		{"windows/amd64|" + run + "|7|" + windows, true},
		{"darwin/amd64|" + run + "|7|" + mac, true},
		{"windows/arm64|" + run + "|9|", true},
		{"windows/amd64|" + run + "|7|" + mac, false},
		{"darwin/amd64|" + run + "|0|" + mac, false},
		{"darwin/arm64|" + strings.ToUpper(run) + "|0|", false},
		{"darwin/arm64|" + run + "|+1|", false},
		{"windows/arm64|" + run + "|-1|", false},
		{"windows/arm64|" + run + "|9223372036854775808|", false},
		{"darwin/arm64|" + run + "|1|" + strings.Repeat("x", 161), false},
	} {
		got, err := ParseManagedProcess(tc.payload)
		if tc.valid != (err == nil) {
			t.Fatalf("unexpected parse of %q: %v", tc.payload, err)
		}
		if tc.valid && got.HeaderValue() != tc.payload {
			t.Fatalf("process round trip changed %q", tc.payload)
		}
	}
}
