// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"testing"
	"time"
)

func TestBMPBoundSettingsRejectInvalidValues(t *testing.T) {
	for _, raw := range []string{"", "0", "-1s", "not-a-duration"} {
		if _, err := parsePositiveBMPDuration("read timeout", raw); err == nil {
			t.Errorf("duration %q was accepted", raw)
		}
	}
	if got, err := parsePositiveBMPDuration("read timeout", "45s"); err != nil || got != 45*time.Second {
		t.Fatalf("valid duration = %s, %v", got, err)
	}
	for _, raw := range []string{"", "0", "-1", "1.5", "not-an-int"} {
		if _, err := parsePositiveBMPInt("max sessions", raw); err == nil {
			t.Errorf("max sessions %q was accepted", raw)
		}
	}
	if got, err := parsePositiveBMPInt("max sessions", "32"); err != nil || got != 32 {
		t.Fatalf("valid max sessions = %d, %v", got, err)
	}
}
