// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"testing"
	"time"
)

// DPR-177: the intermediate that signs every agent SVID lives one year, the
// root that could replace it is deliberately offline, and nothing watched the
// date. The warning has to arrive while there is still time to find that key.
func TestIssuingRenewalPointLeavesTimeToFindTheOfflineRootKey(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(1, 0, 0) // the shipped one-year intermediate

	for _, tc := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"the day it was issued", notBefore, false},
		{"half way through", notBefore.Add(182 * 24 * time.Hour), false},
		{"a day before three quarters", notBefore.Add(272 * 24 * time.Hour), false},
		{"past three quarters", notBefore.Add(275 * 24 * time.Hour), true},
		{"the day it expires", notAfter, true},
		{"after it expired", notAfter.Add(24 * time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pastIssuingRenewalPoint(notBefore, notAfter, tc.now); got != tc.want {
				t.Fatalf("pastIssuingRenewalPoint = %v, want %v", got, tc.want)
			}
		})
	}

	// The warning must arrive with roughly three months in hand, not three days.
	warnFrom := notBefore.Add(time.Duration(0.75 * float64(notAfter.Sub(notBefore))))
	if left := notAfter.Sub(warnFrom); left < 80*24*time.Hour {
		t.Fatalf("only %s of warning before the CA expires — too late to retrieve an offline key", left)
	}

	// A zero or inverted window never warns rather than crying wolf on a CA
	// whose dates could not be read.
	if pastIssuingRenewalPoint(notAfter, notBefore, notBefore) {
		t.Fatal("an inverted window must not raise the renewal warning")
	}
	if pastIssuingRenewalPoint(time.Time{}, time.Time{}, notBefore) {
		t.Fatal("a zero window must not raise the renewal warning")
	}
}
