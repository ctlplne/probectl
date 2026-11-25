// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestAutotaskAdjustmentValidatesSignedDelta(t *testing.T) {
	key := autotaskAdjustmentKey{CompanyID: 7, ContractID: 9, ContractServiceID: 12}
	for _, test := range []struct {
		name               string
		old, desired, want int64
		valid              bool
	}{
		{"increase", 0, math.MaxInt32, math.MaxInt32, true},
		{"decrease to zero", math.MaxInt32, 0, -math.MaxInt32, true},
		{"no change", 4, 4, 0, false},
		{"overflow", 0, math.MaxInt64, 0, false},
		{"negative count", -1, 4, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := autotaskAdjustment{Key: key, EffectiveAt: time.Now(), Previous: test.old, Desired: test.desired}
			got, err := a.delta()
			if test.valid && (err != nil || got != test.want) || !test.valid && !errors.Is(err, errInvalidAutotaskAdjustment) {
				t.Fatalf("delta = %d, %v, want %d (valid %t)", got, err, test.want, test.valid)
			}
		})
	}
}
