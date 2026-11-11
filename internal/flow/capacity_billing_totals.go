// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"math/big"
	"time"
)

type capacityBillingTotals struct {
	in, out               []*big.Rat
	missingIn, missingOut []bool
}

// Called only after whole-member/grid arithmetic admission. Circuit sums are
// shared by percentile and forecast: both operate on the same complete common
// grid and retain unknown directions instead of filling missing members.
func sumCapacityBillingMembers(ctx context.Context, window capacityBillingWindow, members []capacityBillingMember, count int) (capacityBillingTotals, error) {
	type memberKey struct{ context, router, iface string }
	seen := make(map[memberKey]struct{}, len(members))
	in, out := make([]*big.Rat, count), make([]*big.Rat, count)
	missingIn, missingOut := make([]bool, count), make([]bool, count)
	for i := range count {
		if err := ctx.Err(); err != nil {
			return capacityBillingTotals{}, err
		}
		in[i], out[i] = new(big.Rat), new(big.Rat)
	}
	for _, member := range members {
		key := memberKey{member.context, member.router, member.iface}
		if _, duplicate := seen[key]; duplicate {
			return capacityBillingTotals{}, errCapacityCounterInput
		}
		seen[key] = struct{}{}
		for i, sample := range member.samples {
			if err := ctx.Err(); err != nil {
				return capacityBillingTotals{}, err
			}
			from := window.from.Add(time.Duration(i) * 5 * time.Minute)
			to := from.Add(5 * time.Minute)
			if to.After(window.to) {
				to = window.to
			}
			for direction, rate := range []capacityCounterRate{sample.in, sample.out} {
				value, observed, err := capacityBillingBytes(ctx, rate, from, to)
				if err != nil {
					return capacityBillingTotals{}, err
				}
				switch direction {
				case 0:
					if observed {
						in[i].Add(in[i], value)
					} else {
						missingIn[i] = true
					}
				case 1:
					if observed {
						out[i].Add(out[i], value)
					} else {
						missingOut[i] = true
					}
				}
			}
		}
	}
	return capacityBillingTotals{in: in, out: out, missingIn: missingIn, missingOut: missingOut}, nil
}
