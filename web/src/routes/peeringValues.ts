// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { PeeringRateEstimate } from '../api/sdk.gen'

export function peeringGbps(rate: PeeringRateEstimate): string {
  try {
    const numerator = BigInt(rate.bits_per_second_numerator)
    const denominator = BigInt(rate.bits_per_second_denominator) * 1_000_000_000n
    if (numerator < 0n || denominator <= 0n) return 'Unavailable'
    const scaled = (numerator * 1000n) / denominator
    if (numerator > 0n && scaled === 0n) return '<0.001 Gbps'
    return `${scaled / 1000n}.${String(scaled % 1000n).padStart(3, '0')} Gbps`
  } catch {
    return 'Unavailable'
  }
}
