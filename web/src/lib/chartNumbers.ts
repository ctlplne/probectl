// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

/** Coordinates are approximate geometry. Exact data/readouts never pass
 * through this compact, locale-independent axis formatter. */
export function formatPlotCoordinate(value: number): string {
  if (!Number.isFinite(value)) return '—'
  if (value === 0) return '0'
  const magnitude = Math.abs(value)
  if (magnitude >= 10000 || magnitude < 0.001) return value.toExponential(2)
  return String(Number(value.toPrecision(4)))
}
