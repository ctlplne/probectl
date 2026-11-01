// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

function isIPLiteral(value: string): boolean {
  if (value.length > 64) return false
  if (/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) <= 255)
  }
  if (!value.includes(':') || !/^[0-9a-fA-F:.]+$/.test(value)) return false
  try {
    // The URL parser validates bracketed IPv6 locally; no request is made.
    return new URL(`http://[${value}]/`).hostname !== ''
  } catch {
    return false
  }
}

// Only values already present in an authorized row or cited signal become
// options. The 100-option limit bounds a large Explorer result's UI work.
export function observedIPs(rows: ReadonlyArray<Record<string, unknown>>, limit = 100): string[] {
  const found = new Set<string>()
  for (const row of rows) {
    for (const value of Object.values(row)) {
      if (typeof value !== 'string' || !isIPLiteral(value)) continue
      found.add(value)
      if (found.size >= limit) return [...found]
    }
  }
  return [...found]
}
