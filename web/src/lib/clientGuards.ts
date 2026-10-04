// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Client-side guards against hostile/large agent-reported data (WEB-24). These
// values arrive from telemetry an agent produced, so the UI must bound them
// before allocating or formatting — a forged browser.step_count or an invalid
// timestamp must never freeze the tab or throw.

// maxBrowserSteps caps how many per-step rows a browser transaction result may
// render. Real transactions have well under this; a forged count (e.g. 1e9)
// would otherwise drive an unbounded Array.from allocation.
export const maxBrowserSteps = 200

// browserStepCount is the bounded number of step rows to render for a browser
// result, given the agent-declared count and the highest step index seen in the
// metrics. Negative/NaN collapse to 0; anything huge is clamped.
export function browserStepCount(declared: number, metricStepCount: number): number {
  const base = Math.max(
    Number.isFinite(declared) ? declared : 0,
    Number.isFinite(metricStepCount) ? metricStepCount : 0,
  )
  if (base <= 0) {
    return 0
  }
  return Math.min(maxBrowserSteps, Math.floor(base))
}

// safeISOString formats a timestamp as ISO-8601, or returns a readable fallback
// (the original string, or "—") when the value is not a valid date — Date's
// toISOString() throws a RangeError on an invalid date, which would crash a
// panel rendering agent-supplied timestamps.
export function safeISOString(value: string | number | Date): string {
  const d = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(d.getTime())) {
    return typeof value === 'string' && value !== '' ? value : '—'
  }
  return d.toISOString()
}

// shellSingleQuote wraps a value in POSIX single quotes so a copy-pasteable
// command stays safe even when the value (e.g. an IdP-supplied email) contains
// shell metacharacters (WEB-25). An embedded single quote is closed, escaped as
// a literal, and reopened ('\'').
export function shellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}
