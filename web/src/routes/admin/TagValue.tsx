// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useI18n } from '../../i18n/useI18n'
import { formatNumber } from '../../i18n/number'

/** Keep dense tables usable while making the complete stored value available
 * to readers, including those without permission to open an edit form. */
export function TagValue({ value }: { value: string }) {
  const { locale } = useI18n()
  const points = Array.from(value)
  if (points.length <= 256) return <span className="break-all">{value}</span>
  return (
    <details className="min-w-0">
      <summary className="min-h-touch min-w-touch cursor-pointer break-all rounded-control focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-focus">
        {points.slice(0, 80).join('')}… ({formatNumber(points.length, locale)} characters)
      </summary>
      <pre className="whitespace-pre-wrap break-all font-mono text-data" data-tag-value-full>
        {value}
      </pre>
    </details>
  )
}
