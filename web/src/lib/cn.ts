// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { clsx, type ClassValue } from 'clsx'
import { extendTailwindMerge } from 'tailwind-merge'

/**
 * The six semantic type rungs (tailwind.config.js `fontSize`). tailwind-merge
 * ships knowing Tailwind's OWN scale — text-sm, text-lg — and classifies any
 * other `text-<word>` as a TEXT COLOUR. Left unconfigured it therefore reads
 * `text-data` as a colour, puts it in the same group as `text-primary-foreground`,
 * and drops whichever came first: every primary and danger button rendered its
 * label in the inherited body colour, at 2.41:1 in light and 1.53:1 in dark. The
 * token contract could not see it — the tokens were right, the class never
 * reached the element — so it took the rendered accessibility gate to catch it.
 */
const TYPE_RUNGS = ['caption', 'data', 'body', 'title', 'heading', 'display'] as const

const merge = extendTailwindMerge({
  extend: {
    classGroups: {
      'font-size': [{ text: [...TYPE_RUNGS] }],
    },
  },
})

/**
 * cn merges class names and lets a later utility win over an earlier one in the
 * same Tailwind group — so a caller can override a component's default padding
 * or colour by passing `className` without fighting specificity.
 *
 * This is the only place clsx and tailwind-merge are called; components take
 * `className?: string` and pass it through here.
 */
export function cn(...inputs: ClassValue[]): string {
  return merge(clsx(inputs))
}
