// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

/**
 * The one control shell every field and select shares, so a text input and a
 * native select are the same height, radius and focus treatment and line up in a
 * row. A native control has an intrinsic minimum width in several engines, so
 * The floor belongs on the CONTROL, not the shell: flooring the shell at the
 * target size still left the select inside it 20px wide once the shell's own
 * padding and gap were taken out. With min-w-touch on the input the shell's
 * default flex min-width:auto keeps it at content size, so the thing a pointer
 * has to hit is the thing that cannot shrink below the WCAG 2.5.8 minimum.
 *
 * These live apart from the components because a file that exports both a
 * component and a constant breaks fast refresh (react-refresh/only-export-components).
 */
export const controlShell = [
  'flex h-control w-full items-center gap-2 rounded-control border bg-card px-3',
  'text-data text-foreground transition-colors duration-fast ease-standard',
  'focus-within:ring-2 focus-within:ring-focus focus-within:ring-offset-2',
  'focus-within:ring-offset-background',
].join(' ')

export const controlInput =
  'h-full w-full min-w-touch flex-1 border-0 bg-transparent p-0 text-data text-foreground outline-none placeholder:text-muted-foreground'

export const fieldLabel = 'text-caption font-medium text-muted-foreground'
