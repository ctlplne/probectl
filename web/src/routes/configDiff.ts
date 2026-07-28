// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

export const MAX_CONFIG_DIFF_CHARACTERS = 256 * 1024
export const MAX_CONFIG_DIFF_LINES = 2_000
export const MAX_CONFIG_DIFF_EDIT_DISTANCE = 400
export const MAX_RENDERED_CONFIG_DIFF_ROWS = 400

export interface ConfigVersionForComparison {
  id: string
  device: string
  version: number
  content_hash: string
  previous_hash?: string
  content?: string
  drifted: boolean
}

export type ConfigDiffStatus = 'unchanged' | 'added' | 'removed' | 'omitted'

export interface ConfigDiffRow {
  status: ConfigDiffStatus
  text: string
  beforeLine?: number
  afterLine?: number
  omitted?: number
}

export interface ConfigDiffResult {
  rows: ConfigDiffRow[]
  added: number
  removed: number
  unchanged: number
  bounded: boolean
  contextFolded: boolean
}

interface BoundedLines {
  lines: string[]
  bounded: boolean
}

/**
 * Returns the exact archived predecessor for a version. The content hash is
 * authoritative; version only resolves repeated snapshots with identical
 * content by choosing the nearest older record.
 */
export function findPreviousConfig<T extends ConfigVersionForComparison>(
  configs: readonly T[],
  current: T,
): T | undefined {
  if (
    !current.drifted ||
    current.previous_hash === undefined ||
    typeof current.content !== 'string'
  ) {
    return undefined
  }
  return configs
    .filter(
      (candidate) =>
        candidate.id !== current.id &&
        candidate.device === current.device &&
        candidate.version < current.version &&
        candidate.content_hash === current.previous_hash &&
        typeof candidate.content === 'string',
    )
    .sort((left, right) => right.version - left.version || left.id.localeCompare(right.id))[0]
}

export function createConfigDiff(before: string, after: string): ConfigDiffResult {
  const oldInput = boundedLines(before)
  const newInput = boundedLines(after)
  const calculated = myersDiff(oldInput.lines, newInput.lines)
  const raw =
    calculated ??
    oldInput.lines
      .map<ConfigDiffRow>((text, index) => ({
        status: 'removed',
        text,
        beforeLine: index + 1,
      }))
      .concat(
        newInput.lines.map<ConfigDiffRow>((text, index) => ({
          status: 'added',
          text,
          afterLine: index + 1,
        })),
      )

  const added = raw.filter((row) => row.status === 'added').length
  const removed = raw.filter((row) => row.status === 'removed').length
  const unchanged = raw.filter((row) => row.status === 'unchanged').length
  const contextual = foldUnchangedContext(raw)
  const limited = boundRenderedRows(contextual.rows)

  return {
    rows: limited.rows,
    added,
    removed,
    unchanged,
    bounded: oldInput.bounded || newInput.bounded || calculated === undefined || limited.bounded,
    contextFolded: contextual.folded,
  }
}

function boundedLines(content: string): BoundedLines {
  const normalized = content.replace(/\r\n?/g, '\n')
  let text = normalized
  let bounded = false

  if (text.length > MAX_CONFIG_DIFF_CHARACTERS) {
    text = text.slice(0, MAX_CONFIG_DIFF_CHARACTERS)
    const lastCompleteLine = text.lastIndexOf('\n')
    if (lastCompleteLine >= 0) text = text.slice(0, lastCompleteLine)
    bounded = true
  }

  let lines = text.split('\n')
  if (lines.length > MAX_CONFIG_DIFF_LINES) {
    lines = lines.slice(0, MAX_CONFIG_DIFF_LINES)
    bounded = true
  }
  return { lines, bounded }
}

/**
 * Myers' line diff is linear in input size for small edits. The edit budget is
 * deliberate: configs with pathological churn fall back to honest replacement
 * semantics instead of freezing the browser.
 */
function myersDiff(
  before: readonly string[],
  after: readonly string[],
): ConfigDiffRow[] | undefined {
  const maximum = Math.min(before.length + after.length, MAX_CONFIG_DIFF_EDIT_DISTANCE)
  const frontier = new Map<number, number>([[1, 0]])
  const trace: Array<Map<number, number>> = []

  for (let distance = 0; distance <= maximum; distance += 1) {
    trace.push(new Map(frontier))
    for (let diagonal = -distance; diagonal <= distance; diagonal += 2) {
      const down = frontier.get(diagonal + 1) ?? Number.NEGATIVE_INFINITY
      const right = frontier.get(diagonal - 1) ?? Number.NEGATIVE_INFINITY
      let oldIndex =
        diagonal === -distance || (diagonal !== distance && right < down)
          ? Math.max(0, down)
          : Math.max(0, right + 1)
      let newIndex = oldIndex - diagonal

      while (
        oldIndex < before.length &&
        newIndex < after.length &&
        before[oldIndex] === after[newIndex]
      ) {
        oldIndex += 1
        newIndex += 1
      }
      frontier.set(diagonal, oldIndex)

      if (oldIndex >= before.length && newIndex >= after.length) {
        return backtrack(trace, before, after)
      }
    }
  }
  return undefined
}

function backtrack(
  trace: ReadonlyArray<ReadonlyMap<number, number>>,
  before: readonly string[],
  after: readonly string[],
): ConfigDiffRow[] {
  const rows: ConfigDiffRow[] = []
  let oldIndex = before.length
  let newIndex = after.length

  for (let distance = trace.length - 1; distance >= 0; distance -= 1) {
    const frontier = trace[distance]
    const diagonal = oldIndex - newIndex
    const down = frontier.get(diagonal + 1) ?? Number.NEGATIVE_INFINITY
    const right = frontier.get(diagonal - 1) ?? Number.NEGATIVE_INFINITY
    const previousDiagonal =
      diagonal === -distance || (diagonal !== distance && right < down)
        ? diagonal + 1
        : diagonal - 1
    const previousOld = Math.max(0, frontier.get(previousDiagonal) ?? 0)
    const previousNew = previousOld - previousDiagonal

    while (oldIndex > previousOld && newIndex > previousNew) {
      rows.push({
        status: 'unchanged',
        text: before[oldIndex - 1],
        beforeLine: oldIndex,
        afterLine: newIndex,
      })
      oldIndex -= 1
      newIndex -= 1
    }

    if (distance === 0) break
    if (oldIndex === previousOld) {
      rows.push({
        status: 'added',
        text: after[newIndex - 1],
        afterLine: newIndex,
      })
      newIndex -= 1
    } else {
      rows.push({
        status: 'removed',
        text: before[oldIndex - 1],
        beforeLine: oldIndex,
      })
      oldIndex -= 1
    }
  }

  return rows.reverse()
}

function foldUnchangedContext(rows: readonly ConfigDiffRow[]): {
  rows: ConfigDiffRow[]
  folded: boolean
} {
  const context = 2
  const keep = Array.from({ length: rows.length }, () => false)
  const changed = rows
    .map((row, index) => (row.status === 'unchanged' ? -1 : index))
    .filter((index) => index >= 0)

  if (changed.length === 0) {
    for (let index = 0; index < Math.min(context, rows.length); index += 1) keep[index] = true
    for (let index = Math.max(context, rows.length - context); index < rows.length; index += 1) {
      keep[index] = true
    }
  } else {
    for (const index of changed) {
      const start = Math.max(0, index - context)
      const end = Math.min(rows.length, index + context + 1)
      for (let candidate = start; candidate < end; candidate += 1) keep[candidate] = true
    }
  }

  const result: ConfigDiffRow[] = []
  let folded = false
  for (let index = 0; index < rows.length; ) {
    if (keep[index]) {
      result.push(rows[index])
      index += 1
      continue
    }
    const start = index
    while (index < rows.length && !keep[index]) index += 1
    result.push({ status: 'omitted', text: '', omitted: index - start })
    folded = true
  }
  return { rows: result, folded }
}

function boundRenderedRows(rows: readonly ConfigDiffRow[]): {
  rows: ConfigDiffRow[]
  bounded: boolean
} {
  if (rows.length <= MAX_RENDERED_CONFIG_DIFF_ROWS) return { rows: [...rows], bounded: false }

  const headCount = Math.floor((MAX_RENDERED_CONFIG_DIFF_ROWS - 1) / 2)
  const tailCount = MAX_RENDERED_CONFIG_DIFF_ROWS - headCount - 1
  const middle = rows.slice(headCount, rows.length - tailCount)
  const omitted = middle.reduce((count, row) => count + (row.omitted ?? 1), 0)
  return {
    rows: [
      ...rows.slice(0, headCount),
      { status: 'omitted', text: '', omitted },
      ...rows.slice(rows.length - tailCount),
    ],
    bounded: true,
  }
}
