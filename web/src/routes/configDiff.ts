// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

export const MAX_CONFIG_DIFF_EDIT_DISTANCE = 400
export const CONFIG_DIFF_PAGE_SIZE = 400

export interface ConfigVersionForComparison {
  id: string
  device: string
  version: number
  content_hash: string
  previous_hash?: string
  content?: string
  drifted: boolean
  binding?: {
    kind: string
    context_id: string
    device_entity_id: string
    agent_id: string
    source_ref: string
    source_assigned_at: string
    agent_assigned_at: string
  } | null
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
  completeRows: ConfigDiffRow[]
  replacement: boolean
  added: number
  removed: number
  unchanged: number
  contextFolded: boolean
}

/**
 * Returns the exact archived predecessor for a version. The content hash is
 * authoritative together with the immediate version and exact source stream.
 * An older equivalent body cannot substitute for a missing original record.
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
        sameConfigStream(candidate, current) &&
        candidate.version === current.version - 1 &&
        candidate.content_hash === current.previous_hash &&
        typeof candidate.content === 'string',
    )
    .sort((left, right) => right.version - left.version || left.id.localeCompare(right.id))[0]
}

function sameConfigStream(left: ConfigVersionForComparison, right: ConfigVersionForComparison) {
  if (!left.binding && !right.binding) return left.device === right.device
  if (!left.binding || !right.binding) return false
  for (const key of [
    'kind',
    'context_id',
    'device_entity_id',
    'agent_id',
    'source_ref',
    'source_assigned_at',
    'agent_assigned_at',
  ] as const) {
    if (!left.binding[key] || left.binding[key] !== right.binding[key]) return false
  }
  return left.binding.kind === 'operator_bound_archive'
}

export function createConfigDiff(before: string, after: string): ConfigDiffResult {
  // Archive admission owns complete input bytes. Never slice a supported
  // snapshot or discard changed rows to fit the viewport. The edit search has
  // finite work; high churn retains a complete replacement representation.
  const oldLines = before.replace(/\r\n?/g, '\n').split('\n')
  const newLines = after.replace(/\r\n?/g, '\n').split('\n')
  const calculated = myersDiff(oldLines, newLines)
  const raw =
    calculated ??
    oldLines
      .map<ConfigDiffRow>((text, index) => ({
        status: 'removed',
        text,
        beforeLine: index + 1,
      }))
      .concat(
        newLines.map<ConfigDiffRow>((text, index) => ({
          status: 'added',
          text,
          afterLine: index + 1,
        })),
      )

  const added = raw.filter((row) => row.status === 'added').length
  const removed = raw.filter((row) => row.status === 'removed').length
  const unchanged = raw.filter((row) => row.status === 'unchanged').length
  const contextual = foldUnchangedContext(raw)

  return {
    rows: contextual.rows,
    completeRows: raw,
    replacement: calculated === undefined,
    added,
    removed,
    unchanged,
    contextFolded: contextual.folded,
  }
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
