// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type { TopoEdge, TopoNode } from '../api/topology'

/**
 * Layered layout for the S43 topology graph: nodes group into columns by kind
 * (the natural dependency order — agents probe through hops/devices to hosts;
 * services overlay; routing anchors the right edge), stack alphabetically
 * within a column, and edges connect computed centers. O(nodes + edges), so
 * dense graphs stay fast; legibility on dense graphs is bounded by MAX_NODES
 * with an honest "showing N of M" rather than an unreadable hairball (the PR2+
 * polish iterates layout quality — this is the functional PR1 view).
 */

export const T_NODE_W = 148
export const T_NODE_H = 40
// Keep a useful hop → device → service chain readable as one laptop overview.
// Edges still get a dedicated channel; edgePath bounds its curve to this gap.
export const T_COL_GAP = 48
export const T_ROW_GAP = 14
export const T_MARGIN = 30
/** Vertical room above the node grid for the per-kind column headers. */
export const T_HEADER = 30

/** Render cap for dense graphs (PR1 legibility guard). */
export const MAX_NODES = 400

const KIND_ORDER = ['agent', 'hop', 'device', 'host', 'service', 'as', 'prefix']

export interface PlacedNode extends TopoNode {
  x: number
  y: number
}

export interface PlacedEdge extends TopoEdge {
  id: string
  x1: number
  y1: number
  x2: number
  y2: number
}

export interface TopoColumn {
  kind: string
  x: number
}

export interface TopoLayout {
  nodes: PlacedNode[]
  edges: PlacedEdge[]
  /** Populated kind columns, in layout order — drives band headers + legend. */
  columns: TopoColumn[]
  width: number
  height: number
  total: number // total nodes before the render cap
  truncated: boolean
}

export function layoutTopology(nodes: TopoNode[], edges: TopoEdge[]): TopoLayout {
  const total = nodes.length
  const sorted = [...nodes].sort((a, b) => a.label.localeCompare(b.label))
  const capped = sorted.slice(0, MAX_NODES)
  if (capped.length === 0) {
    return {
      nodes: [],
      edges: [],
      columns: [],
      width: T_MARGIN * 2 + T_NODE_W,
      height: T_MARGIN * 2 + T_NODE_H,
      total,
      truncated: false,
    }
  }
  const keep = new Set(capped.map((n) => n.id))

  const columns: PlacedNode[][] = KIND_ORDER.map(() => [])
  const overflow: PlacedNode[] = []
  for (const n of capped) {
    const col = KIND_ORDER.indexOf(n.kind)
    const placed: PlacedNode = { ...n, x: 0, y: 0 }
    if (col >= 0) columns[col].push(placed)
    else overflow.push(placed)
  }
  if (overflow.length) columns.push(overflow)

  const populated = columns.filter((c) => c.length > 0)
  const maxRows = Math.max(1, ...populated.map((c) => c.length))
  const height = T_HEADER + T_MARGIN * 2 + maxRows * T_NODE_H + (maxRows - 1) * T_ROW_GAP
  const width = T_MARGIN * 2 + populated.length * T_NODE_W + (populated.length - 1) * T_COL_GAP

  const byID = new Map<string, PlacedNode>()
  const placedColumns: TopoColumn[] = []
  populated.forEach((col, ci) => {
    const colHeight = col.length * T_NODE_H + (col.length - 1) * T_ROW_GAP
    const top = T_HEADER + (height - T_HEADER - colHeight) / 2
    const x = T_MARGIN + ci * (T_NODE_W + T_COL_GAP)
    placedColumns.push({ kind: col === overflow ? 'other' : col[0].kind, x })
    col.forEach((n, ri) => {
      n.x = x
      n.y = top + ri * (T_NODE_H + T_ROW_GAP)
      byID.set(n.id, n)
    })
  })

  const placedEdges: PlacedEdge[] = []
  for (const e of edges) {
    if (!keep.has(e.from) || !keep.has(e.to)) continue
    const a = byID.get(e.from)
    const b = byID.get(e.to)
    if (!a || !b) continue
    placedEdges.push({
      ...e,
      id: `${e.from}|${e.kind}|${e.to}`,
      x1: a.x + T_NODE_W,
      y1: a.y + T_NODE_H / 2,
      x2: b.x,
      y2: b.y + T_NODE_H / 2,
    })
  }

  return {
    nodes: [...byID.values()],
    edges: placedEdges,
    columns: placedColumns,
    width,
    height,
    total,
    truncated: total > capped.length,
  }
}
