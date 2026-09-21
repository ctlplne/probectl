// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { HopNode, Path } from '../api/paths'

// Geometry of the path graph (pixels). Columns are TTL distance left→right; nodes
// within a column stack vertically and are centered.
export const NODE_W = 168
export const NODE_H = 64
export const COL_GAP = 92
export const ROW_GAP = 18
export const MARGIN = 28

export interface VizNode {
  id: string
  ttl: number
  ip: string
  label: string
  x: number
  y: number
  lossRatio: number
  isSource: boolean
  isDestination: boolean
  branchLabel: string
  node?: HopNode
}

export interface VizEdge {
  id: string
  from: string
  to: string
  x1: number
  y1: number
  x2: number
  y2: number
  lossRatio: number
}

export interface VizLayout {
  nodes: VizNode[]
  edges: VizEdge[]
  width: number
  height: number
}

export interface PathGraphSummary {
  path: Path
  branchLabels: ReadonlyMap<string, string>
  totalNodes: number
  visibleNodes: number
  aggregated: boolean
}

export const MAX_PATH_GRAPH_NODES = 120
export const MAX_PATH_GRAPH_BRANCHES_PER_HOP = 6

/**
 * layoutPath turns a discovered Path into positioned nodes + edges. A synthetic
 * "source" node anchors the left so the graph reads source → hops → destination.
 * It is O(nodes + links) — linear, so it stays fast on dense ECMP graphs.
 */
export function layoutPath(
  path: Path,
  branchLabels: ReadonlyMap<string, string> = pathBranchLabels(path),
): VizLayout {
  const columns: VizNode[][] = []

  const source: VizNode = {
    id: 'source',
    ttl: 0,
    ip: 'source',
    label: 'You',
    x: 0,
    y: 0,
    lossRatio: 0,
    isSource: true,
    isDestination: false,
    branchLabel: 'Source',
  }
  columns.push([source])

  for (const hop of path.hops) {
    columns.push(
      hop.nodes.map((n) => ({
        id: pathNodeID(hop.ttl, n.ip),
        ttl: hop.ttl,
        ip: n.ip,
        label: n.ip,
        x: 0,
        y: 0,
        lossRatio: n.loss_ratio,
        isSource: false,
        isDestination: n.ip === path.target_ip,
        branchLabel: branchLabels.get(pathNodeID(hop.ttl, n.ip)) ?? 'Primary',
        node: n,
      })),
    )
  }

  const maxRows = Math.max(1, ...columns.map((c) => c.length))
  const height = MARGIN * 2 + maxRows * NODE_H + (maxRows - 1) * ROW_GAP
  const width = MARGIN * 2 + columns.length * NODE_W + (columns.length - 1) * COL_GAP

  columns.forEach((col, ci) => {
    const x = MARGIN + ci * (NODE_W + COL_GAP)
    const colH = col.length * NODE_H + (col.length - 1) * ROW_GAP
    const y0 = (height - colH) / 2
    col.forEach((n, ri) => {
      n.x = x
      n.y = y0 + ri * (NODE_H + ROW_GAP)
    })
  })

  const nodes = columns.flat()
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const edges: VizEdge[] = []

  // Source connects to every first-hop responder.
  for (const n of columns[1] ?? []) {
    edges.push(makeEdge('source', n.id, byId, n.lossRatio))
  }
  // Observed adjacencies (link.from at link.ttl → link.to at link.ttl+1).
  for (const l of path.links) {
    const from = pathNodeID(l.ttl, l.from)
    const to = pathNodeID(l.ttl + 1, l.to)
    const b = byId.get(to)
    if (byId.has(from) && b) {
      edges.push(makeEdge(from, to, byId, b.lossRatio))
    }
  }

  return { nodes, edges, width, height }
}

export function pathNodeID(ttl: number, ip: string) {
  return `${ttl}:${ip}`
}

export function pathBranchLabels(path: Path): ReadonlyMap<string, string> {
  const labels = new Map<string, string>()
  for (const hop of path.hops) {
    hop.nodes.forEach((node, index) => {
      labels.set(
        pathNodeID(hop.ttl, node.ip),
        hop.nodes.length > 1 ? `Branch ${index + 1}` : 'Primary',
      )
    })
  }
  return labels
}

/**
 * summarizePathForGraph bounds only the SVG. The exact source path is returned
 * separately through the searchable table, so dense telemetry is aggregated,
 * never silently clipped. Lossiest/highest-latency branches win the viewport;
 * an explicitly selected branch is always retained.
 */
export function summarizePathForGraph(path: Path, selectedID?: string): PathGraphSummary {
  const totalNodes = path.hops.reduce((total, hop) => total + hop.nodes.length, 0)
  const branchLabels = pathBranchLabels(path)
  if (totalNodes <= MAX_PATH_GRAPH_NODES) {
    return { path, branchLabels, totalNodes, visibleNodes: totalNodes, aggregated: false }
  }

  const perHop = Math.max(
    1,
    Math.min(
      MAX_PATH_GRAPH_BRANCHES_PER_HOP,
      Math.floor((MAX_PATH_GRAPH_NODES - 1) / Math.max(path.hops.length, 1)),
    ),
  )
  const hops = path.hops.map((hop) => {
    if (hop.nodes.length <= perHop) return hop
    const ranked = [...hop.nodes].sort(
      (a, b) =>
        b.loss_ratio - a.loss_ratio || b.rtt_avg_ms - a.rtt_avg_ms || a.ip.localeCompare(b.ip),
    )
    const keep = new Set(ranked.slice(0, perHop).map((node) => node.ip))
    const selected = hop.nodes.find((node) => pathNodeID(hop.ttl, node.ip) === selectedID)
    const destination = hop.nodes.find((node) => node.ip === path.target_ip)
    const required = new Set(
      [destination?.ip, selected?.ip].filter((ip): ip is string => Boolean(ip)),
    )
    for (const ip of required) keep.add(ip)
    for (const candidate of [...ranked].reverse()) {
      if (keep.size <= Math.max(perHop, required.size)) break
      if (!required.has(candidate.ip)) keep.delete(candidate.ip)
    }
    return { ...hop, nodes: hop.nodes.filter((node) => keep.has(node.ip)) }
  })
  const visible = new Set(
    hops.flatMap((hop) => hop.nodes.map((node) => pathNodeID(hop.ttl, node.ip))),
  )
  const links = path.links.filter(
    (link) =>
      visible.has(pathNodeID(link.ttl, link.from)) &&
      visible.has(pathNodeID(link.ttl + 1, link.to)),
  )
  const visibleNodes = hops.reduce((total, hop) => total + hop.nodes.length, 0)
  return {
    path: { ...path, hops, links },
    branchLabels,
    totalNodes,
    visibleNodes,
    aggregated: true,
  }
}

function makeEdge(
  fromId: string,
  toId: string,
  byId: Map<string, VizNode>,
  lossRatio: number,
): VizEdge {
  const a = byId.get(fromId)!
  const b = byId.get(toId)!
  return {
    id: `${fromId}->${toId}`,
    from: fromId,
    to: toId,
    x1: a.x + NODE_W,
    y1: a.y + NODE_H / 2,
    x2: b.x,
    y2: b.y + NODE_H / 2,
    lossRatio,
  }
}

/** lossByHop is the worst per-hop loss, for the loss-by-hop sparkline (localizes
 *  where drops happen). */
export function lossByHop(
  path: Path,
): { ttl: number; loss: number; ip: string; id: string; branchLabel: string }[] {
  const branches = pathBranchLabels(path)
  return path.hops.map((hop) => {
    let loss = 0
    let ip = hop.nodes[0]?.ip ?? '*'
    for (const n of hop.nodes) {
      if (n.loss_ratio > loss) {
        loss = n.loss_ratio
        ip = n.ip
      }
    }
    const id = pathNodeID(hop.ttl, ip)
    return { ttl: hop.ttl, loss, ip, id, branchLabel: branches.get(id) ?? 'Primary' }
  })
}

export function worstPathNode(path: Path): VizNode | undefined {
  return layoutPath(path)
    .nodes.filter((node) => !node.isSource)
    .sort(
      (a, b) =>
        b.lossRatio - a.lossRatio ||
        (b.node?.rtt_avg_ms ?? 0) - (a.node?.rtt_avg_ms ?? 0) ||
        a.id.localeCompare(b.id),
    )[0]
}

/** lossTone maps a loss ratio to a status tone for token-driven coloring. */
export function lossTone(loss: number): 'ok' | 'warning' | 'danger' {
  if (loss <= 0) return 'ok'
  if (loss < 0.3) return 'warning'
  return 'danger'
}
