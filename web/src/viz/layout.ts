import type { HopNode, Path } from '../api/paths'

// Geometry of the path graph (pixels). Columns are TTL distance left→right; nodes
// within a column stack vertically and are centered.
export const NODE_W = 132
export const NODE_H = 46
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

/**
 * layoutPath turns a discovered Path into positioned nodes + edges. A synthetic
 * "source" node anchors the left so the graph reads source → hops → destination.
 * It is O(nodes + links) — linear, so it stays fast on dense ECMP graphs.
 */
export function layoutPath(path: Path): VizLayout {
  const columns: VizNode[][] = []

  const source: VizNode = {
    id: 'source', ttl: 0, ip: 'source', label: 'You', x: 0, y: 0,
    lossRatio: 0, isSource: true, isDestination: false,
  }
  columns.push([source])

  for (const hop of path.hops) {
    columns.push(
      hop.nodes.map((n) => ({
        id: nodeId(hop.ttl, n.ip),
        ttl: hop.ttl,
        ip: n.ip,
        label: n.ip,
        x: 0,
        y: 0,
        lossRatio: n.loss_ratio,
        isSource: false,
        isDestination: n.ip === path.target_ip,
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
    const from = nodeId(l.ttl, l.from)
    const to = nodeId(l.ttl + 1, l.to)
    const b = byId.get(to)
    if (byId.has(from) && b) {
      edges.push(makeEdge(from, to, byId, b.lossRatio))
    }
  }

  return { nodes, edges, width, height }
}

function nodeId(ttl: number, ip: string) {
  return `${ttl}:${ip}`
}

function makeEdge(fromId: string, toId: string, byId: Map<string, VizNode>, lossRatio: number): VizEdge {
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
export function lossByHop(path: Path): { ttl: number; loss: number; ip: string }[] {
  return path.hops.map((hop) => {
    let loss = 0
    let ip = hop.nodes[0]?.ip ?? '*'
    for (const n of hop.nodes) {
      if (n.loss_ratio > loss) {
        loss = n.loss_ratio
        ip = n.ip
      }
    }
    return { ttl: hop.ttl, loss, ip }
  })
}

/** lossTone maps a loss ratio to a status tone for token-driven coloring. */
export function lossTone(loss: number): 'ok' | 'warning' | 'danger' {
  if (loss <= 0) return 'ok'
  if (loss < 0.3) return 'warning'
  return 'danger'
}
