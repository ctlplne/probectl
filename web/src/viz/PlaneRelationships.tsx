import styles from './PlaneRelationships.module.css'
import { ChartShell } from '../components'
import type { FlowTopRow } from '../api/planes'
import type { TopoEdge, TopoNode } from '../api/topology'
import { useI18n } from '../i18n/useI18n'
import { formatScaledBytes } from '../i18n/number'

const BGP_EDGE_LIMIT = 16
const FLOW_EDGE_LIMIT = 8
const SVG_W = 760
const NODE_W = 178
const NODE_H = 38
const LEFT_X = 32
const RIGHT_X = SVG_W - LEFT_X - NODE_W

interface Relationship {
  id: string
  source: string
  target: string
}

function labelFor(nodes: TopoNode[], id: string): string {
  return nodes.find((n) => n.id === id)?.label ?? id
}

function uniq(values: string[]): string[] {
  return [...new Set(values)]
}

function clip(label: string, max = 24): string {
  return label.length > max ? `${label.slice(0, max - 3)}...` : label
}

function yFor(index: number, total: number, height: number): number {
  if (total <= 1) return height / 2
  const top = 32
  const span = height - top * 2
  return top + (span * index) / (total - 1)
}

function NodeLabel({
  x,
  y,
  label,
  variant,
}: {
  x: number
  y: number
  label: string
  variant: 'source' | 'target'
}) {
  return (
    <g className={[styles.node, styles[variant]].join(' ')} transform={`translate(${x} ${y})`}>
      <rect width={NODE_W} height={NODE_H} rx={6} />
      <text x={12} y={24}>
        {clip(label)}
      </text>
      <title>{label}</title>
    </g>
  )
}

export function BgpAsPathView({ nodes, routingEdges }: { nodes: TopoNode[]; routingEdges: TopoEdge[] }) {
  const relationships: Relationship[] = routingEdges.map((edge, index) => ({
    id: `${edge.from}-${edge.to}-${index}`,
    source: labelFor(nodes, edge.from),
    target: labelFor(nodes, edge.to),
  }))
  const visible = relationships.slice(0, BGP_EDGE_LIMIT)
  const sources = uniq(visible.map((r) => r.source))
  const targets = uniq(visible.map((r) => r.target))
  const rowCount = Math.max(sources.length, targets.length, 1)
  const svgH = Math.max(210, rowCount * 54)
  const hidden = Math.max(0, relationships.length - visible.length)

  return (
    <ChartShell
      title="BGP AS-path arcs"
      height={260}
      legend={
        <span>
          Showing {visible.length} of {relationships.length} routing relationships
          {hidden > 0 ? '; table fallback lists every edge' : ''}
        </span>
      }
    >
      <div className={styles.canvas}>
        <svg
          className={styles.svg}
          width={SVG_W}
          height={svgH}
          viewBox={`0 0 ${SVG_W} ${svgH}`}
          role="img"
          aria-label={`BGP AS-path arc view with ${visible.length} of ${relationships.length} routing relationships`}
        >
          <g className={styles.links}>
            {visible.map((rel) => {
              const sy = yFor(sources.indexOf(rel.source), sources.length, svgH) + NODE_H / 2
              const ty = yFor(targets.indexOf(rel.target), targets.length, svgH) + NODE_H / 2
              const sx = LEFT_X + NODE_W
              const tx = RIGHT_X
              return (
                <path
                  key={rel.id}
                  className={styles.bgpLink}
                  d={`M ${sx} ${sy} C ${sx + 120} ${sy}, ${tx - 120} ${ty}, ${tx} ${ty}`}
                >
                  <title>{`${rel.source} announces ${rel.target}`}</title>
                </path>
              )
            })}
          </g>
          {sources.map((source, index) => (
            <NodeLabel
              key={source}
              x={LEFT_X}
              y={yFor(index, sources.length, svgH)}
              label={source}
              variant="source"
            />
          ))}
          {targets.map((target, index) => (
            <NodeLabel
              key={target}
              x={RIGHT_X}
              y={yFor(index, targets.length, svgH)}
              label={target}
              variant="target"
            />
          ))}
        </svg>
      </div>
    </ChartShell>
  )
}

export function FlowSankeyView({ rows }: { rows: FlowTopRow[] }) {
  const { locale } = useI18n()
  const visible = rows.slice(0, FLOW_EDGE_LIMIT)
  const sources = uniq(visible.map((row) => row.key))
  const targets = uniq(visible.map((row) => row.detail || 'tenant aggregate'))
  const rowCount = Math.max(sources.length, targets.length, 1)
  const svgH = Math.max(210, rowCount * 54)
  const maxBytes = Math.max(...visible.map((row) => row.bytes), 1)
  const hidden = Math.max(0, rows.length - visible.length)

  return (
    <ChartShell
      title="Flow Sankey"
      height={260}
      legend={
        <span>
          Showing {visible.length} of {rows.length} contributors
          {hidden > 0 ? '; table fallback lists every row' : ''}
        </span>
      }
    >
      <div className={styles.canvas}>
        <svg
          className={styles.svg}
          width={SVG_W}
          height={svgH}
          viewBox={`0 0 ${SVG_W} ${svgH}`}
          role="img"
          aria-label={`Flow Sankey view with ${visible.length} of ${rows.length} contributors`}
        >
          <g className={styles.links}>
            {visible.map((row) => {
              const target = row.detail || 'tenant aggregate'
              const sy = yFor(sources.indexOf(row.key), sources.length, svgH) + NODE_H / 2
              const ty = yFor(targets.indexOf(target), targets.length, svgH) + NODE_H / 2
              const sx = LEFT_X + NODE_W
              const tx = RIGHT_X
              const width = 4 + (row.bytes / maxBytes) * 18
              return (
                <path
                  key={`${row.key}-${target}`}
                  className={styles.flowLink}
                  strokeWidth={width}
                  d={`M ${sx} ${sy} C ${sx + 130} ${sy}, ${tx - 130} ${ty}, ${tx} ${ty}`}
                >
                  <title>{`${row.key} to ${target}: ${formatScaledBytes(row.bytes, locale)}`}</title>
                </path>
              )
            })}
          </g>
          {sources.map((source, index) => (
            <NodeLabel
              key={source}
              x={LEFT_X}
              y={yFor(index, sources.length, svgH)}
              label={source}
              variant="source"
            />
          ))}
          {targets.map((target, index) => (
            <NodeLabel
              key={target}
              x={RIGHT_X}
              y={yFor(index, targets.length, svgH)}
              label={target}
              variant="target"
            />
          ))}
        </svg>
      </div>
    </ChartShell>
  )
}
