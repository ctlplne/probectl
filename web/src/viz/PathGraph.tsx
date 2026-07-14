import { useMemo, useState, type KeyboardEvent } from 'react'
import styles from './PathGraph.module.css'
import { layoutPath, lossTone, NODE_H, NODE_W, summarizePathForGraph, type VizNode } from './layout'
import type { Path } from '../api/paths'
import { useI18n } from '../i18n/useI18n'
import { formatPercentValue, formatUnit } from '../i18n/number'

function fmtMs(ms: number, locale: string) {
  return ms >= 0 ? formatUnit(ms, 'ms', locale, { maximumFractionDigits: ms < 10 ? 1 : 0 }) : '—'
}
function fmtLoss(loss: number, locale: string) {
  return formatPercentValue(loss * 100, locale, { maximumFractionDigits: 0 })
}

/**
 * PathGraph renders a merged multi-path traceroute as an interactive, dark-native
 * SVG: TTL columns, stable ECMP branch identities, inline loss/latency/MPLS,
 * links colored by loss, focus tooltips, and keyboard-operable selection. Dense
 * paths deliberately summarize only the SVG; PathHopTable keeps every exact row.
 */
export function PathGraph({
  path,
  selectedId,
  onSelect,
}: {
  path: Path
  selectedId?: string
  onSelect: (node: VizNode) => void
}) {
  const { locale } = useI18n()
  const summarized = useMemo(() => summarizePathForGraph(path, selectedId), [path, selectedId])
  const { nodes, edges, width, height } = useMemo(
    () => layoutPath(summarized.path, summarized.branchLabels),
    [summarized],
  )
  const [activeId, setActiveId] = useState<string | null>(null)
  const active = nodes.find((n) => n.id === activeId)

  function activate(node: VizNode, e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onSelect(node)
    }
  }

  return (
    <div className={styles.wrap}>
      <div className={styles.scroll}>
        <svg
          className={styles.svg}
          width={width}
          height={height}
          role="group"
          aria-label={`Network path to ${path.target}: ${path.hops.length} hops, destination ${
            path.destination_reached ? 'reached' : 'not reached'
          }`}
        >
          <g className={styles.edges}>
            {edges.map((edge) => {
              const dx = Math.max(24, (edge.x2 - edge.x1) / 2)
              return (
                <path
                  key={edge.id}
                  className={[styles.edge, styles[lossTone(edge.lossRatio)]].join(' ')}
                  d={`M ${edge.x1} ${edge.y1} C ${edge.x1 + dx} ${edge.y1}, ${edge.x2 - dx} ${edge.y2}, ${edge.x2} ${edge.y2}`}
                />
              )
            })}
          </g>

          {nodes.map((n) => {
            const tone = lossTone(n.lossRatio)
            const cls = [
              styles.node,
              n.isSource ? styles.source : '',
              n.isDestination ? styles.destination : '',
              n.id === selectedId ? styles.selected : '',
              !n.isSource ? styles[tone] : '',
            ]
              .filter(Boolean)
              .join(' ')
            const ariaLabel = n.isSource
              ? 'Source'
              : `Hop ${n.ttl}, ${n.branchLabel}, ${n.ip}${
                  n.isDestination ? ' (destination)' : ''
                }, ${fmtLoss(n.lossRatio, locale)} loss, ${fmtMs(n.node?.rtt_avg_ms ?? -1, locale)}`
            return (
              <g
                key={n.id}
                className={cls}
                transform={`translate(${n.x} ${n.y})`}
                tabIndex={n.isSource ? -1 : 0}
                role={n.isSource ? undefined : 'button'}
                aria-pressed={n.isSource ? undefined : n.id === selectedId}
                aria-label={n.isSource ? undefined : ariaLabel}
                onMouseEnter={() => setActiveId(n.id)}
                onMouseLeave={() => setActiveId((id) => (id === n.id ? null : id))}
                onFocus={() => setActiveId(n.id)}
                onBlur={() => setActiveId((id) => (id === n.id ? null : id))}
                onClick={() => !n.isSource && onSelect(n)}
                onKeyDown={(e) => !n.isSource && activate(n, e)}
              >
                <rect className={styles.box} width={NODE_W} height={NODE_H} rx={8} />
                <text className={styles.ip} x={12} y={18}>
                  {n.label}
                </text>
                {!n.isSource ? (
                  <text className={styles.meta} x={12} y={36}>
                    {n.branchLabel} · {fmtMs(n.node?.rtt_avg_ms ?? -1, locale)}
                    {n.lossRatio > 0 ? ` · ${fmtLoss(n.lossRatio, locale)} loss` : ''}
                  </text>
                ) : null}
                {n.node?.mpls && n.node.mpls.length > 0 ? (
                  <text className={styles.mpls} x={12} y={53}>
                    MPLS {n.node.mpls.map((label) => label.label).join(' / ')}
                  </text>
                ) : null}
              </g>
            )
          })}
        </svg>

        {active && !active.isSource ? (
          <div
            className={styles.tooltip}
            style={{ left: active.x + NODE_W + 10, top: active.y }}
            role="presentation"
          >
            <strong className={styles.ttIp}>{active.ip}</strong>
            <dl className={styles.ttList}>
              <div>
                <dt>RTT</dt>
                <dd>
                  {fmtMs(active.node?.rtt_min_ms ?? -1, locale)} /{' '}
                  {fmtMs(active.node?.rtt_avg_ms ?? -1, locale)} /{' '}
                  {fmtMs(active.node?.rtt_max_ms ?? -1, locale)}
                </dd>
              </div>
              <div>
                <dt>Loss</dt>
                <dd>{fmtLoss(active.lossRatio, locale)}</dd>
              </div>
              {active.node?.mpls && active.node.mpls.length > 0 ? (
                <div>
                  <dt>MPLS</dt>
                  <dd>{active.node.mpls.map((l) => l.label).join(', ')}</dd>
                </div>
              ) : null}
            </dl>
          </div>
        ) : null}
      </div>
      {summarized.aggregated ? (
        <p className={styles.coverage} role="note" aria-label="Path graph coverage">
          Graph shows {summarized.visibleNodes} representative responders of {summarized.totalNodes}
          . Lossiest and highest-latency branches are prioritized; every exact responder remains
          searchable in the hop table.
        </p>
      ) : null}
    </div>
  )
}
