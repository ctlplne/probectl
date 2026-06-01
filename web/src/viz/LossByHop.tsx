import styles from './LossByHop.module.css'
import { ChartShell } from '../components'
import { lossByHop, lossTone } from './layout'
import type { Path } from '../api/paths'

/** LossByHop is the per-hop loss sparkline — a tall, danger-toned bar pinpoints
 *  the hop where drops occur (the Done-when: localize the lossy hop). */
export function LossByHop({ path }: { path: Path }) {
  const series = lossByHop(path)
  const h = 110
  const barW = 18
  const gap = 10
  const w = Math.max(series.length * (barW + gap) + gap, 120)
  const worst = series.reduce((m, s) => Math.max(m, s.loss), 0)

  return (
    <ChartShell
      title="Loss by hop"
      height={150}
      legend={
        worst > 0 ? (
          <span>
            Worst hop: {Math.round(worst * 100)}% loss
          </span>
        ) : (
          <span>No loss observed</span>
        )
      }
    >
      <svg
        className={styles.svg}
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="xMinYMid meet"
        role="img"
        aria-label="Packet loss by hop"
      >
        {series.map((s, i) => {
          const x = gap + i * (barW + gap)
          const bh = Math.max(2, s.loss * (h - 22))
          return (
            <g key={s.ttl}>
              <rect
                className={[styles.bar, styles[lossTone(s.loss)]].join(' ')}
                x={x}
                y={h - 18 - bh}
                width={barW}
                height={bh}
                rx={2}
              >
                <title>{`Hop ${s.ttl} (${s.ip}): ${Math.round(s.loss * 100)}% loss`}</title>
              </rect>
              <text className={styles.label} x={x + barW / 2} y={h - 4} textAnchor="middle">
                {s.ttl}
              </text>
            </g>
          )
        })}
      </svg>
    </ChartShell>
  )
}
