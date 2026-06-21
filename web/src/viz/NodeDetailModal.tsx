import styles from './NodeDetailModal.module.css'
import { Badge, Modal } from '../components'
import type { VizNode } from './layout'
import { useI18n } from '../i18n/useI18n'
import { formatInteger, formatPercentValue, formatUnit } from '../i18n/number'

function ms(v: number | undefined, locale: string) {
  return v === undefined || v < 0
    ? '—'
    : formatUnit(v, 'ms', locale, { maximumFractionDigits: v < 10 ? 2 : 1 })
}

/** NodeDetailModal is the per-hop drill-down on the S8a Modal. */
export function NodeDetailModal({ node, onClose }: { node: VizNode | null; onClose: () => void }) {
  const { locale } = useI18n()
  const n = node?.node
  return (
    <Modal
      open={!!node && !node.isSource}
      onClose={onClose}
      title={node ? `Hop ${node.ttl} · ${node.ip}` : ''}
    >
      {n ? (
        <dl className={styles.detail}>
          <div>
            <dt>Responder</dt>
            <dd>
              <code>{node?.ip}</code>{' '}
              {node?.isDestination ? <Badge tone="accent">destination</Badge> : null}
            </dd>
          </div>
          <div>
            <dt>RTT (min / avg / max)</dt>
            <dd>
              {ms(n.rtt_min_ms, locale)} / {ms(n.rtt_avg_ms, locale)} /{' '}
              {ms(n.rtt_max_ms, locale)}
            </dd>
          </div>
          <div>
            <dt>Loss</dt>
            <dd>
              <Badge
                tone={n.loss_ratio === 0 ? 'success' : n.loss_ratio < 0.3 ? 'warning' : 'danger'}
              >
                {formatPercentValue(n.loss_ratio * 100, locale, { maximumFractionDigits: 0 })} (
                {formatInteger(n.received, locale)}/{formatInteger(n.sent, locale)})
              </Badge>
            </dd>
          </div>
          {n.mpls && n.mpls.length > 0 ? (
            <div>
              <dt>MPLS labels</dt>
              <dd className={styles.labels}>
                {n.mpls.map((l, i) => (
                  <Badge key={i} tone="info">
                    {l.label}
                    {l.s ? ' (bottom)' : ''}
                  </Badge>
                ))}
              </dd>
            </div>
          ) : null}
        </dl>
      ) : null}
    </Modal>
  )
}
