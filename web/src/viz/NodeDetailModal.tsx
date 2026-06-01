import styles from './NodeDetailModal.module.css'
import { Badge, Modal } from '../components'
import type { VizNode } from './layout'

function ms(v: number | undefined) {
  return v === undefined || v < 0 ? '—' : `${v.toFixed(v < 10 ? 2 : 1)} ms`
}

/** NodeDetailModal is the per-hop drill-down on the S8a Modal. */
export function NodeDetailModal({ node, onClose }: { node: VizNode | null; onClose: () => void }) {
  const n = node?.node
  return (
    <Modal open={!!node && !node.isSource} onClose={onClose} title={node ? `Hop ${node.ttl} · ${node.ip}` : ''}>
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
              {ms(n.rtt_min_ms)} / {ms(n.rtt_avg_ms)} / {ms(n.rtt_max_ms)}
            </dd>
          </div>
          <div>
            <dt>Loss</dt>
            <dd>
              <Badge tone={n.loss_ratio === 0 ? 'success' : n.loss_ratio < 0.3 ? 'warning' : 'danger'}>
                {Math.round(n.loss_ratio * 100)}% ({n.received}/{n.sent})
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
