import styles from './EmptyStatePreviews.module.css'

export function FirstRunPreview() {
  return (
    <div className={styles.panel} aria-label="First-run sample preview">
      <div className={styles.row}>
        <span className={styles.dotSuccess} />
        <strong>checkout-http</strong>
        <span>p95 38 ms</span>
      </div>
      <div className={styles.row}>
        <span className={styles.dotInfo} />
        <strong>edge-dns</strong>
        <span>scheduled</span>
      </div>
    </div>
  )
}

export function TopologyPreview() {
  return (
    <div className={styles.graph} aria-label="Topology sample preview">
      <span className={styles.node}>canary</span>
      <span className={styles.edge} />
      <span className={styles.node}>edge-r1</span>
      <span className={styles.edge} />
      <span className={styles.nodeAccent}>checkout</span>
    </div>
  )
}

export function PlanesPreview() {
  return (
    <div className={styles.panel} aria-label="Planes sample preview">
      <div className={styles.row}>
        <strong>BGP</strong>
        <span>2 AS paths</span>
      </div>
      <div className={styles.row}>
        <strong>Flow</strong>
        <span>14.2 Mbps</span>
      </div>
      <div className={styles.row}>
        <strong>eBPF</strong>
        <span>service edge</span>
      </div>
    </div>
  )
}

export function DashboardPreview() {
  return (
    <div className={styles.metrics} aria-label="Dashboard sample preview">
      <span>
        <strong>99.95%</strong>
        <small>SLO</small>
      </span>
      <span>
        <strong>3</strong>
        <small>signals</small>
      </span>
      <span>
        <strong>42 ms</strong>
        <small>p95</small>
      </span>
    </div>
  )
}
