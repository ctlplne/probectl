// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import styles from './EmptyStatePreviews.module.css'
import { DemoDataBadge } from './Badge'
import { useDemoMode } from '../demo/useDemoMode'

export function FirstRunPreview() {
  const { active } = useDemoMode()
  if (!active) return null
  return (
    <div className={styles.panel} aria-label="First-run sample preview">
      <div className={styles.badge}>
        <DemoDataBadge />
      </div>
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
  const { active } = useDemoMode()
  if (!active) return null
  return (
    <div className={styles.graph} aria-label="Topology sample preview">
      <div className={styles.badge}>
        <DemoDataBadge />
      </div>
      <span className={styles.node}>canary</span>
      <span className={styles.edge} />
      <span className={styles.node}>edge-r1</span>
      <span className={styles.edge} />
      <span className={styles.nodeAccent}>checkout</span>
    </div>
  )
}

export function PlanesPreview() {
  const { active } = useDemoMode()
  if (!active) return null
  return (
    <div className={styles.panel} aria-label="Planes sample preview">
      <div className={styles.badge}>
        <DemoDataBadge />
      </div>
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
  const { active } = useDemoMode()
  if (!active) return null
  return (
    <div className={styles.metrics} aria-label="Dashboard sample preview">
      <div className={styles.badge}>
        <DemoDataBadge />
      </div>
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
