// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { lazy, Suspense } from 'react'
import { useLocation } from 'react-router-dom'
import { Badge, Card, CardBody, CardHeader, DemoDataBadge, Table } from '../components'
import { demoPageForPath, type DemoTableModel, type DemoTableRow } from './demoPages'
import styles from './DemoWorkspace.module.css'

// The sample hero visualizations reuse the live presentational components on
// static props; they load as their own chunk so the tour costs the entry
// bundle nothing.
const DemoViz = lazy(() => import('./DemoViz'))

/**
 * Static, route-aware product tour. No tenant data hook or mutation is mounted
 * below this boundary; the shared API client independently rejects live calls.
 */
export function DemoWorkspace() {
  const { pathname } = useLocation()
  const page = demoPageForPath(pathname)

  return (
    <section className={styles.workspace} aria-labelledby="demo-workspace-title">
      <header className={styles.header}>
        <p className={styles.kicker}>{page.kicker}</p>
        <div className={styles.titleRow}>
          <h1 id="demo-workspace-title">{page.title}</h1>
          <DemoDataBadge />
        </div>
        <p>{page.description}</p>
      </header>

      <div className={styles.scope}>
        <Badge tone="warning">Sample tenant · Default Tenant</Badge>
        <span>Fixed window · 09:30–09:45 UTC</span>
        <span>Read-only · no live writes, exports, or configuration changes</span>
      </div>

      <div className={styles.metrics}>
        {page.metrics.map((item) => (
          <Card className={styles.metricCard} key={item.label}>
            <CardBody className={styles.metricBody}>
              <div className={styles.metricHeading}>
                <span className={styles.metricLabel}>{item.label}</span>
                <DemoDataBadge />
              </div>
              <strong className={styles.metricValue}>{item.value}</strong>
              <Badge tone={item.tone}>{item.detail}</Badge>
            </CardBody>
          </Card>
        ))}
      </div>

      {page.viz ? (
        <Suspense fallback={<p className={styles.vizFallback}>Loading sample visualization…</p>}>
          <DemoViz spec={page.viz} />
        </Suspense>
      ) : null}

      <div className={styles.grid}>
        <DemoTablePanel model={page.primary} />
        <DemoTablePanel model={page.secondary} />
      </div>
    </section>
  )
}

function DemoTablePanel({ model }: { model: DemoTableModel }) {
  const columns = model.columns.map((header, index) => ({
    key: `column-${index}`,
    header,
    render: (item: DemoTableRow) => {
      const value = item.cells[index] ?? '—'
      return index === model.columns.length - 1 && item.tone ? (
        <Badge tone={item.tone}>{value}</Badge>
      ) : (
        value
      )
    },
  }))

  return (
    <Card>
      <CardHeader title={model.title} description={model.description} actions={<DemoDataBadge />} />
      <CardBody className={styles.tableBody}>
        <Table
          caption={`${model.title} demo data`}
          columns={columns}
          rows={model.rows}
          rowKey={(item) => item.id}
        />
      </CardBody>
    </Card>
  )
}
