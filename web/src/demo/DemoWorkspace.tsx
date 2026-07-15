// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import {
  Card,
  CardBody,
  CardHeader,
  DashboardPreview,
  FirstRunPreview,
  PlanesPreview,
  TopologyPreview,
} from '../components'
import styles from './DemoWorkspace.module.css'

/** Static, non-exportable illustrations. No data hook is mounted below this boundary. */
export function DemoWorkspace() {
  return (
    <section className={styles.workspace} aria-labelledby="demo-workspace-title">
      <header className={styles.header}>
        <p className={styles.kicker}>Isolated product tour</p>
        <h1 id="demo-workspace-title">Sample network workspace</h1>
        <p>
          Every value on this screen is illustrative. It is not tenant telemetry and cannot produce
          exports, alerts, or incidents.
        </p>
      </header>
      <div className={styles.grid}>
        <Card>
          <CardHeader title="Synthetic first signal" description="Illustrative checks only" />
          <CardBody>
            <FirstRunPreview />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Path and topology" description="Illustrative graph only" />
          <CardBody>
            <TopologyPreview />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Cross-plane evidence" description="Illustrative signals only" />
          <CardBody>
            <PlanesPreview />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Operator summary" description="Illustrative metrics only" />
          <CardBody>
            <DashboardPreview />
          </CardBody>
        </Card>
      </div>
    </section>
  )
}
