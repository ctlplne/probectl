// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { Badge, Button } from '../components'
import { useDemoMode } from './useDemoMode'
import styles from './DemoModeBanner.module.css'

export function DemoModeBanner() {
  const { active, exit } = useDemoMode()
  if (!active) return null

  return (
    <aside className={styles.banner} aria-label="Demo mode is active">
      <Badge tone="warning">Demo mode · sample data</Badge>
      <span>Live tenant queries, exports, alerts, and incidents are disabled.</span>
      <Button variant="secondary" size="sm" onClick={exit} aria-keyshortcuts="Shift+D">
        Exit demo mode <kbd>Shift+D</kbd>
      </Button>
    </aside>
  )
}
