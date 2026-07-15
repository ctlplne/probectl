// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
