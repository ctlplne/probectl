// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { Badge } from '../components'
import { useAuth } from '../auth/useAuth'
import { authorityPosture } from './authority'
import styles from './AuthorityBadge.module.css'

export function AuthorityBadge() {
  const { permissions } = useAuth()
  const posture = authorityPosture(permissions)

  return (
    <span
      role="status"
      className={styles.wrap}
      aria-label={`Authority posture: ${posture.label}`}
      title={posture.detail}
    >
      <Badge tone={posture.tone}>
        <span className={styles.long}>{posture.label}</span>
        <span className={styles.short} aria-hidden="true">
          {posture.short}
        </span>
      </Badge>
    </span>
  )
}
