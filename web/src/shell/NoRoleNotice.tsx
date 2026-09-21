// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { Badge } from '../components'
import { useAuth } from '../auth/useAuth'
import { useDemoMode } from '../demo/useDemoMode'
import { useI18n } from '../i18n/useI18n'
import styles from './NoRoleNotice.module.css'

/**
 * DPR-016: a freshly provisioned SSO user holds no role (deny-by-default), so
 * every screen degrades to "unavailable" independently. Say it once, at the
 * top, and name the way out: a tenant admin grants a role, or on a brand-new
 * deployment the operator runs `probectl-control bootstrap-admin`.
 */
export function NoRoleNotice() {
  const { permissions, user } = useAuth()
  const { active: demoMode } = useDemoMode()
  const { t } = useI18n()
  if (demoMode || permissions.length > 0) return null
  return (
    <div role="status" aria-label={t('norole.label')} className={styles.notice}>
      <Badge tone="warning">{t('norole.badge')}</Badge>
      <span>
        {t('norole.message', { email: user.email })}{' '}
        <code className={styles.command}>probectl-control bootstrap-admin -email {user.email}</code>
      </span>
    </div>
  )
}
