// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
