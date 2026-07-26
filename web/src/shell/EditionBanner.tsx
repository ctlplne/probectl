// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useEditions } from '../api/editions'
import { Badge, Button } from '../components'
import { useDemoMode } from '../demo/useDemoMode'
import { useI18n } from '../i18n/useI18n'
import styles from './EditionBanner.module.css'

/**
 * The banner the license ladder promises (internal/license: grace is "full
 * function + banner"). Renders ONLY in grace (countdown to read-only) or
 * read_only (quiet, factual) — community and active deployments never see a
 * pixel, keeping the hidden-unlicensed UX intact. Dismiss is session memory
 * only (guardrail 11: no browser storage) — a countdown you can permanently
 * silence isn't a countdown. Callers whose role can't read /editions get
 * nothing (the query errors quietly); demo mode never queries at all.
 */
export function EditionBanner() {
  const { active: demoMode } = useDemoMode()
  const { t } = useI18n()
  const navigate = useNavigate()
  const [dismissed, setDismissed] = useState(false)
  const editions = useEditions({ enabled: !demoMode })
  // api-error-covered: editions — this shell-only query is deliberately
  // fail-closed and invisible for role-restricted or unlicensed callers; the
  // Admin → Editions surface owns visible license diagnostics.

  const info = editions.data
  if (demoMode || dismissed || !info) return null
  if (info.state !== 'grace' && info.state !== 'read_only') return null

  const grace = info.state === 'grace'
  let message: string
  if (!grace) {
    message = t('edition.banner.readOnly')
  } else {
    const deadline = info.read_only_at ? Date.parse(info.read_only_at) : Number.NaN
    const days = Number.isFinite(deadline)
      ? Math.max(1, Math.ceil((deadline - Date.now()) / 86_400_000))
      : null
    message =
      days === null
        ? t('edition.banner.grace.nodate')
        : days === 1
          ? t('edition.banner.grace.one')
          : t('edition.banner.grace.many', { days: String(days) })
  }

  return (
    <aside
      className={grace ? styles.banner : `${styles.banner} ${styles.readOnly}`}
      aria-label={t('edition.banner.label')}
    >
      <Badge tone={grace ? 'warning' : 'danger'}>
        {grace ? t('edition.banner.badge.grace') : t('edition.banner.badge.readOnly')}
      </Badge>
      <span>{message}</span>
      <Button variant="secondary" size="sm" onClick={() => void navigate('/admin')}>
        {t('edition.banner.manage')}
      </Button>
      <Button variant="ghost" size="sm" onClick={() => setDismissed(true)}>
        {t('edition.banner.dismiss')}
      </Button>
    </aside>
  )
}
