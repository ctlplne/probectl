// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { Button, Card, CardBody, EmptyState, ErrorState } from '../components'
import { useI18n } from '../i18n/useI18n'
import { NAV } from '../nav/ia'
import styles from './pages.module.css'

/** Page is the lightweight frame shared by lazy route chunks. Keeping it out
 * of TargetsPage prevents that feature's data/forms bundle from entering the
 * initial app-shell chunk. */
export function Page({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string
  subtitle?: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div>
          <h1 className={styles.title}>{title}</h1>
          {subtitle ? <p className={styles.subtitle}>{subtitle}</p> : null}
        </div>
        {actions ? <div className={styles.actions}>{actions}</div> : null}
      </header>
      {children}
    </div>
  )
}

/** PlaceholderPage stands in for an IA section until its sprint lands. */
export function PlaceholderPage({ to }: { to: string }) {
  const { t } = useI18n()
  const item = NAV.find((n) => n.to === to)
  const label = item ? t(item.labelKey) : t('page.generic')
  return (
    <Page title={label} subtitle={t('page.placeholder.subtitle')}>
      <Card>
        <CardBody>
          <EmptyState
            icon={item?.icon}
            title={t('page.placeholder.title', { label })}
            description={t('page.placeholder.description')}
          />
        </CardBody>
      </Card>
    </Page>
  )
}

export function NotFoundPage() {
  const { t } = useI18n()
  const navigate = useNavigate()
  return (
    <Page title={t('page.notFound.title')}>
      <Card>
        <CardBody>
          <ErrorState
            title={t('page.notFound.errorTitle')}
            description={t('page.notFound.description')}
            action={
              <Button variant="primary" onClick={() => navigate('/dashboards')}>
                {t('page.notFound.action')}
              </Button>
            }
          />
        </CardBody>
      </Card>
    </Page>
  )
}
