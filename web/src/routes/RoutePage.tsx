// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { Button, Card, CardBody, EmptyState, ErrorState, PageHeader } from '../components'
import { useI18n } from '../i18n/useI18n'
import { NAV } from '../nav/ia'

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
  // Page delegates to PageHeader so every route shares one title hierarchy;
  // a route that wants the eyebrow or the technical-details layer can use
  // PageHeader directly instead of growing another prop here.
  return (
    <div className="mx-auto w-full max-w-content px-comfortable py-comfortable">
      <PageHeader title={title} description={subtitle} actions={actions} />
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
              <Button variant="primary" onClick={() => void navigate('/dashboards')}>
                {t('page.notFound.action')}
              </Button>
            }
          />
        </CardBody>
      </Card>
    </Page>
  )
}
