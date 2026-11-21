// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import {
  useDeviceSyslogPatterns,
  type DeviceSyslogPattern,
  type DeviceSyslogPatternKind,
} from '../api/planes'
import { formatInteger } from '../i18n/number'
import { type MessageKey } from '../i18n/messages'
import { useI18n } from '../i18n/useI18n'
import type { DeviceSyslogPatternFrequency } from '../api/sdk.gen'
import { DateTime } from '../time/DateTime'
import { Button } from './Button'
import { Card, CardBody, CardHeader } from './Card'
import { ErrorState, LoadingState } from './States'
import { Table, type Column } from './Table'

const patternNames: Record<DeviceSyslogPatternKind, MessageKey> = {
  other: 'device.syslog.pattern.other',
  link_down: 'device.syslog.pattern.link',
  bgp_neighbor_down: 'device.syslog.pattern.peer',
  power_supply_fault: 'device.syslog.pattern.supply',
}

const frequencyStates: Record<DeviceSyslogPatternFrequency['state'], MessageKey> = {
  unavailable: 'device.syslog.frequency.unavailable',
  warming: 'device.syslog.frequency.warming',
  within_band: 'device.syslog.frequency.normal',
  up: 'device.syslog.frequency.up',
  down: 'device.syslog.frequency.down',
}

function recentSyslogInterval() {
  const now = Date.now()
  return { from: new Date(now - 60 * 60 * 1000).toISOString(), to: new Date(now).toISOString() }
}

export function DeviceSyslogPatternsCard() {
  const { t, locale } = useI18n()
  const [interval, setInterval] = useState(recentSyslogInterval)
  const [selectedPattern, setSelectedPattern] = useState<string | null>(null)
  const query = useDeviceSyslogPatterns(interval.from, interval.to)
  const hour = 60 * 60 * 1000
  const completed = Math.floor(Date.parse(interval.to) / hour) * hour
  const frequencyFrom = new Date(completed - hour).toISOString()
  const frequencyTo = new Date(completed).toISOString()
  const frequencyQuery = useDeviceSyslogPatterns(frequencyFrom, frequencyTo, selectedPattern)
  const frequency = frequencyQuery.data?.frequency
  const page = query.data
  const columns: Column<DeviceSyslogPattern>[] = [
    {
      key: 'type',
      header: t('device.syslog.pattern.type'),
      render: (row) => t(patternNames[row.kind]),
    },
    {
      key: 'id',
      header: t('device.syslog.pattern.id'),
      render: (row) => (
        <code dir="ltr" title={row.id}>
          {row.id.slice(0, 12)}
        </code>
      ),
    },
    {
      key: 'count',
      header: t('device.syslog.pattern.count'),
      numeric: true,
      render: (row) => formatInteger(row.count, locale),
    },
    {
      key: 'first',
      header: t('device.syslog.pattern.first'),
      render: (row) => <DateTime value={row.first_at} />,
    },
    {
      key: 'last',
      header: t('device.syslog.pattern.last'),
      render: (row) => <DateTime value={row.last_at} />,
    },
    {
      key: 'frequency',
      header: t('device.syslog.frequency.column'),
      render: (row) => (
        <Button
          size="sm"
          aria-pressed={selectedPattern === row.id}
          onClick={() => setSelectedPattern(selectedPattern === row.id ? null : row.id)}
        >
          {t('device.syslog.frequency.compare')}
        </Button>
      ),
    },
  ]
  return (
    <Card>
      <CardHeader
        title={t('device.syslog.pattern.title')}
        description={t('device.syslog.pattern.hour')}
        actions={
          <Button onClick={() => setInterval(recentSyslogInterval())}>
            {t('device.syslog.pattern.refresh')}
          </Button>
        }
      />
      <CardBody>
        {query.isPending ? (
          <LoadingState label={t('device.syslog.pattern.loading')} />
        ) : query.isError ? (
          <ErrorState description={t('device.syslog.pattern.unavailable')} />
        ) : page ? (
          <>
            {page.unindexed_rows > 0 ? (
              <p className="mb-2 text-body text-muted-foreground">
                {t('device.syslog.pattern.unindexed', {
                  count: formatInteger(page.unindexed_rows, locale),
                })}
              </p>
            ) : null}
            <Table
              caption={t('device.syslog.pattern.title')}
              rows={page.patterns}
              columns={columns}
              rowKey={(row) => row.id}
              empty={t('device.syslog.pattern.empty')}
            />
            {selectedPattern ? (
              <section
                aria-label={t('device.syslog.frequency.column')}
                className="mt-4 space-y-2 text-body"
              >
                <p className="text-muted-foreground">
                  {t('device.syslog.frequency.interval')} <DateTime value={frequencyFrom} /> –{' '}
                  <DateTime value={frequencyTo} />
                </p>
                {frequencyQuery.isPending ? (
                  <LoadingState label={t('device.syslog.pattern.loading')} />
                ) : frequencyQuery.isError || !frequency ? (
                  <ErrorState description={t('device.syslog.pattern.unavailable')} />
                ) : (
                  <div role="status">
                    <p>{t(frequencyStates[frequency.state])}</p>
                    <p>
                      {t('device.syslog.frequency.weeks', {
                        count: formatInteger(frequency.comparable_weeks, locale),
                        required: formatInteger(frequency.required_weeks, locale),
                      })}
                    </p>
                    {frequency.band ? (
                      <p>
                        {t('device.syslog.frequency.band', {
                          count: frequency.band.current,
                          lower: frequency.band.lower,
                          upper: frequency.band.upper,
                        })}
                      </p>
                    ) : null}
                  </div>
                )}
              </section>
            ) : null}
          </>
        ) : null}
      </CardBody>
    </Card>
  )
}
