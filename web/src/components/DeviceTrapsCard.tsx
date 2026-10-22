// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useDeviceTraps, type DeviceTrap, type DeviceTrapVarBind } from '../api/planes'
import { useI18n } from '../i18n/useI18n'
import { formatInteger } from '../i18n/number'
import { DateTime } from '../time/DateTime'
import { Badge, type BadgeTone } from './Badge'
import { Card, CardBody, CardHeader } from './Card'
import { EmptyState, ErrorState, LoadingState } from './States'
import { Table, type Column } from './Table'

// D-60: the SNMP traps a tenant's device agents authenticated and the control
// plane stored (GET /v1/device/traps). Refused traps never reach this list:
// the agent counts them and drops them before the bus.

/** Header varbinds every SNMPv2 trap carries; they say nothing about the event. */
const HEADER_OIDS = new Set(['.1.3.6.1.2.1.1.3.0', '.1.3.6.1.6.3.1.1.4.1.0'])

/** Well-known IF-MIB columns, so a linkDown reads "ifIndex.2 = 2". */
const OID_NAMES: [string, string][] = [
  ['.1.3.6.1.2.1.2.2.1.1', 'ifIndex'],
  ['.1.3.6.1.2.1.2.2.1.2', 'ifDescr'],
  ['.1.3.6.1.2.1.2.2.1.7', 'ifAdminStatus'],
  ['.1.3.6.1.2.1.2.2.1.8', 'ifOperStatus'],
  ['.1.3.6.1.2.1.31.1.1.1.1', 'ifName'],
  ['.1.3.6.1.2.1.31.1.1.1.18', 'ifAlias'],
]

const KEY_VARBINDS = 3

function oidName(oid: string): string {
  for (const [prefix, name] of OID_NAMES) {
    if (oid === prefix) return name
    if (oid.startsWith(`${prefix}.`)) return `${name}${oid.slice(prefix.length)}`
  }
  return oid
}

function keyVarbinds(trap: DeviceTrap): DeviceTrapVarBind[] {
  return trap.varbinds.filter((vb) => !HEADER_OIDS.has(vb.oid))
}

function severityTone(severity: DeviceTrap['severity']): BadgeTone {
  if (severity === 'critical') return 'danger'
  if (severity === 'warning') return 'warning'
  return 'info'
}

function versionLabel(version: DeviceTrap['version']): string {
  return version === 'snmpv2c' ? 'SNMPv2c' : version === 'snmpv3' ? 'SNMPv3' : 'SNMPv1'
}

export function DeviceTrapsCard() {
  const { locale, t } = useI18n()
  const traps = useDeviceTraps(50)
  const rows = traps.data?.items ?? []

  const columns: Column<DeviceTrap>[] = [
    {
      key: 'received',
      header: t('device.traps.column.time'),
      render: (r) => <DateTime value={r.received_at} />,
    },
    {
      key: 'device',
      header: t('device.traps.column.device'),
      render: (r) => (
        <span>
          <strong dir="ltr">{r.device_address}</strong>
          <div className="text-caption text-muted-foreground">
            <code>{r.agent_id}</code>
          </div>
        </span>
      ),
    },
    {
      key: 'trap',
      header: t('device.traps.column.trap'),
      render: (r) => (
        <span>
          <Badge tone={severityTone(r.severity)}>
            {r.trap_name || t('device.traps.value.enterprise')}
          </Badge>
          <div className="text-caption text-muted-foreground">
            <code dir="ltr">{r.trap_oid}</code>
          </div>
        </span>
      ),
    },
    {
      key: 'varbinds',
      header: t('device.traps.column.varbinds'),
      render: (r) => {
        const binds = keyVarbinds(r)
        if (binds.length === 0) {
          return <span className="text-muted-foreground">{t('device.traps.value.noVarbinds')}</span>
        }
        const more = binds.length - KEY_VARBINDS + (r.varbinds_truncated ? 1 : 0)
        return (
          <ul className="m-0 list-none p-0">
            {binds.slice(0, KEY_VARBINDS).map((vb, i) => (
              <li key={`${vb.oid}:${i}`}>
                <code dir="ltr">
                  {oidName(vb.oid)} = {vb.value}
                </code>
              </li>
            ))}
            {more > 0 ? (
              <li className="text-caption text-muted-foreground">
                {t('device.traps.value.moreVarbinds', { count: formatInteger(more, locale) })}
              </li>
            ) : null}
          </ul>
        )
      },
    },
    {
      key: 'version',
      header: t('device.traps.column.version'),
      render: (r) => <Badge tone="info">{versionLabel(r.version)}</Badge>,
    },
  ]

  return (
    <Card>
      <CardHeader
        title={t('device.traps.title')}
        description={t('device.traps.description')}
        actions={
          traps.data?.truncated ? <Badge tone="warning">{t('device.traps.truncated')}</Badge> : null
        }
      />
      <CardBody>
        {traps.isPending ? (
          <LoadingState label={t('device.traps.loading')} />
        ) : traps.isError ? (
          <ErrorState description={t('device.traps.error')} />
        ) : traps.data?.collection_running === false ? (
          <EmptyState
            icon="admin"
            title={t('device.traps.unavailable.title')}
            description={t('device.traps.unavailable.description')}
          />
        ) : (
          <Table
            caption={t('device.traps.caption')}
            columns={columns}
            rows={rows}
            rowKey={(r) => r.id}
            empty={
              <EmptyState
                icon="admin"
                title={t('device.traps.empty.title')}
                description={t('device.traps.empty.description')}
              />
            }
          />
        )}
        {traps.data?.retention ? (
          <p className="mt-3 text-caption text-muted-foreground">
            {t('device.traps.retention', {
              days: formatInteger(traps.data.retention.retention_days, locale),
              max: formatInteger(traps.data.retention.max_per_tenant, locale),
            })}
          </p>
        ) : null}
      </CardBody>
    </Card>
  )
}
