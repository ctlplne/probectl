// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMemo, type ReactNode } from 'react'
import { useDeviceMetrics, type DeviceMetricSummary } from '../api/planes'
import { useI18n } from '../i18n/useI18n'
import {
  formatDecimal,
  formatDuration,
  formatInteger,
  formatPercentValue,
  formatScaledBytes,
  formatUnit,
} from '../i18n/number'
import { DateTime } from '../time/DateTime'
import { Badge } from './Badge'
import { Card, CardBody, CardHeader } from './Card'
import { EmptyState, ErrorState, LoadingState } from './States'
import { Table, type Column } from './Table'

// DPR-295: the Device page listed devices by name and never showed what they
// report. This card reads the tenant's newest sample of every device series
// (GET /v1/device/metrics, read back from the TSDB) and lays it out the way an
// operator reads a device: one row of health per device, one row per
// interface with its link state, speed and cumulative counters.

const metricPrefix = 'probectl_device_'

interface DeviceRow {
  key: string
  device: string
  deviceName?: string
  source?: string
  lastSeen: string
  values: Record<string, number>
}

interface InterfaceRow extends DeviceRow {
  ifIndex: number
  ifName: string
}

function newerOf(a: string, b: string): string {
  return Date.parse(b) > Date.parse(a) ? b : a
}

/** pivot groups the per-series samples into device and interface rows. */
function pivot(items: DeviceMetricSummary[]): { devices: DeviceRow[]; interfaces: InterfaceRow[] } {
  const devices = new Map<string, DeviceRow>()
  const interfaces = new Map<string, InterfaceRow>()
  for (const m of items) {
    const name = m.metric.startsWith(metricPrefix) ? m.metric.slice(metricPrefix.length) : m.metric
    const deviceKey = `${m.agent_id ?? ''}|${m.device}`
    const base = {
      device: m.device,
      deviceName: m.device_name || undefined,
      source: m.source,
      lastSeen: m.last_seen,
    }
    if (m.if_index || m.if_name) {
      const key = `${deviceKey}|${m.if_index ?? ''}|${m.if_name ?? ''}`
      const row = interfaces.get(key) ?? {
        ...base,
        key,
        ifIndex: Number(m.if_index ?? 0),
        ifName: m.if_name ?? '',
        values: {},
      }
      row.values[name] = m.value
      row.lastSeen = newerOf(row.lastSeen, m.last_seen)
      row.deviceName ??= base.deviceName
      interfaces.set(key, row)
    } else {
      const row = devices.get(deviceKey) ?? { ...base, key: deviceKey, values: {} }
      row.values[name] = m.value
      row.lastSeen = newerOf(row.lastSeen, m.last_seen)
      row.deviceName ??= base.deviceName
      devices.set(deviceKey, row)
    }
  }
  const byDevice = (a: DeviceRow, b: DeviceRow) =>
    (a.deviceName || a.device).localeCompare(b.deviceName || b.device) ||
    a.device.localeCompare(b.device)
  return {
    devices: [...devices.values()].sort(byDevice),
    interfaces: [...interfaces.values()].sort(
      (a, b) => byDevice(a, b) || a.ifIndex - b.ifIndex || a.ifName.localeCompare(b.ifName),
    ),
  }
}

export function DeviceMetricsCard() {
  const { locale, t } = useI18n()
  const metrics = useDeviceMetrics(500)
  const items = metrics.data?.items
  const { devices, interfaces } = useMemo(() => pivot(items ?? []), [items])
  const bounded =
    metrics.data !== undefined &&
    metrics.data.effective_limit > 0 &&
    metrics.data.items.length >= metrics.data.effective_limit

  const none = <span className="text-muted-foreground">{t('device.metrics.value.none')}</span>
  const count = (v: number | undefined): ReactNode =>
    v === undefined ? none : <span dir="ltr">{formatInteger(v, locale)}</span>
  const pair = (a: number | undefined, b: number | undefined): ReactNode =>
    a === undefined && b === undefined ? (
      none
    ) : (
      <span dir="ltr">
        {a === undefined ? '–' : formatInteger(a, locale)} /{' '}
        {b === undefined ? '–' : formatInteger(b, locale)}
      </span>
    )
  const deviceCell = (r: DeviceRow) => (
    <span>
      <strong>{r.deviceName || r.device}</strong>
      {r.deviceName ? <div className="text-caption text-muted-foreground">{r.device}</div> : null}
    </span>
  )
  const temperature = (r: InterfaceRow): string | null =>
    r.values.sensor_temperature_celsius === undefined
      ? null
      : `${formatDecimal(r.values.sensor_temperature_celsius, locale)} °C`
  const sensors = interfaces.filter((r) => temperature(r) !== null)
  const ports = interfaces.filter((r) => temperature(r) === null)

  const deviceColumns: Column<DeviceRow>[] = [
    { key: 'device', header: t('device.metrics.column.device'), render: deviceCell },
    {
      key: 'source',
      header: t('device.metrics.column.source'),
      render: (r) => <Badge tone="info">{(r.source || 'snmp').toUpperCase()}</Badge>,
    },
    {
      key: 'uptime',
      header: t('device.metrics.column.uptime'),
      numeric: true,
      render: (r) =>
        r.values.uptime_seconds === undefined
          ? none
          : formatDuration(r.values.uptime_seconds, locale),
    },
    {
      key: 'cpu',
      header: t('device.metrics.column.cpu'),
      numeric: true,
      render: (r) =>
        r.values.cpu_utilization === undefined
          ? none
          : formatPercentValue(r.values.cpu_utilization, locale),
    },
    {
      key: 'memory',
      header: t('device.metrics.column.memory'),
      numeric: true,
      render: (r) =>
        r.values.memory_used_bytes === undefined
          ? none
          : `${formatScaledBytes(r.values.memory_used_bytes, locale)} / ${formatScaledBytes(
              r.values.memory_total_bytes,
              locale,
            )}`,
    },
    {
      key: 'observed',
      header: t('device.metrics.column.observed'),
      render: (r) => <DateTime value={r.lastSeen} />,
    },
  ]

  const interfaceColumns: Column<InterfaceRow>[] = [
    { key: 'device', header: t('device.metrics.column.device'), render: deviceCell },
    {
      key: 'interface',
      header: t('device.metrics.column.interface'),
      render: (r) => r.ifName || t('device.metrics.value.ifIndex', { index: String(r.ifIndex) }),
    },
    {
      key: 'status',
      header: t('device.metrics.column.status'),
      render: (r) =>
        r.values.if_oper_status === undefined ? (
          none
        ) : r.values.if_oper_status === 1 ? (
          <Badge tone="success">{t('device.metrics.value.up')}</Badge>
        ) : (
          <Badge tone="warning">{t('device.metrics.value.down')}</Badge>
        ),
    },
    {
      key: 'speed',
      header: t('device.metrics.column.speed'),
      numeric: true,
      render: (r) =>
        r.values.if_speed_mbps === undefined
          ? none
          : formatUnit(r.values.if_speed_mbps, 'Mbps', locale, { maximumFractionDigits: 0 }),
    },
    {
      key: 'in',
      header: t('device.metrics.column.inOctets'),
      numeric: true,
      render: (r) => count(r.values.if_in_octets),
    },
    {
      key: 'out',
      header: t('device.metrics.column.outOctets'),
      numeric: true,
      render: (r) => count(r.values.if_out_octets),
    },
    {
      key: 'errors',
      header: t('device.metrics.column.errors'),
      numeric: true,
      render: (r) => pair(r.values.if_in_errors, r.values.if_out_errors),
    },
    {
      key: 'discards',
      header: t('device.metrics.column.discards'),
      numeric: true,
      render: (r) => pair(r.values.if_in_discards, r.values.if_out_discards),
    },
  ]

  const sensorColumns: Column<InterfaceRow>[] = [
    { key: 'device', header: t('device.metrics.column.device'), render: deviceCell },
    {
      key: 'sensor',
      header: t('device.metrics.column.sensor'),
      render: (r) => r.ifName || String(r.ifIndex),
    },
    {
      key: 'temperature',
      header: t('device.metrics.column.temperature'),
      numeric: true,
      render: (r) => temperature(r),
    },
  ]

  return (
    <Card>
      <CardHeader
        title={t('device.metrics.title')}
        description={t('device.metrics.description')}
        actions={bounded ? <Badge tone="warning">{t('device.metrics.truncated')}</Badge> : null}
      />
      <CardBody>
        {metrics.isPending ? (
          <LoadingState label={t('device.metrics.loading')} />
        ) : metrics.isError ? (
          <ErrorState description={t('device.metrics.error')} />
        ) : metrics.data?.metrics_running === false ? (
          <EmptyState
            title={t('device.metrics.unavailable.title')}
            description={t('device.metrics.unavailable.description')}
          />
        ) : devices.length === 0 && interfaces.length === 0 ? (
          <EmptyState
            title={t('device.metrics.empty.title')}
            description={t('device.metrics.empty.description')}
          />
        ) : (
          <div className="grid gap-4">
            <Table
              caption={t('device.metrics.devices.caption')}
              columns={deviceColumns}
              rows={devices}
              rowKey={(r) => r.key}
              empty={t('device.metrics.devices.empty')}
            />
            <Table
              caption={t('device.metrics.interfaces.caption')}
              columns={interfaceColumns}
              rows={ports}
              rowKey={(r) => r.key}
              empty={t('device.metrics.interfaces.empty')}
            />
            {sensors.length > 0 ? (
              <Table
                caption={t('device.metrics.sensors.caption')}
                columns={sensorColumns}
                rows={sensors}
                rowKey={(r) => r.key}
              />
            ) : null}
            <p className="text-caption text-muted-foreground">{t('device.metrics.series')}</p>
          </div>
        )}
      </CardBody>
    </Card>
  )
}
