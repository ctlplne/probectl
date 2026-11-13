// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ClientReportDefinition, ClientReportCapacityTarget } from '../api/dashboardReporting'
import { Button, Field, Select } from '../components'
import styles from './dashboards.module.css'

export function emptyMonthlyReport(): ClientReportDefinition {
  return { period: 'completed_month', timezone: 'UTC', capacity_targets: [] }
}

function emptyTarget(): ClientReportCapacityTarget {
  return {
    target: { kind: 'interface', context_id: '', interface_id: '' },
    direction: 'max_directional_percentiles',
    capacity_bps: '',
    maximum_poll_gap: '5m',
    forecast_months: 1,
    physical_bounds: [{ context_id: '', interface_id: '', max_bps: '' }],
  }
}

export function validMonthlyReport(value: ClientReportDefinition): boolean {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
  const positive = (text: string) =>
    /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(text) && /[1-9]/.test(text)
  if (!value.timezone?.trim() || (value.month && !/^[0-9]{4}-(?:0[1-9]|1[0-2])$/.test(value.month)))
    return false
  return value.capacity_targets.every((item) => {
    const target = item.target
    const knownTarget =
      target.kind === 'interface'
        ? uuid.test(target.context_id ?? '') && uuid.test(target.interface_id ?? '')
        : uuid.test(target.tag_id ?? '') && Boolean(target.tag_value)
    const months = item.forecast_months ?? 1
    const members = new Set(
      item.physical_bounds.map((bound) => `${bound.context_id}/${bound.interface_id}`),
    )
    return (
      knownTarget &&
      positive(item.capacity_bps) &&
      Boolean(item.maximum_poll_gap.trim()) &&
      Number.isSafeInteger(months) &&
      months > 0 &&
      item.physical_bounds.length > 0 &&
      members.size === item.physical_bounds.length &&
      item.physical_bounds.every(
        (bound) =>
          uuid.test(bound.context_id) &&
          uuid.test(bound.interface_id) &&
          /^[1-9][0-9]*$/.test(bound.max_bps),
      )
    )
  })
}

export function MonthlyClientReportEditor({
  value,
  onChange,
  disabled,
  canCapacity,
}: {
  value: ClientReportDefinition
  onChange: (value: ClientReportDefinition) => void
  disabled: boolean
  canCapacity: boolean
}) {
  function changeTarget(index: number, next: ClientReportCapacityTarget) {
    onChange({
      ...value,
      capacity_targets: value.capacity_targets.map((item, i) => (i === index ? next : item)),
    })
  }
  return (
    <section aria-label="Monthly client pack configuration" className={styles.monthlyEditor}>
      <p>
        Include availability and SLOs, incident verdicts, changes, capacity/runout and offline
        signed evidence. Every report checks current tenant and source access.
      </p>
      <div className={styles.reportingControls}>
        <Select
          label="Monthly report period"
          value={value.period ?? 'completed_month'}
          disabled={disabled}
          onChange={(event) =>
            onChange({
              ...value,
              period: event.target.value as ClientReportDefinition['period'],
              month: undefined,
            })
          }
          options={[
            { value: 'completed_month', label: 'Completed calendar month' },
            { value: 'month_to_date', label: 'Month to date · partial' },
          ]}
        />
        <Field
          label="Report month"
          type="month"
          disabled={disabled || value.period === 'month_to_date'}
          value={value.month ?? ''}
          hint="Leave empty for the previous complete month. Month-to-date uses the current month."
          onChange={(event) => onChange({ ...value, month: event.target.value || undefined })}
        />
        <Field
          label="Report timezone"
          value={value.timezone ?? 'UTC'}
          disabled={disabled}
          hint="IANA name, such as UTC, Europe/London or America/New_York."
          onChange={(event) => onChange({ ...value, timezone: event.target.value })}
        />
      </div>
      {value.period === 'month_to_date' && (
        <p role="status">
          Month-to-date is partial through generation time. It does not claim a complete calendar
          month.
        </p>
      )}
      <p>
        {value.capacity_targets.length
          ? `${value.capacity_targets.length} explicit capacity targets.`
          : 'Add a canonical target to include measured capacity and runout.'}{' '}
        Thresholds and physical bounds are operator assumptions; inventory speeds do not supply
        them.
      </p>
      {value.capacity_targets.map((item, index) => (
        <section
          key={index}
          aria-label={`Monthly capacity target ${index + 1}`}
          className={styles.monthlyTarget}
        >
          <h4>Capacity target {index + 1}</h4>
          <div className={styles.reportingControls}>
            <Select
              label={`Monthly target ${index + 1} kind`}
              disabled={disabled || !canCapacity}
              value={item.target.kind}
              onChange={(event) =>
                changeTarget(index, {
                  ...item,
                  target:
                    event.target.value === 'interface'
                      ? { kind: 'interface', context_id: '', interface_id: '' }
                      : { kind: 'circuit', tag_id: '', tag_value: '' },
                  physical_bounds: [{ context_id: '', interface_id: '', max_bps: '' }],
                })
              }
              options={[
                { value: 'interface', label: 'Canonical interface' },
                { value: 'circuit', label: 'Complete circuit tag' },
              ]}
            />
            {item.target.kind === 'interface' ? (
              <>
                <Field
                  label={`Monthly target ${index + 1} routing context ID`}
                  disabled={disabled || !canCapacity}
                  value={item.target.context_id ?? ''}
                  onChange={(event) =>
                    changeTarget(index, {
                      ...item,
                      target: { ...item.target, context_id: event.target.value },
                      physical_bounds: [
                        { ...item.physical_bounds[0], context_id: event.target.value },
                      ],
                    })
                  }
                />
                <Field
                  label={`Monthly target ${index + 1} canonical interface ID`}
                  disabled={disabled || !canCapacity}
                  value={item.target.interface_id ?? ''}
                  onChange={(event) =>
                    changeTarget(index, {
                      ...item,
                      target: { ...item.target, interface_id: event.target.value },
                      physical_bounds: [
                        { ...item.physical_bounds[0], interface_id: event.target.value },
                      ],
                    })
                  }
                />
              </>
            ) : (
              <>
                <Field
                  label={`Monthly target ${index + 1} circuit tag ID`}
                  disabled={disabled || !canCapacity}
                  value={item.target.tag_id ?? ''}
                  onChange={(event) =>
                    changeTarget(index, {
                      ...item,
                      target: { ...item.target, tag_id: event.target.value },
                    })
                  }
                />
                <Field
                  label={`Monthly target ${index + 1} complete circuit tag value`}
                  disabled={disabled || !canCapacity}
                  value={item.target.tag_value ?? ''}
                  onChange={(event) =>
                    changeTarget(index, {
                      ...item,
                      target: { ...item.target, tag_value: event.target.value },
                    })
                  }
                />
              </>
            )}
            <Field
              label={`Monthly target ${index + 1} threshold (bps)`}
              disabled={disabled || !canCapacity}
              inputMode="decimal"
              value={item.capacity_bps}
              onChange={(event) =>
                changeTarget(index, { ...item, capacity_bps: event.target.value })
              }
              hint="Exact positive decimal; separate from the physical upper bound."
            />
            <Field
              label={`Monthly target ${index + 1} maximum poll gap`}
              disabled={disabled || !canCapacity}
              value={item.maximum_poll_gap}
              onChange={(event) =>
                changeTarget(index, { ...item, maximum_poll_gap: event.target.value })
              }
            />
            <Field
              label={`Monthly target ${index + 1} forecast months`}
              disabled={disabled || !canCapacity}
              type="number"
              min="1"
              step="1"
              value={item.forecast_months ?? 1}
              onChange={(event) =>
                changeTarget(index, { ...item, forecast_months: Number(event.target.value) })
              }
            />
            <Select
              label={`Monthly target ${index + 1} direction`}
              disabled={disabled || !canCapacity}
              value={item.direction}
              onChange={(event) =>
                changeTarget(index, {
                  ...item,
                  direction: event.target.value as ClientReportCapacityTarget['direction'],
                })
              }
              options={[
                { value: 'in', label: 'Inbound' },
                { value: 'out', label: 'Outbound' },
                { value: 'max_directional_percentiles', label: 'Both directional percentiles' },
                { value: 'interval_max', label: 'Interval maximum' },
                { value: 'interval_sum', label: 'Interval sum' },
              ]}
            />
          </div>
          {item.physical_bounds.map((bound, member) => (
            <div
              key={member}
              className={styles.reportingControls}
              role="group"
              aria-label={`Monthly target ${index + 1} physical member ${member + 1}`}
            >
              {item.target.kind === 'circuit' && (
                <>
                  <Field
                    label={`Monthly target ${index + 1} member ${member + 1} context ID`}
                    disabled={disabled || !canCapacity}
                    value={bound.context_id}
                    onChange={(event) =>
                      changeTarget(index, {
                        ...item,
                        physical_bounds: item.physical_bounds.map((b, i) =>
                          i === member ? { ...b, context_id: event.target.value } : b,
                        ),
                      })
                    }
                  />
                  <Field
                    label={`Monthly target ${index + 1} member ${member + 1} interface ID`}
                    disabled={disabled || !canCapacity}
                    value={bound.interface_id}
                    onChange={(event) =>
                      changeTarget(index, {
                        ...item,
                        physical_bounds: item.physical_bounds.map((b, i) =>
                          i === member ? { ...b, interface_id: event.target.value } : b,
                        ),
                      })
                    }
                  />
                </>
              )}
              <Field
                label={`Monthly target ${index + 1} member ${member + 1} physical bound (bps)`}
                disabled={disabled || !canCapacity}
                inputMode="numeric"
                value={bound.max_bps}
                onChange={(event) =>
                  changeTarget(index, {
                    ...item,
                    physical_bounds: item.physical_bounds.map((b, i) =>
                      i === member ? { ...b, max_bps: event.target.value } : b,
                    ),
                  })
                }
              />
              {item.physical_bounds.length > 1 && (
                <Button
                  disabled={disabled || !canCapacity}
                  onClick={() =>
                    changeTarget(index, {
                      ...item,
                      physical_bounds: item.physical_bounds.filter((_, i) => i !== member),
                    })
                  }
                >
                  Remove monthly target {index + 1} member {member + 1}
                </Button>
              )}
            </div>
          ))}
          <div className={styles.reportActions}>
            {item.target.kind === 'circuit' && (
              <Button
                disabled={disabled || !canCapacity}
                onClick={() =>
                  changeTarget(index, {
                    ...item,
                    physical_bounds: [
                      ...item.physical_bounds,
                      { context_id: '', interface_id: '', max_bps: '' },
                    ],
                  })
                }
              >
                Add monthly target {index + 1} member
              </Button>
            )}
            <Button
              disabled={disabled}
              onClick={() =>
                onChange({
                  ...value,
                  capacity_targets: value.capacity_targets.filter((_, i) => i !== index),
                })
              }
            >
              Remove monthly capacity target {index + 1}
            </Button>
          </div>
        </section>
      ))}
      <Button
        disabled={disabled || !canCapacity}
        onClick={() =>
          onChange({ ...value, capacity_targets: [...value.capacity_targets, emptyTarget()] })
        }
      >
        Add monthly capacity target
      </Button>
      {!canCapacity && <p>Capacity configuration also requires current flow.read permission.</p>}
    </section>
  )
}
