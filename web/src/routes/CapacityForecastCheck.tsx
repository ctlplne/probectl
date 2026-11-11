// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, apiFetch } from '../api/client'
import type {
  CapacityForecastInput,
  CapacityForecastMeasurement,
  CapacityRunoutInterval,
  CapacityPhysicalBound,
} from '../api/sdk.gen'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Select,
} from '../components'
import { CapacityMemberAssumptions } from './CapacityMemberAssumptions'
import styles from './flowExplorer.module.css'

function emptyForecast(): CapacityForecastInput {
  return {
    target: { kind: 'interface', context_id: '', interface_id: '' },
    from: '',
    to: '',
    until: '',
    direction: 'max_directional_percentiles',
    capacity_bps: '',
    maximum_poll_gap: '5m',
    physical_bounds: [{ context_id: '', interface_id: '', max_bps: '' }],
  }
}

export function CapacityForecastCheck() {
  const [input, setInput] = useState(emptyForecast)
  const [result, setResult] = useState<CapacityForecastMeasurement>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const lifetime = useRef({
    active: true,
    epoch: 0,
    request: undefined as AbortController | undefined,
  })
  useEffect(() => {
    const current = lifetime.current
    current.active = true
    return () => {
      current.active = false
      current.epoch++
      current.request?.abort()
    }
  }, [])
  useEffect(() => {
    if (!result) return
    const timer = window.setTimeout(
      () => {
        setResult(undefined)
        setError('Source validity window elapsed. Run a fresh forecast.')
      },
      Math.min(Math.max(0, Date.parse(result.source_valid_until) - Date.now()), 2147483647),
    )
    return () => window.clearTimeout(timer)
  }, [result])
  function change<K extends keyof CapacityForecastInput>(key: K, value: CapacityForecastInput[K]) {
    setResult(undefined)
    setInput((old) => ({ ...old, [key]: value }))
  }
  function changeBound(index: number, key: keyof CapacityPhysicalBound, value: string) {
    change(
      'physical_bounds',
      input.physical_bounds.map((bound, i) => (i === index ? { ...bound, [key]: value } : bound)),
    )
  }
  async function forecast(event: FormEvent) {
    event.preventDefault()
    const current = lifetime.current
    const epoch = ++current.epoch
    current.request?.abort()
    const request = new AbortController()
    current.request = request
    setResult(undefined)
    setError('')
    setBusy(true)
    try {
      const value = await apiFetch<CapacityForecastMeasurement>('/flows/capacity/forecast', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
        signal: request.signal,
      })
      if (current.active && current.epoch === epoch) setResult(value)
    } catch (cause) {
      if (current.active && current.epoch === epoch) {
        if (cause instanceof ApiError && (cause.status === 401 || cause.status === 403))
          setInput(emptyForecast())
        setError(cause instanceof Error ? cause.message : 'Current-source forecast is unavailable.')
      }
    } finally {
      if (current.active && current.epoch === epoch) setBusy(false)
    }
  }
  return (
    <Card data-capacity-forecast>
      <CardHeader
        title="Measured capacity forecast"
        description="Forecast from original counters without accessing financial terms. Choose a complete training window and explicit threshold and horizon."
      />
      <CardBody className={styles.stack}>
        {error && <ErrorState title="Forecast unavailable" description={error} />}
        {busy && <LoadingState label="Training complete current-source forecast" />}
        <form
          className={styles.stack}
          onSubmit={(event) => {
            void forecast(event)
          }}
        >
          <div className={styles.grid}>
            <Select
              label="Forecast target"
              disabled={busy}
              value={input.target.kind}
              options={[
                { value: 'interface', label: 'Interface' },
                { value: 'circuit', label: 'Tagged circuit' },
              ]}
              onChange={(event) =>
                change(
                  'target',
                  event.target.value === 'interface'
                    ? { kind: 'interface', context_id: '', interface_id: '' }
                    : { kind: 'circuit', tag_id: '', tag_value: '' },
                )
              }
            />
            {input.target.kind === 'interface' ? (
              <>
                <Field
                  label="Forecast routing context ID"
                  required
                  disabled={busy}
                  value={input.target.context_id ?? ''}
                  onChange={(event) =>
                    change('target', { ...input.target, context_id: event.target.value })
                  }
                />
                <Field
                  label="Forecast canonical interface ID"
                  required
                  disabled={busy}
                  value={input.target.interface_id ?? ''}
                  onChange={(event) =>
                    change('target', { ...input.target, interface_id: event.target.value })
                  }
                />
              </>
            ) : (
              <>
                <Field
                  label="Forecast circuit tag ID"
                  required
                  disabled={busy}
                  value={input.target.tag_id ?? ''}
                  onChange={(event) =>
                    change('target', { ...input.target, tag_id: event.target.value })
                  }
                />
                <Field
                  label="Forecast complete circuit tag value"
                  required
                  disabled={busy}
                  value={input.target.tag_value ?? ''}
                  onChange={(event) =>
                    change('target', { ...input.target, tag_value: event.target.value })
                  }
                />
              </>
            )}
            <Field
              label="Forecast training from"
              required
              disabled={busy}
              hint="Inclusive RFC3339 instant with timezone."
              value={input.from}
              onChange={(event) => change('from', event.target.value)}
            />
            <Field
              label="Forecast training to"
              required
              disabled={busy}
              hint="Exclusive RFC3339 instant; the complete window is preserved."
              value={input.to}
              onChange={(event) => change('to', event.target.value)}
            />
            <Field
              label="Forecast horizon"
              required
              disabled={busy}
              hint="RFC3339 instant later than training end."
              value={input.until}
              onChange={(event) => change('until', event.target.value)}
            />
            <Field
              label="Forecast threshold (bps)"
              required
              disabled={busy}
              inputMode="decimal"
              hint="Exact positive decimal; separate from physical counter bounds and financial commit."
              value={input.capacity_bps}
              onChange={(event) => change('capacity_bps', event.target.value)}
            />
            <Field
              label="Forecast maximum poll gap"
              required
              disabled={busy}
              value={input.maximum_poll_gap}
              onChange={(event) => change('maximum_poll_gap', event.target.value)}
            />
            <Select
              label="Forecast direction"
              disabled={busy}
              value={input.direction}
              options={[
                { value: 'in', label: 'Inbound' },
                { value: 'out', label: 'Outbound' },
                { value: 'max_directional_percentiles', label: 'Both directional forecasts' },
                { value: 'interval_max', label: 'Larger direction per interval' },
                { value: 'interval_sum', label: 'Sum directions per interval' },
              ]}
              onChange={(event) =>
                change('direction', event.target.value as CapacityForecastInput['direction'])
              }
            />
          </div>
          <p>
            The current complete member set is applied throughout training. Historical tag
            membership is not reconstructed. Enter a physical upper bound for every current member
            over the complete window.
          </p>
          {input.physical_bounds.map((bound, index) => (
            <div className={styles.stack} key={index}>
              <div className={styles.grid}>
                <Field
                  label={`Forecast member ${index + 1} routing context ID`}
                  required
                  disabled={busy}
                  value={bound.context_id}
                  onChange={(event) => changeBound(index, 'context_id', event.target.value)}
                />
                <Field
                  label={`Forecast member ${index + 1} interface ID`}
                  required
                  disabled={busy}
                  value={bound.interface_id}
                  onChange={(event) => changeBound(index, 'interface_id', event.target.value)}
                />
                <Field
                  label={`Forecast member ${index + 1} physical bound (bps)`}
                  required
                  disabled={busy}
                  inputMode="numeric"
                  value={bound.max_bps}
                  onChange={(event) => changeBound(index, 'max_bps', event.target.value)}
                />
              </div>
              {input.physical_bounds.length > 1 && (
                <Button
                  disabled={busy}
                  onClick={() =>
                    change(
                      'physical_bounds',
                      input.physical_bounds.filter((_, i) => i !== index),
                    )
                  }
                >
                  Remove forecast member {index + 1}
                </Button>
              )}
            </div>
          ))}
          <div className={styles.actions}>
            {input.target.kind === 'circuit' && (
              <Button
                disabled={busy}
                onClick={() =>
                  change('physical_bounds', [
                    ...input.physical_bounds,
                    { context_id: '', interface_id: '', max_bps: '' },
                  ])
                }
              >
                Add forecast member
              </Button>
            )}
            <Button type="submit" variant="primary" disabled={busy}>
              Forecast runout
            </Button>
          </div>
        </form>
        {result && <ForecastResult key={result.as_of} result={result} />}
      </CardBody>
    </Card>
  )
}

function interval(value: CapacityRunoutInterval) {
  return value.reached && value.from && value.to
    ? `${value.from} to ${value.to} (end exclusive)`
    : 'Not reached within the selected horizon'
}
function ForecastResult({ result }: { result: CapacityForecastMeasurement }) {
  return (
    <section aria-label="Measured forecast result" className={styles.stack}>
      <p>
        Authority checked at {result.as_of}; source validity upper bound {result.source_valid_until}
        ; maximum poll gap {result.maximum_poll_gap}. Current member set applied to the complete
        training window.
      </p>
      {result.forecasts.map((value) => (
        <div className={styles.stack} key={value.direction}>
          <h3>{value.direction} forecast</h3>
          <dl className={styles.summary}>
            {[
              ['Training window', `${value.from} to ${value.to} (end exclusive)`],
              ['Horizon', value.until],
              ['Model', value.model],
              ['Counter model', value.counter_model],
              ['Interval method', value.interval_method],
              ['Trained', value.trained ? 'Yes' : 'No'],
              ['Coverage complete', value.coverage_complete ? 'Yes' : 'No'],
              [
                'Expected / observed samples',
                `${value.expected_samples} / ${value.observed_samples}`,
              ],
              ['Reason', value.reason ?? 'None'],
              [
                'Threshold (bps, exact fraction)',
                `${value.capacity_numerator} / ${value.capacity_denominator}`,
              ],
              [
                'Trend (bps per day, exact fraction)',
                value.trend_bps_per_day_numerator !== undefined
                  ? `${value.trend_bps_per_day_numerator} / ${value.trend_bps_per_day_denominator}`
                  : 'Unavailable',
              ],
              ['Central runout', interval(value.central)],
              ['Earliest runout', interval(value.earliest)],
              ['Latest runout', interval(value.latest)],
              ['Observed exceedances', String(value.observed_exceedances)],
              [
                'Last sample',
                value.last_sample_known
                  ? value.last_sample_exceeded
                    ? 'At or above threshold'
                    : 'Below threshold'
                  : 'Unknown',
              ],
            ].map(([label, text]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{text}</dd>
              </div>
            ))}
          </dl>
        </div>
      ))}
      <p>
        Residual envelopes describe the training fit. They are not calibrated confidence
        probabilities; a horizon without a crossing has no invented future date.
      </p>
      <CapacityMemberAssumptions
        members={result.members}
        caption="Complete forecast member assumptions"
      />
      <details className={styles.completeResult}>
        <summary>Complete measured forecast JSON</summary>
        <pre tabIndex={0} aria-label="Complete measured forecast result">
          {JSON.stringify(result, null, 2)}
        </pre>
      </details>
    </section>
  )
}
