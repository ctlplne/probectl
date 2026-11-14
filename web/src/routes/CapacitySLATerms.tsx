// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { CarrierSLACreditBand, CarrierSLARule, CarrierSLATerms } from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, Field, Select, Table } from '../components'
import styles from './flowExplorer.module.css'

const metricLabels: Record<string, string> = {
  availability: 'Availability ratio',
  loss: 'Packet loss ratio',
  latency_nanos: 'Latency in nanoseconds',
  repair_nanos: 'Repair time in nanoseconds',
}
const goalLabels: Record<string, string> = {
  at_least: 'At least',
  at_most: 'At most',
  greater_than: 'Strictly greater than',
  less_than: 'Strictly less than',
}

const basisOptions = [
  {
    value: 'original_execution_ratio',
    label: 'Successful complete probe executions / all complete executions',
  },
  {
    value: 'original_packet_ratio',
    label: 'Lost packets / all transmitted packets in complete executions',
  },
  { value: 'original_rtt_mean', label: 'Mean of original successful round trips' },
  { value: 'original_rtt_p95', label: '95th percentile of original successful round trips' },
  { value: 'original_failure_interval', label: 'Original measured failure-to-recovery interval' },
]
function newRule(): CarrierSLARule {
  return {
    id: '',
    metric: 'availability',
    basis: 'original_execution_ratio',
    good_when: 'at_least',
    threshold: '',
    credit_bands: [],
  }
}

export function CapacitySLAEditor({
  value,
  currency,
  disabled,
  onChange,
}: {
  value?: CarrierSLATerms | null
  currency: string
  disabled: boolean
  onChange: (next: CarrierSLATerms | undefined) => void
}) {
  if (!value)
    return (
      <Button
        type="button"
        disabled={disabled}
        onClick={() =>
          onChange({
            carrier: '',
            circuit_id: '',
            site: '',
            currency,
            monthly_charge: '',
            aggregation: 'maximum',
            credit_cap_ratio: '',
            rules: [],
          })
        }
      >
        Add carrier SLA terms
      </Button>
    )
  function changeRule(index: number, change: Partial<CarrierSLARule>) {
    if (value)
      onChange({
        ...value,
        rules: value.rules.map((rule, row) => (row === index ? { ...rule, ...change } : rule)),
      })
  }
  function changeBand(ruleIndex: number, bandIndex: number, change: Partial<CarrierSLACreditBand>) {
    if (!value) return
    const rule = value.rules[ruleIndex]
    changeRule(ruleIndex, {
      credit_bands: rule.credit_bands.map((band, row) =>
        row === bandIndex ? { ...band, ...change } : band,
      ),
    })
  }
  return (
    <Card>
      <CardHeader
        title="Carrier SLA terms · preview"
        description="Record the actual operator contract. Missing measurements never establish a credit, and no claim is submitted automatically."
      />
      <CardBody className={styles.stack}>
        <div className={styles.grid}>
          <Field
            label="SLA carrier"
            required
            disabled={disabled}
            value={value.carrier}
            onChange={(event) => onChange({ ...value, carrier: event.target.value })}
          />
          <Field
            label="Carrier circuit ID"
            required
            disabled={disabled}
            value={value.circuit_id}
            onChange={(event) => onChange({ ...value, circuit_id: event.target.value })}
          />
          <Field
            label="Circuit site"
            disabled={disabled}
            value={value.site ?? ''}
            onChange={(event) => onChange({ ...value, site: event.target.value })}
          />
          <Field
            label="SLA currency"
            required
            disabled={disabled}
            value={value.currency}
            onChange={(event) => onChange({ ...value, currency: event.target.value })}
          />
          <Field
            label="Monthly recurring charge"
            required
            disabled={disabled}
            inputMode="decimal"
            value={value.monthly_charge}
            onChange={(event) => onChange({ ...value, monthly_charge: event.target.value })}
          />
          <Field
            label="Contract credit cap (ratio of monthly charge)"
            required
            disabled={disabled}
            inputMode="decimal"
            value={value.credit_cap_ratio}
            onChange={(event) => onChange({ ...value, credit_cap_ratio: event.target.value })}
          />
          <Select
            label="Contract credit aggregation"
            disabled={disabled}
            value={value.aggregation}
            options={[
              { value: 'maximum', label: 'Largest qualifying credit' },
              { value: 'sum_capped', label: 'Sum qualifying credits, then apply the contract cap' },
            ]}
            onChange={(event) =>
              onChange({
                ...value,
                aggregation: event.target.value as CarrierSLATerms['aggregation'],
              })
            }
          />
        </div>
        <p>
          Availability and loss are ratios from zero to one. Latency and repair thresholds use exact
          nanoseconds. Credit ratios and caps come from your contract; they can be zero or exceed
          one monthly charge.
        </p>
        <h3>Probes that measure this circuit</h3>
        <p>
          Choose explicit test and agent identities. Missing or retired sources leave coverage
          unknown.
        </p>
        {(value.sources ?? []).map((source, index) => (
          <div key={index} className={styles.grid}>
            <Field
              label={`Circuit probe ${index + 1} test ID`}
              required
              disabled={disabled}
              value={source.test_id}
              onChange={(event) =>
                onChange({
                  ...value,
                  sources: (value.sources ?? []).map((item, row) =>
                    row === index ? { ...item, test_id: event.target.value } : item,
                  ),
                })
              }
            />
            <Field
              label={`Circuit probe ${index + 1} agent ID`}
              required
              disabled={disabled}
              value={source.agent_id}
              onChange={(event) =>
                onChange({
                  ...value,
                  sources: (value.sources ?? []).map((item, row) =>
                    row === index ? { ...item, agent_id: event.target.value } : item,
                  ),
                })
              }
            />
            <Button
              type="button"
              disabled={disabled}
              onClick={() =>
                onChange({
                  ...value,
                  sources: (value.sources ?? []).filter((_, row) => row !== index),
                })
              }
            >
              Remove circuit probe {index + 1}
            </Button>
          </div>
        ))}
        <Button
          type="button"
          disabled={disabled}
          onClick={() =>
            onChange({
              ...value,
              sources: [...(value.sources ?? []), { agent_id: '', test_id: '' }],
            })
          }
        >
          Link circuit probe
        </Button>
        {value.rules.map((rule, index) => (
          <Card key={index}>
            <CardHeader title={`SLA clause ${index + 1}`} />
            <CardBody className={styles.stack}>
              <div className={styles.grid}>
                <Field
                  label={`Clause ${index + 1} reference`}
                  required
                  disabled={disabled}
                  value={rule.id}
                  onChange={(event) => changeRule(index, { id: event.target.value })}
                />
                <Select
                  label={`Clause ${index + 1} metric`}
                  disabled={disabled}
                  value={rule.metric}
                  options={[
                    { value: 'availability', label: 'Availability' },
                    { value: 'loss', label: 'Packet loss' },
                    { value: 'latency_nanos', label: 'Latency' },
                    { value: 'repair_nanos', label: 'Time to repair' },
                  ]}
                  onChange={(event) =>
                    changeRule(index, { metric: event.target.value as CarrierSLARule['metric'] })
                  }
                />
                <Select
                  label={`Clause ${index + 1} measurement basis`}
                  disabled={disabled}
                  value={rule.basis}
                  options={[
                    ...(!basisOptions.some((option) => option.value === rule.basis)
                      ? [{ value: rule.basis, label: `Recorded basis: ${rule.basis}` }]
                      : []),
                    ...basisOptions,
                  ]}
                  onChange={(event) => changeRule(index, { basis: event.target.value })}
                />
                <Select
                  label={`Clause ${index + 1} meets the SLA when`}
                  disabled={disabled}
                  value={rule.good_when}
                  options={[
                    { value: 'at_least', label: 'At least the threshold' },
                    { value: 'at_most', label: 'At most the threshold' },
                    { value: 'greater_than', label: 'Strictly greater than the threshold' },
                    { value: 'less_than', label: 'Strictly less than the threshold' },
                  ]}
                  onChange={(event) =>
                    changeRule(index, {
                      good_when: event.target.value as CarrierSLARule['good_when'],
                    })
                  }
                />
                <Field
                  label={`Clause ${index + 1} threshold`}
                  required
                  disabled={disabled}
                  value={rule.threshold}
                  onChange={(event) => changeRule(index, { threshold: event.target.value })}
                />
              </div>
              {rule.credit_bands.map((band, bandIndex) => (
                <div key={bandIndex} className={styles.grid}>
                  <Field
                    label={`Clause ${index + 1}, band ${bandIndex + 1} measured from (inclusive)`}
                    required
                    disabled={disabled}
                    value={band.from_inclusive}
                    onChange={(event) =>
                      changeBand(index, bandIndex, { from_inclusive: event.target.value })
                    }
                  />
                  <Field
                    label={`Clause ${index + 1}, band ${bandIndex + 1} measured to (exclusive)`}
                    hint="Leave empty for no upper boundary."
                    disabled={disabled}
                    value={band.to_exclusive ?? ''}
                    onChange={(event) =>
                      changeBand(index, bandIndex, { to_exclusive: event.target.value })
                    }
                  />
                  <Field
                    label={`Clause ${index + 1}, band ${bandIndex + 1} credit ratio`}
                    required
                    disabled={disabled}
                    inputMode="decimal"
                    value={band.credit_ratio}
                    onChange={(event) =>
                      changeBand(index, bandIndex, { credit_ratio: event.target.value })
                    }
                  />
                  <Button
                    type="button"
                    disabled={disabled}
                    onClick={() =>
                      changeRule(index, {
                        credit_bands: rule.credit_bands.filter((_, row) => row !== bandIndex),
                      })
                    }
                  >
                    Remove band {bandIndex + 1} from clause {index + 1}
                  </Button>
                </div>
              ))}
              <div className={styles.actions}>
                <Button
                  type="button"
                  disabled={disabled}
                  onClick={() =>
                    changeRule(index, {
                      credit_bands: [
                        ...rule.credit_bands,
                        { from_inclusive: '', credit_ratio: '' },
                      ],
                    })
                  }
                >
                  Add credit band to clause {index + 1}
                </Button>
                <Button
                  type="button"
                  disabled={disabled}
                  onClick={() =>
                    onChange({ ...value, rules: value.rules.filter((_, row) => row !== index) })
                  }
                >
                  Remove clause {index + 1}
                </Button>
              </div>
            </CardBody>
          </Card>
        ))}
        <div className={styles.actions}>
          <Button
            type="button"
            disabled={disabled}
            onClick={() => onChange({ ...value, rules: [...value.rules, newRule()] })}
          >
            Add SLA clause
          </Button>
          <Button type="button" disabled={disabled} onClick={() => onChange(undefined)}>
            Remove SLA from this revision
          </Button>
        </div>
      </CardBody>
    </Card>
  )
}

export function CapacitySLATermsView({ value }: { value: CarrierSLATerms }) {
  return (
    <div className={styles.stack}>
      <p>
        Carrier {value.carrier}; circuit {value.circuit_id}; site {value.site || 'unspecified'}.
      </p>
      <p>
        Recurring charge {value.monthly_charge} {value.currency}; credit cap{' '}
        {value.credit_cap_ratio}; aggregation{' '}
        {value.aggregation === 'maximum' ? 'largest qualifying credit' : 'sum then cap'}.
      </p>
      <Table
        caption="Recorded circuit probes"
        rows={value.sources ?? []}
        rowKey={(source) => `${source.agent_id}/${source.test_id}`}
        columns={[
          { key: 'test', header: 'Configured test', render: (source) => source.test_id },
          { key: 'agent', header: 'Agent', render: (source) => source.agent_id },
        ]}
        empty={<p>No circuit probes are linked; measurement coverage is unknown.</p>}
      />
      <Table
        caption="Recorded SLA clauses"
        rows={value.rules}
        rowKey={(rule) => rule.id}
        columns={[
          { key: 'clause', header: 'Clause', render: (rule) => rule.id },
          {
            key: 'metric',
            header: 'Metric and basis',
            render: (rule) =>
              `${metricLabels[rule.metric] ?? rule.metric} / ${basisOptions.find((option) => option.value === rule.basis)?.label ?? rule.basis}`,
          },
          {
            key: 'threshold',
            header: 'Meets the SLA',
            render: (rule) => `${goalLabels[rule.good_when] ?? rule.good_when} ${rule.threshold}`,
          },
          {
            key: 'credits',
            header: 'Contract credit bands',
            render: (rule) => (
              <ul>
                {rule.credit_bands.map((band, index) => (
                  <li key={index}>
                    {band.from_inclusive} inclusive to {band.to_exclusive ?? 'no upper boundary'}{' '}
                    exclusive: {band.credit_ratio} of recurring charge
                  </li>
                ))}
              </ul>
            ),
          },
        ]}
      />
    </div>
  )
}
