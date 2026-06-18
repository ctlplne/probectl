import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import axe from 'axe-core'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { ComplianceResponse } from '../api/compliance'

/** S46 surface: segmentation verdicts + the never-overclaim coverage block. */

function fixture(): ComplianceResponse {
  return {
    compliance_running: true,
    items: [
      {
        policy: 'pci-segmentation',
        rule_id: 'corp-to-cde',
        from: 'corp',
        to: 'cde',
        ports: 'all ports',
        frameworks: { 'pci-dss': 'Req 1.3 — network segmentation of the CDE' },
        verdict: 'violation',
        violations: 2,
        observed_pairs: 2,
        samples: [
          {
            src: '10.20.1.5',
            dst: '10.10.2.9',
            dst_port: 443,
            bytes: 4096,
            source: 'flow',
            at: '2026-06-04T12:00:00Z',
          },
        ],
        first_violated: '2026-06-04T12:00:00Z',
        last_violated: '2026-06-04T12:01:00Z',
      },
      {
        policy: 'pci-segmentation',
        rule_id: 'dmz-to-cde-db',
        from: 'dmz',
        to: 'cde',
        ports: 'ports 3306,5432',
        verdict: 'observed_clean',
        violations: 0,
        observed_pairs: 5,
      },
      {
        policy: 'pci-segmentation',
        rule_id: 'guest-to-cde',
        from: 'guest',
        to: 'cde',
        ports: 'all ports',
        verdict: 'not_observed',
        violations: 0,
        observed_pairs: 0,
      },
    ],
    coverage: {
      flow_observed: true,
      ebpf_observed: false,
      observations: 7,
      zones_seen: 3,
      zones_total: 4,
      notes: [
        'no eBPF-plane (S20) flows observed — host-level traffic is invisible',
        '3 of 4 declared zones have observed endpoints — quiet zones are NOT proven isolated',
        'verdicts cover OBSERVED traffic only; absence of traffic is not proof of blocking',
      ],
    },
  }
}

function stubWith(resp: ComplianceResponse) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/v1/compliance')) return jsonResponse(resp)
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

describe('compliance / segmentation validation (S46)', () => {
  test('shows all three verdicts with framework tags and coverage caveats', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    renderApp('/compliance')

    const table = await screen.findByRole('table', {
      name: /segmentation verdicts/i,
    })
    expect(within(table).getByText('violation')).toBeInTheDocument()
    expect(within(table).getByText('observed clean')).toBeInTheDocument()
    // The honest verdict: never "compliant" for unobserved pairs.
    expect(within(table).getByText('not observed')).toBeInTheDocument()
    expect(within(table).queryByText(/^compliant$/i)).toBeNull()
    // PCI framework mapping rides the boundary.
    expect(within(table).getByText(/pci-dss: Req 1.3/)).toBeInTheDocument()

    // Coverage caveats are front and center.
    const note = screen.getByRole('note', { name: /coverage caveats/i })
    expect(within(note).getByText(/not proven isolated/i)).toBeInTheDocument()
    expect(within(note).getByText(/absence of traffic is not proof/i)).toBeInTheDocument()

    // Evidence download is offered.
    expect(screen.getByRole('button', { name: /download audit evidence/i })).toBeInTheDocument()
  })

  test('download evidence click uses exactly one version prefix', async () => {
    const assign = vi.fn()
    vi.stubGlobal('location', { assign, href: '', pathname: '/' })
    vi.stubGlobal('fetch', stubWith(fixture()))
    renderApp('/compliance')

    await userEvent.click(await screen.findByRole('button', { name: /download audit evidence/i }))

    expect(assign).toHaveBeenCalledWith('/v1/compliance/evidence')
  })

  test('honesty: unwired validator renders as not wired', async () => {
    vi.stubGlobal('fetch', stubWith({ compliance_running: false, items: [] }))
    renderApp('/compliance')
    expect(await screen.findByText(/compliance validator not wired/i)).toBeInTheDocument()
  })

  test('zero policies point at the policy dir', async () => {
    vi.stubGlobal('fetch', stubWith({ compliance_running: true, items: [] }))
    renderApp('/compliance')
    expect(await screen.findByText(/no policies declared/i)).toBeInTheDocument()
    expect(screen.getByText(/PROBECTL_COMPLIANCE_POLICY_DIR/)).toBeInTheDocument()
  })

  test('a11y: the compliance page passes the axe baseline', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    const { container } = renderApp('/compliance')
    await screen.findByRole('table', { name: /segmentation verdicts/i })
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    })
    expect(results.violations).toEqual([])
  })
})
