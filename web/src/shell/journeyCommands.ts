// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { IconName } from '../components/Icon'
import type { MessageKey } from '../i18n/messages'
import { parsePivotContext, pivotHref } from '../routes/pivotContext'

export type JourneyID = 'J1' | 'J2' | 'J3' | 'J4' | 'J5' | 'J6'

export type JourneyAvailability = 'always' | 'incident-open' | 'path-open' | 'topology-selected'

export interface JourneyPaletteCommand {
  id: string
  journey: JourneyID
  labelKey: MessageKey
  hintKey: MessageKey
  icon: IconName
  route: string
  extras?: Record<string, string>
  preserveQuery?: string[]
  carriesPivotContext: boolean
  availability: JourneyAvailability
  requiresWrite?: boolean
}

/**
 * Stable outcome vocabulary for the six rubric journeys. These definitions are
 * deliberately data, not JSX: the palette, keyboard tests, and generated human
 * reference all consume the same IDs instead of drifting independently.
 */
export const JOURNEY_PALETTE_COMMANDS: readonly JourneyPaletteCommand[] = [
  {
    id: 'journey:first-insight',
    journey: 'J1',
    labelKey: 'command.journey.firstInsight',
    hintKey: 'command.journey.firstInsightHint',
    icon: 'admin',
    route: '/onboarding',
    extras: { task: 'first-insight' },
    carriesPivotContext: false,
    availability: 'always',
    requiresWrite: true,
  },
  {
    id: 'journey:incident-rca',
    journey: 'J2',
    labelKey: 'command.journey.incidentRca',
    hintKey: 'command.journey.incidentRcaHint',
    icon: 'incidents',
    route: '/incidents',
    extras: { task: 'incident-rca' },
    preserveQuery: ['incident'],
    carriesPivotContext: true,
    availability: 'always',
  },
  {
    id: 'journey:incident-share',
    journey: 'J2',
    labelKey: 'command.journey.incidentShare',
    hintKey: 'command.journey.incidentShareHint',
    icon: 'incidents',
    route: '/incidents',
    extras: { task: 'incident-share' },
    preserveQuery: ['incident'],
    carriesPivotContext: true,
    availability: 'incident-open',
    requiresWrite: true,
  },
  {
    id: 'journey:explorer',
    journey: 'J3',
    labelKey: 'command.journey.explorer',
    hintKey: 'command.journey.explorerHint',
    icon: 'search',
    route: '/explore',
    extras: { task: 'canonical-questions' },
    carriesPivotContext: true,
    availability: 'always',
  },
  {
    id: 'journey:path-compare',
    journey: 'J4',
    labelKey: 'command.journey.pathCompare',
    hintKey: 'command.journey.pathCompareHint',
    icon: 'path',
    route: '/path',
    extras: { task: 'compare-rounds' },
    carriesPivotContext: true,
    availability: 'always',
  },
  {
    id: 'journey:path-share',
    journey: 'J4',
    labelKey: 'command.journey.pathShare',
    hintKey: 'command.journey.pathShareHint',
    icon: 'path',
    route: '/path',
    extras: { task: 'copy-stable-link' },
    carriesPivotContext: true,
    availability: 'path-open',
  },
  {
    id: 'journey:topology-simulate',
    journey: 'J4',
    labelKey: 'command.journey.topologySimulate',
    hintKey: 'command.journey.topologySimulateHint',
    icon: 'dashboards',
    route: '/topology',
    extras: { preview: 'blast', task: 'simulate-selected' },
    carriesPivotContext: true,
    availability: 'topology-selected',
  },
  {
    id: 'journey:fleet-health',
    journey: 'J5',
    labelKey: 'command.journey.fleetHealth',
    hintKey: 'command.journey.fleetHealthHint',
    icon: 'admin',
    route: '/admin',
    extras: { agent_health: 'needs_action', task: 'review-safe-action' },
    carriesPivotContext: false,
    availability: 'always',
  },
  {
    id: 'journey:provider-exceptions',
    journey: 'J6',
    labelKey: 'command.journey.providerExceptions',
    hintKey: 'command.journey.providerHint',
    icon: 'admin',
    route: '/provider#provider-exceptions',
    carriesPivotContext: false,
    availability: 'always',
  },
  {
    id: 'journey:provider-tenants',
    journey: 'J6',
    labelKey: 'command.journey.providerTenants',
    hintKey: 'command.journey.providerHint',
    icon: 'admin',
    route: '/provider#provider-tenants',
    carriesPivotContext: false,
    availability: 'always',
  },
  {
    id: 'journey:provider-usage',
    journey: 'J6',
    labelKey: 'command.journey.providerUsage',
    hintKey: 'command.journey.providerHint',
    icon: 'cost',
    route: '/provider#provider-usage',
    carriesPivotContext: false,
    availability: 'always',
  },
] as const

/**
 * Build a command destination from untrusted browser state. parsePivotContext
 * removes tenant keys and invalid references; pivotHref refreshes the bounded
 * expiry and serializes only the X3 allow-list.
 */
export function journeyCommandHref(
  spec: JourneyPaletteCommand,
  currentHref: string,
  now: Date = new Date(),
) {
  const current = new URL(currentHref, 'https://probectl.invalid')
  const parsed = parsePivotContext(current.searchParams, { now })
  const extras = { ...spec.extras }
  for (const key of spec.preserveQuery ?? []) {
    const value = current.searchParams.get(key)
    if (value) extras[key] = value
  }
  if (spec.carriesPivotContext) {
    return pivotHref(
      spec.route,
      {
        ...parsed.context,
        returnTo: `${current.pathname}${current.search}${current.hash}`,
      },
      extras,
      now,
    )
  }
  const destination = new URL(spec.route, 'https://probectl.invalid')
  for (const [key, value] of Object.entries(extras)) destination.searchParams.set(key, value)
  return `${destination.pathname}${destination.search}${destination.hash}`
}

export interface JourneyKeyboardAction {
  journey: JourneyID
  action: string
  shortcut: string
  result: string
}

/** Source for docs/ux/keyboard-command-reference.md. */
export const JOURNEY_KEYBOARD_ACTIONS: readonly JourneyKeyboardAction[] = [
  {
    journey: 'J1',
    action: 'Open the first-real-insight workflow',
    shortcut: 'Ctrl/⌘+K → Start first real insight → Enter',
    result: 'Guided onboarding opens without carrying a stale object selection.',
  },
  {
    journey: 'J1',
    action: 'Mint the one-time enrollment token',
    shortcut: 'Tab to Mint enrollment token → Enter',
    result: 'A human explicitly creates the short-lived enrollment credential.',
  },
  {
    journey: 'J1',
    action: 'Copy the tenant-bound agent command',
    shortcut: 'Tab to Copy command → Enter',
    result: 'The shell command is copied; secrets are not counted or echoed.',
  },
  {
    journey: 'J1',
    action: 'Create the default real test and open its finding',
    shortcut: 'Tab through native fields → Enter on Create test; Enter on the finding link',
    result: 'Producer health and the named first server finding are distinct receipts.',
  },
  {
    journey: 'J2',
    action: 'Open the incident RCA workspace',
    shortcut: 'Ctrl/⌘+K → Open incident RCA → Enter',
    result: 'Incident, absolute clock, filters, and authorized evidence stay in X3 context.',
  },
  {
    journey: 'J2',
    action: 'Select evidence and generate cited RCA',
    shortcut: 'Tab to evidence → Enter; Tab to Explain this view → Enter',
    result: 'The selected evidence and server-authored reasoning provenance remain visible.',
  },
  {
    journey: 'J2',
    action: 'Open the exact citation',
    shortcut: 'Tab to the citation → Enter',
    result: 'Focus moves to the cited, tenant-authorized evidence row.',
  },
  {
    journey: 'J2',
    action: 'Copy the fixed cited snapshot',
    shortcut: 'Ctrl/⌘+K → Share cited incident RCA → Enter',
    result: 'The copied URL contains only a random share artifact ID.',
  },
  {
    journey: 'J3',
    action: 'Open canonical Explorer',
    shortcut: 'Ctrl/⌘+K → Open canonical Explorer → Enter',
    result: 'The tenant-scoped grammar opens with the current safe clock and filters.',
  },
  {
    journey: 'J3',
    action: 'Answer each of ten taught questions',
    shortcut: 'Focus question → Enter; focus Run query → Enter (repeat 10×)',
    result: 'All ten answers use exact structured queries with zero typed query text.',
  },
  {
    journey: 'J4',
    action: 'Inspect the worst ECMP branch',
    shortcut: 'Tab to Inspect worst hop → Enter; Escape closes detail safely',
    result: 'The branch stays selected in X3 context after focus returns.',
  },
  {
    journey: 'J4',
    action: 'Compare immutable path rounds',
    shortcut: 'Ctrl/⌘+K → Compare path rounds → Enter; use native Compare with select',
    result: 'The exact-value table mirrors the visual path comparison.',
  },
  {
    journey: 'J4',
    action: 'Copy the stable path replay URL',
    shortcut: 'Ctrl/⌘+K → Copy stable path link → Enter',
    result: 'Rounds, clock, and branch survive; tenant identity is absent.',
  },
  {
    journey: 'J4',
    action: 'Simulate the selected topology node',
    shortcut: 'Select the graph or list node; Ctrl/⌘+K → Simulate selected topology node → Enter',
    result: 'Graph and list invoke the same observe-only blast-radius preview.',
  },
  {
    journey: 'J4',
    action: 'Open exact incident evidence',
    shortcut: 'Tab to Open incident evidence → Enter',
    result: 'The incident receives the same clock, rounds, and branch selection.',
  },
  {
    journey: 'J5',
    action: 'Filter the fleet to exceptions',
    shortcut: 'Ctrl/⌘+K → Review unhealthy fleet → Enter',
    result: 'Only tenant-scoped stale, skewed, or capability-gap agents remain.',
  },
  {
    journey: 'J5',
    action: 'Open the evidence-only safe action',
    shortcut: 'Tab to the recommended action → Enter; Escape closes and restores focus',
    result:
      'No update executes; human approval, health gates, rollback, RBAC, and audit stay visible.',
  },
  {
    journey: 'J6',
    action: 'Triage the highest-ranked fleet exception',
    shortcut: 'Alt+X; Tab to Triage exception → Enter',
    result: 'Metadata-only evidence opens without implicit tenant telemetry access.',
  },
  {
    journey: 'J6',
    action: 'Open tenant lifecycle and choose silo isolation',
    shortcut: 'Alt+T; use native Isolation model select',
    result: 'Isolation and residency are explicit before provisioning.',
  },
  {
    journey: 'J6',
    action: 'Enter residency, slug, and display name',
    shortcut: 'Tab through native fields and type the values',
    result: 'The provider request contains lifecycle metadata only.',
  },
  {
    journey: 'J6',
    action: 'Provision the tenant',
    shortcut: 'Tab to Provision → Enter',
    result: 'Expired licenses leave this control visibly read-only.',
  },
  {
    journey: 'J6',
    action: 'Export usage showback',
    shortcut: 'Alt+E',
    result: 'The provider-scoped CSV export opens directly after separate-plane authentication.',
  },
] as const

export function renderJourneyCommandReference(
  actions: readonly JourneyKeyboardAction[] = JOURNEY_KEYBOARD_ACTIONS,
): string {
  const lines = [
    '# Keyboard command reference',
    '',
    '<!-- Generated from web/src/shell/journeyCommands.ts; do not hand-edit. -->',
    '',
    'The command palette opens with `Ctrl+K` or `⌘K`. Commands preserve the safe X3 clock, filters, and authorized selection, but never encode `tenant_id`. Unavailable or unauthorized commands remain visible with a reason. Provider commands cross into the separately authenticated provider privilege domain.',
    '',
    '<!-- prettier-ignore -->',
    '| Journey | Action | Stable command / shortcut | Observable result |',
    '| --- | --- | --- | --- |',
  ]
  for (const action of actions) {
    lines.push(`| ${action.journey} | ${action.action} | ${action.shortcut} | ${action.result} |`)
  }
  lines.push(
    '',
    'Escape closes palettes and dialogs without committing an action. Dialog focus is trapped and restored. Path and topology visual selections have equivalent native table/list buttons. Tenant switching first navigates to a neutral onboarding route, clearing action parameters and object references before the new tenant session can be used.',
    '',
  )
  return lines.join('\n')
}
