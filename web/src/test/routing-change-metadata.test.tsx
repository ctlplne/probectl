// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { render, screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import { I18nProvider } from '../i18n/I18nProvider'
import { RoutingChangeMetadata } from '../routes/RoutingChangeMetadata'
import type { RoutingChangeReference } from '../api/incidents'

const original: RoutingChangeReference = {
  version: 1,
  context_id: 'primary-context',
  router_id: 'primary-router',
  base_context_id: 'primary-base',
  base_router_id: 'primary-origin',
  view_id: 'original-view',
  generation: 'original-generation',
  sequence: '9007199254740993',
  update_index: 3,
  batch_digest: 'a'.repeat(64),
  observed_at: '2026-11-14T01:02:03.123456789Z',
  view: 'loc_rib',
  action: 'selected_route_update',
  afi: 1,
  safi: 1,
  has_path_id: true,
  path_id: 0,
  prior_present: true,
  path_changed: true,
  attributes_changed: false,
}

test('owned routing metadata retains the original sequence and explains BGP coverage', () => {
  const view = (reference: RoutingChangeReference) => (
    <I18nProvider initialLocale="en">
      <RoutingChangeMetadata reference={reference} />
    </I18nProvider>
  )
  const rendered = render(view(original))
  expect(screen.getByText('9007199254740993')).toBeInTheDocument()
  expect(
    screen.getByText('Observed BGP-selected route; forwarding-table state is unverified.'),
  ).toBeInTheDocument()
  expect(screen.getByText('0')).toBeInTheDocument()
  expect(screen.getByText('primary-router')).toBeInTheDocument()
  rendered.rerender(
    view({
      ...original,
      context_id: 'paired-context',
      router_id: 'paired-router',
      view: 'adj_rib_in_pre_policy',
      action: 'announcement',
      has_path_id: false,
      prior_present: false,
    }),
  )
  expect(screen.queryByText('primary-router')).not.toBeInTheDocument()
  expect(screen.getByText('paired-router')).toBeInTheDocument()
  expect(
    screen.getByText(
      'Observed advertisement; selected-route and forwarding-table state are unverified.',
    ),
  ).toBeInTheDocument()
  expect(screen.getByText('Not present')).toBeInTheDocument()
  expect(screen.getByText('Unknown')).toBeInTheDocument()
})
