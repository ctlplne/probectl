// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { RoutingChangeReference } from '../api/incidents'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'

/** Original references are read-only; a selected BGP route does not prove FIB state. */
export function RoutingChangeMetadata({ reference }: { reference: RoutingChangeReference }) {
  const { t } = useI18n()
  const selected = reference.view === 'loc_rib' || reference.view === 'operator_loc_rib'
  return (
    <section aria-label={t('changes.routing.title')}>
      <p>{t(selected ? 'changes.routing.selected' : 'changes.routing.advertised')}</p>
      <dl>
        <dt>{t('changes.routing.view')}</dt>
        <dd>{reference.view}</dd>
        <dt>{t('changes.routing.action')}</dt>
        <dd>{reference.action}</dd>
        <dt>{t('changes.routing.context')}</dt>
        <dd>{reference.context_id}</dd>
        <dt>{t('changes.routing.router')}</dt>
        <dd>{reference.router_id}</dd>
        <dt>{t('changes.routing.originalContext')}</dt>
        <dd>{reference.base_context_id}</dd>
        <dt>{t('changes.routing.originalRouter')}</dt>
        <dd>{reference.base_router_id}</dd>
        <dt>{t('changes.routing.observed')}</dt>
        <dd>
          <DateTime value={reference.observed_at} />
        </dd>
        <dt>{t('changes.routing.sequence')}</dt>
        <dd>{reference.sequence}</dd>
        <dt>{t('changes.routing.position')}</dt>
        <dd>{reference.update_index}</dd>
        <dt>{t('changes.routing.generation')}</dt>
        <dd>
          {reference.view_id} / {reference.generation}
        </dd>
        <dt>{t('changes.routing.path')}</dt>
        <dd>{reference.has_path_id ? reference.path_id : t('changes.routing.noPath')}</dd>
        <dt>{t('changes.routing.prior')}</dt>
        <dd>{t(reference.prior_present ? 'changes.routing.known' : 'changes.routing.unknown')}</dd>
        <dt>{t('changes.routing.changed')}</dt>
        <dd>{t(reference.path_changed ? 'changes.routing.yes' : 'changes.routing.no')}</dd>
        <dt>{t('changes.routing.attributes')}</dt>
        <dd>{t(reference.attributes_changed ? 'changes.routing.yes' : 'changes.routing.no')}</dd>
        <dt>{t('changes.routing.digest')}</dt>
        <dd>{reference.batch_digest}</dd>
      </dl>
    </section>
  )
}
