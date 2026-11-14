// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { DeviceConfigVersion } from '../api/planes'
import { DateTime } from '../time/DateTime'

export function ConfigArchiveBinding({ config }: { config: DeviceConfigVersion }) {
  const binding = config.binding
  if (!binding) return <span>Unbound archive</span>
  return (
    <details>
      <summary>Operator-bound archive</summary>
      <p>Declared device association; device collection was not attested.</p>
      <dl>
        <dt>Routing context</dt>
        <dd>
          <code>{binding.context_id}</code>
        </dd>
        <dt>Canonical device</dt>
        <dd>
          <code>{binding.device_entity_id}</code>
        </dd>
        <dt>Configured source</dt>
        <dd>
          {binding.agent_id} · {binding.source_ref}
        </dd>
        <dt>Source assigned</dt>
        <dd>
          <DateTime value={binding.source_assigned_at} />
        </dd>
        <dt>Collector assigned</dt>
        <dd>
          <DateTime value={binding.agent_assigned_at} />
        </dd>
        <dt>Archive bound</dt>
        <dd>
          <DateTime value={binding.bound_at} />
        </dd>
      </dl>
    </details>
  )
}
