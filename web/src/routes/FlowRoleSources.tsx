// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import type { FlowExplorerResult } from '../api/flowExplorer'
import { useAuth } from '../auth/useAuth'
import { Button, ErrorState } from '../components'
import { flowRoleResultReadable } from './flowRoleSourcePolicy'
import styles from './flowExplorer.module.css'

export function FlowRoleSources({ result }: { result: FlowExplorerResult }) {
  const { tenant, permissions } = useAuth()
  const [after, setAfter] = useState(0)
  if (!flowRoleResultReadable(result, tenant.id, permissions))
    return (
      <ErrorState
        title="Interface role access changed"
        description="Run a fresh query with current access to this tenant and its source planes."
      />
    )
  if (!result.role_digest) return null
  const sources = result.role_sources ?? []
  const pageSize = 20 // presentation only; every source remains reachable
  const start = Math.min(after, Math.max(0, Math.ceil(sources.length / pageSize) - 1) * pageSize)
  const shown = sources.slice(start, start + pageSize)
  return (
    <details className={styles.roleSources}>
      <summary role="button">Interface role sources ({sources.length})</summary>
      <div className={styles.stack}>
        <p>
          Roles describe current evidence at query time. Unmatched interfaces remain other, with
          their traffic retained.
        </p>
        {!sources.length && <p>No current owned interface metadata matched this result.</p>}
        <ol start={start + 1}>
          {shown.map((source) => (
            <li
              key={`${source.context_id}:${source.exporter}:${source.protocol}:${source.obs_domain}:${source.if_index}`}
            >
              <strong>{source.role.replace(/_/g, ' ')}</strong>: {source.exporter} /{' '}
              {source.protocol} / domain {source.obs_domain} / interface {source.if_index}
              <dl className={styles.summary}>
                <div>
                  <dt>Context</dt>
                  <dd>{source.context_id}</dd>
                </div>
                <div>
                  <dt>Router</dt>
                  <dd>{source.router_id}</dd>
                </div>
                <div>
                  <dt>Canonical interface</dt>
                  <dd>{source.interface_id}</dd>
                </div>
                <div>
                  <dt>Reason</dt>
                  <dd>{source.reason.replace(/_/g, ' ')}</dd>
                </div>
                <div>
                  <dt>Evidence valid until</dt>
                  <dd>{source.valid_until}</dd>
                </div>
              </dl>
              <ul aria-label={`Sources for interface ${source.if_index}`}>
                {source.sources.map((reference) => (
                  <li key={reference}>{reference}</li>
                ))}
              </ul>
            </li>
          ))}
        </ol>
        {sources.length > pageSize && (
          <div className={styles.actions}>
            <Button disabled={start === 0} onClick={() => setAfter(Math.max(0, start - pageSize))}>
              Previous role sources
            </Button>
            <span role="status">
              Sources {start + 1}–{Math.min(start + pageSize, sources.length)} of {sources.length}
            </span>
            <Button
              disabled={start + pageSize >= sources.length}
              onClick={() => setAfter(start + pageSize)}
            >
              Next role sources
            </Button>
          </div>
        )}
      </div>
    </details>
  )
}
