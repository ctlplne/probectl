// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import type { CapacityBillMember } from '../api/sdk.gen'
import { Button, Table } from '../components'
import styles from './flowExplorer.module.css'

export function CapacityMemberAssumptions({
  members,
  caption = 'Complete bill member assumptions',
}: {
  members: CapacityBillMember[]
  caption?: string
}) {
  const [page, setPage] = useState(0)
  const pageSize = 100
  const rows = members.slice(page * pageSize, (page + 1) * pageSize)
  return (
    <div className={styles.stack}>
      <p>
        Physical assumptions: {members.length} members; showing{' '}
        {page * pageSize + (rows.length ? 1 : 0)}–{page * pageSize + rows.length}.
      </p>
      <Table
        caption={caption}
        rows={rows}
        rowKey={(member) => `${member.context_id}/${member.interface_id}`}
        columns={[
          { key: 'context', header: 'Routing context', render: (member) => member.context_id },
          {
            key: 'interface',
            header: 'Canonical interface',
            render: (member) => member.interface_id,
          },
          { key: 'device', header: 'Device', render: (member) => member.device_id },
          { key: 'index', header: 'Interface index', render: (member) => String(member.if_index) },
          {
            key: 'bound',
            header: 'Physical bound (bps)',
            render: (member) => member.physical_max_bps,
          },
          {
            key: 'birth',
            header: 'Observed not before',
            render: (member) => member.observed_not_before,
          },
        ]}
      />
      <div className={styles.actions}>
        <Button disabled={page === 0} onClick={() => setPage((old) => old - 1)}>
          Previous member assumptions
        </Button>
        <Button
          disabled={(page + 1) * pageSize >= members.length}
          onClick={() => setPage((old) => old + 1)}
        >
          Next member assumptions
        </Button>
      </div>
    </div>
  )
}
