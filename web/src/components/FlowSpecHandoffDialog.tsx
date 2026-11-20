// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { ApiError } from '../api/client'
import { useFlowSpecHandoff, useWithdrawFlowSpec } from '../api/remediation'
import { DateTime } from '../time/DateTime'
import { Button, LoadingState, Modal } from './index'
import { FlowSpecProfileResult } from './FlowSpecRouterQualification'

export function FlowSpecHandoffDialog({
  id,
  identity,
  allowWithdraw,
  onClose,
}: {
  id: string
  identity: string
  allowWithdraw: boolean
  onClose: () => void
}) {
  const status = useFlowSpecHandoff(id, identity)
  const withdraw = useWithdrawFlowSpec(id, identity)
  const handoff = status.data
  return (
    <Modal
      open
      title="Approved FlowSpec handoff"
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          {handoff?.state === 'authorized' && allowWithdraw ? (
            <Button disabled={withdraw.isPending} onClick={() => withdraw.mutate()}>
              Withdraw handoff
            </Button>
          ) : null}
        </>
      }
    >
      {status.isPending ? <LoadingState label="Loading approved handoff" /> : null}
      {status.isError ? (
        <p role="alert">
          {status.error instanceof ApiError && status.error.status === 404
            ? 'This proposal was approved without a handoff.'
            : status.error.message}
        </p>
      ) : null}
      {withdraw.isError ? <p role="alert">{withdraw.error.message}</p> : null}
      {handoff ? (
        <>
          <dl>
            <dt>Authorization state</dt>
            <dd>
              <span role="status">
                {
                  {
                    authorized: 'Authorized',
                    withdrawal_requested: 'Withdrawal requested',
                    expired: 'Authorization expired',
                  }[handoff.state]
                }
              </span>
            </dd>
            <dt>Authorization expires</dt>
            <dd>
              <DateTime value={handoff.expires_at} />
            </dd>
            {handoff.withdraw_requested_at ? (
              <>
                <dt>Withdrawal requested at</dt>
                <dd>
                  <DateTime value={handoff.withdraw_requested_at} />
                </dd>
              </>
            ) : null}
          </dl>
          <FlowSpecProfileResult result={handoff.qualification} />
          <p>Confirm the rule’s removal at the receiver during the change process.</p>
        </>
      ) : null}
    </Modal>
  )
}
