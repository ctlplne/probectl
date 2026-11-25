// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState } from 'react'
import {
  useApproveRoutingTransfer,
  useDecideRemediation,
  useRequestRoutingTransferWithdrawal,
  useRoutingTransferReview,
  useRoutingTransferRollback,
  type Proposal,
} from '../api/remediation'
import type { RoutingTransferDryRun } from '../api/sdk.gen'
import { DateTime } from '../time/DateTime'
import { Button } from './Button'
import { Modal } from './Modal'
import { LoadingState } from './States'

export function RoutingTransferPolicyEvidence({ preview }: { preview: RoutingTransferDryRun }) {
  return (
    <>
      <dl aria-label="Routing transfer policy evidence">
        <dt>Destination prefix</dt>
        <dd>{preview.exact_prefix}</dd>
        <dt>Candidate BGP peer</dt>
        <dd>
          {preview.candidate_peer} (AS{preview.candidate_asn})
        </dd>
        <dt>Router archive</dt>
        <dd>{preview.archive_id}</dd>
        <dt>Peak moved</dt>
        <dd>{preview.moved_peak_bps} bps</dd>
        <dt>Candidate peak and limit</dt>
        <dd>
          {preview.candidate_peak_bps} / {preview.candidate_limit_bps} bps
        </dd>
        <dt>Address upper bound and limit</dt>
        <dd>
          {preview.address_count_upper_bound} / {preview.address_limit}
        </dd>
      </dl>
      {preview.requires_weight_verification && (
        <p role="status">Verify the current best-path weight before approval.</p>
      )}
      <details open>
        <summary>Proposed configuration</summary>
        <pre aria-label="Proposed configuration">{preview.configure.join('\n')}</pre>
      </details>
      <details>
        <summary>Rollback configuration</summary>
        <pre aria-label="Rollback configuration">{preview.withdraw.join('\n')}</pre>
      </details>
    </>
  )
}

export function RoutingTransferReviewDialog({
  proposal,
  identity,
  canDecide,
  canReadReview,
  canReadRollback,
  approvalsEnabled,
  onClose,
}: {
  proposal: Proposal
  identity: string
  canDecide: boolean
  canReadReview: boolean
  canReadRollback: boolean
  approvalsEnabled: boolean
  onClose: () => void
}) {
  const review = useRoutingTransferReview(proposal.id, identity, canReadReview)
  const approve = useApproveRoutingTransfer()
  const reject = useDecideRemediation()
  const withdraw = useRequestRoutingTransferWithdrawal()
  const approved = proposal.state === 'approved' || approve.isSuccess
  const rollbackRead = useRoutingTransferRollback(
    proposal.id,
    identity,
    approved && canReadRollback,
  )
  const rollback = rollbackRead.isError ? undefined : (withdraw.data ?? rollbackRead.data)
  const [expiredDeadline, setExpiredDeadline] = useState<number>()
  const deadline = Date.parse(review.data?.valid_until ?? rollback?.approval_expires_at ?? '')
  useEffect(() => {
    if (!Number.isFinite(deadline)) return
    const timer = window.setTimeout(
      () => setExpiredDeadline(deadline),
      Math.max(0, deadline - Date.now()),
    )
    return () => window.clearTimeout(timer)
  }, [deadline])
  const hasDeadline = Number.isFinite(deadline)
  const expired = hasDeadline && (expiredDeadline === deadline || deadline <= Date.now())
  const rollbackExpired =
    rollback &&
    (rollback.state === 'approval_expired' ||
      Date.parse(rollback.approval_expires_at) <= Date.now())
  const current =
    review.isSuccess &&
    !review.isFetching &&
    hasDeadline &&
    !expired &&
    rollback?.state !== 'withdrawal_requested'
      ? review.data
      : undefined
  const pending = approve.isPending || reject.isPending || withdraw.isPending
  const proposed = proposal.state === 'proposed' && !current?.decision && !approve.isSuccess
  const mayApprove = Boolean(
    canDecide &&
    approvalsEnabled &&
    proposed &&
    current &&
    !current.preview.requires_weight_verification,
  )
  const error =
    approve.error ??
    reject.error ??
    withdraw.error ??
    rollbackRead.error ??
    (rollback ? null : review.error)

  return (
    <Modal
      open
      onClose={onClose}
      title="Review routing transfer"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          {canDecide && proposed && (
            <>
              <Button
                variant="ghost"
                disabled={pending}
                onClick={() =>
                  reject.mutate({ id: proposal.id, decision: 'reject' }, { onSuccess: onClose })
                }
              >
                Reject
              </Button>
              <Button
                disabled={!mayApprove || pending}
                onClick={() => {
                  if (mayApprove && current && deadline > Date.now()) {
                    approve.mutate({
                      id: proposal.id,
                      input: { fingerprint: current.fingerprint },
                    })
                  }
                }}
              >
                Approve routing transfer
              </Button>
            </>
          )}
          {canDecide && rollback && rollback.state !== 'withdrawal_requested' && (
            <Button
              variant="ghost"
              disabled={pending}
              onClick={() =>
                withdraw.mutate({
                  id: proposal.id,
                  input: { review_fingerprint: rollback.review_fingerprint },
                })
              }
            >
              Request withdrawal
            </Button>
          )}
        </>
      }
    >
      {canReadReview && review.isPending && (
        <LoadingState label="Loading routing transfer review" />
      )}
      {error && <p role="alert">{error.message}</p>}
      {expired && !approved && !review.isError && (
        <p role="status">This review expired. Run a fresh estimate.</p>
      )}
      {approved && rollbackRead.isFetching && !rollback && (
        <LoadingState label="Loading approved rollback" />
      )}
      {current && (
        <>
          <dl>
            <dt>Declared peak limit</dt>
            <dd>{current.max_moved_bps} bps</dd>
            <dt>Valid until</dt>
            <dd>
              <DateTime value={current.valid_until} />
            </dd>
            {current.decision && (
              <>
                <dt>Approved by</dt>
                <dd>{current.decision.approved_by}</dd>
                <dt>Approved at</dt>
                <dd>
                  <DateTime value={current.decision.approved_at} />
                </dd>
              </>
            )}
          </dl>
          <RoutingTransferPolicyEvidence preview={current.preview} />
          {current.decision && <p>Apply the approved policy through your router change process.</p>}
        </>
      )}
      {rollback && !current && (
        <section aria-label="Approved routing rollback">
          <p role="status">
            {rollback.state === 'withdrawal_requested'
              ? 'Withdrawal requested. Restore the prior policy through your router change process.'
              : rollbackExpired
                ? 'Approval expired. Restore the prior policy if the transfer is active.'
                : 'The saved rollback is available through your router change process.'}
          </p>
          <dl>
            <dt>Router</dt>
            <dd>{rollback.router_id}</dd>
            <dt>Destination prefix</dt>
            <dd>{rollback.exact_prefix}</dd>
            <dt>Current attachment to replace</dt>
            <dd>{rollback.remove_policy}</dd>
            <dt>Previous attachment to restore</dt>
            <dd>{rollback.restore_policy}</dd>
            <dt>Approval deadline</dt>
            <dd>
              <DateTime value={rollback.approval_expires_at} />
            </dd>
          </dl>
          <details>
            <summary>Rollback configuration</summary>
            <pre aria-label="Approved rollback configuration">{rollback.withdraw.join('\n')}</pre>
          </details>
        </section>
      )}
    </Modal>
  )
}
