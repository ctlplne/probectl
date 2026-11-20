// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import {
  type Proposal,
  useApproveDiversion,
  useDecideRemediation,
  useDiversionReview,
  usePreviewDiversion,
  useProposeDiversion,
} from '../api/remediation'
import { DateTime } from '../time/DateTime'
import { Button, LoadingState, Modal } from './index'

export function DiversionReviewDialog({
  proposal,
  identity,
  canApprove,
  onClose,
}: {
  proposal: Proposal
  identity: string
  canApprove: boolean
  onClose: () => void
}) {
  const review = useDiversionReview(proposal.id, identity)
  const approval = useApproveDiversion()
  const decide = useDecideRemediation()
  const stopPreview = usePreviewDiversion()
  const fileStop = useProposeDiversion()
  const data = review.data
  const receipt = approval.data ?? data?.receipt
  const stop = stopPreview.data
  const expired = data ? Date.parse(data.expires_at) <= Date.now() : true
  const canDecide = !receipt && !decide.isSuccess && proposal.state === 'proposed' && canApprove
  const busy = approval.isPending || decide.isPending || stopPreview.isPending || fileStop.isPending
  const error =
    review.error ?? approval.error ?? decide.error ?? stopPreview.error ?? fileStop.error

  return (
    <Modal
      open
      onClose={onClose}
      title={proposal.title}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          {canDecide && data ? (
            <>
              <Button
                variant="ghost"
                disabled={busy}
                onClick={() =>
                  decide.mutate({ id: proposal.id, decision: 'reject' }, { onSuccess: onClose })
                }
              >
                Reject preview
              </Button>
              <Button
                disabled={busy || expired || review.isFetching || review.isError}
                onClick={() =>
                  approval.mutate({
                    id: proposal.id,
                    input: { review_fingerprint: data.review_fingerprint },
                  })
                }
              >
                Approve local preview
              </Button>
            </>
          ) : null}
        </>
      }
    >
      <p>Local preview. Approval records a simulated scrubbing state for this prefix.</p>
      {review.isPending ? <LoadingState label="Loading diversion review" /> : null}
      {error ? <p role="alert">{error.message}</p> : null}
      {data ? (
        <dl>
          <dt>Protected prefix</dt>
          <dd>{data.candidate.prefix}</dd>
          <dt>Action</dt>
          <dd>
            {data.candidate.action === 'start'
              ? 'Start diversion preview'
              : 'Stop diversion preview'}
          </dd>
          {data.candidate.impact ? (
            <>
              <dt>Known benign packets</dt>
              <dd>{data.candidate.impact.known_benign.packets}</dd>
              <dt>Unclassified packets</dt>
              <dd>{data.candidate.impact.unclassified.packets}</dd>
              <dt>Approved maximum for known benign packets</dt>
              <dd>{data.max_known_benign_packets}</dd>
            </>
          ) : (
            <>
              <dt>Original preview ID</dt>
              <dd>
                <code>{data.candidate.start_preview_id}</code>
              </dd>
            </>
          )}
          <dt>{receipt ? 'Local acknowledgement' : 'Review expires'}</dt>
          <dd>
            <DateTime value={receipt?.recorded_at ?? data.expires_at} />
          </dd>
        </dl>
      ) : null}
      {receipt?.action === 'start' && !stop && !data?.start_stopped_at ? (
        <Button
          variant="secondary"
          disabled={busy}
          onClick={() =>
            stopPreview.mutate({ action: 'stop', start_preview_id: receipt.start_preview_id })
          }
        >
          Preview stop
        </Button>
      ) : null}
      {data?.start_stopped_at ? <p role="status">This local preview has stopped.</p> : null}
      {stop && !fileStop.isSuccess ? (
        <Button
          disabled={busy}
          onClick={() =>
            fileStop.mutate({
              selection: stop.input,
              preview_fingerprint: stop.assessment.preview_fingerprint,
            })
          }
        >
          File stop for independent review
        </Button>
      ) : null}
      {fileStop.isSuccess ? <p role="status">Stop preview filed for independent review.</p> : null}
    </Modal>
  )
}
