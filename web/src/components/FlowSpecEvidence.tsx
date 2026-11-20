// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { RemediationFlowSpecPreview } from '../api/sdk.gen'
import { DateTime } from '../time/DateTime'

export function FlowSpecEvidence({ preview }: { preview: RemediationFlowSpecPreview }) {
  const { candidate, matching, whole_scope: whole } = preview
  const { protocol, source_port: source, destination_port: destination } = candidate.transport
  return (
    <>
      <dt>Proposed FlowSpec match</dt>
      <dd>
        {candidate.destination} · {protocol.toUpperCase()}
        {source === undefined ? '' : ` · source port ${source}`}
        {destination === undefined ? '' : ` · destination port ${destination}`}
        {' · proposed discard'}
      </dd>
      <dt>Observation window</dt>
      <dd>
        <DateTime value={matching.from} /> – <DateTime value={matching.to} />
      </dd>
      <dt>Whole protected prefix</dt>
      <dd>
        {whole.matched.bytes} bytes · {whole.matched.packets} packets
      </dd>
      <dt>Traffic matching the proposal</dt>
      <dd>
        {matching.matched.bytes} bytes · {matching.matched.packets} packets
      </dd>
      <dt>Known benign traffic matching the proposal</dt>
      <dd>
        {matching.known_benign.bytes} bytes · {matching.known_benign.packets} packets
      </dd>
      <dt>Unclassified traffic matching the proposal</dt>
      <dd>
        {matching.unclassified.bytes} bytes · {matching.unclassified.packets} packets
      </dd>
      {whole.sampled ? (
        <>
          <dt>Sampling</dt>
          <dd>Counts are adjusted for exporter sampling.</dd>
        </>
      ) : null}
    </>
  )
}
