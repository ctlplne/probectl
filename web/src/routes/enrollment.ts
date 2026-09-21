// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { AgentEnrollToken } from '../api/agents'

export function defaultControlPlaneURL(): string {
  if (typeof window === 'undefined' || window.location.protocol !== 'https:') {
    return 'https://<control-host>:8443'
  }
  return window.location.origin
}

export function agentEnrollCommand(token: AgentEnrollToken, server: string): string {
  const trust = token.server_cert_pin
    ? ` --ca-pin ${token.server_cert_pin}`
    : ' --ca-file /etc/probectl/control-plane-ca.crt'
  return `probectl-agent enroll --server ${server} --token ${token.token} --dir /var/lib/probectl-agent/identity${trust}`
}
