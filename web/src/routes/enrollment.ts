// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
