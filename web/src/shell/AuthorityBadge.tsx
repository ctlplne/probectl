// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { Badge } from '../components'
import { useAuth } from '../auth/useAuth'
import { authorityPosture } from './authority'

export function AuthorityBadge() {
  const { permissions } = useAuth()
  const posture = authorityPosture(permissions)

  return (
    <span
      role="status"
      aria-label={`Authority posture: ${posture.label}`}
      title={posture.detail}
    >
      <Badge tone={posture.tone}>{posture.label}</Badge>
    </span>
  )
}
