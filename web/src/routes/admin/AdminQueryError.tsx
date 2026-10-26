// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { ErrorState } from '../../components'
import { classifySurfaceTruth } from '../../data/classifySurfaceTruth'

/** A rejected read says nothing about whether the deployment is configured. */
export function AdminQueryError({
  error,
  description,
}: {
  error: unknown
  description: ReactNode
}) {
  if (classifySurfaceTruth({ error }) === 'permission-denied') {
    return (
      <ErrorState
        title="Permission denied"
        description="Your current access does not allow viewing this information. Ask your tenant administrator if you need access."
      />
    )
  }
  return <ErrorState description={description} />
}
