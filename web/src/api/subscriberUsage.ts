// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { SubscriberUsageReport, SubscriberUsageRequest } from './sdk.gen'

export function useSubscriberUsage(tenantID: string, id: string) {
  return useMutation({
    mutationFn: (input: SubscriberUsageRequest) =>
      apiFetch<SubscriberUsageReport>(
        `/explorer/flow-views/${encodeURIComponent(id)}/subscriber-usage`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Probectl-Tenant': tenantID },
          body: JSON.stringify(input),
        },
      ),
  })
}
