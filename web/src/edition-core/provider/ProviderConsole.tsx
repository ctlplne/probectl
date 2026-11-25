// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// The core edition's stand-in for ee/web's provider console (PD-5, AUD-20). A
// core build carries no commercial UI, and the provider API that console calls
// is not linked into a core control plane. The route renders the platform
// identity with the commercial controls hidden.
// vite.config.ts aliases `@ee` here when PROBECTL_WEB_EDITION=core.
import { ProductIdentity } from '../../brand/ProductIdentity'

export interface ProviderConsoleProps {
  search?: string
}

export function ProviderConsole(props: ProviderConsoleProps) {
  void props
  return <ProductIdentity platform />
}
