// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// The core edition's stand-in for ee/web's provider console (PD-5, AUD-20). A
// core build carries no commercial UI, and the provider API that console calls
// is not linked into a core control plane, so the route renders nothing, the
// way an unlicensed feature does (docs/editions.md: hidden, not lockware).
// vite.config.ts aliases `@ee` here when PROBECTL_WEB_EDITION=core.
export interface ProviderConsoleProps {
  search?: string
}

export function ProviderConsole(props: ProviderConsoleProps): null {
  void props
  return null
}
