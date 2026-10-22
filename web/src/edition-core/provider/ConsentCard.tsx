// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// The core edition's stand-in for ee/web's break-glass consent card (PD-5): the
// break-glass plane is commercial, so a core build's Admin page shows no card.
export function ConsentCard(): null {
  return null
}
