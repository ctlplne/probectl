// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

const launchPermissions = ['test.read', 'test.write', 'agent.read', 'metrics.read']

export function canRunInstantTest(permissions: readonly string[]): boolean {
  return launchPermissions.every((permission) => permissions.includes(permission))
}
