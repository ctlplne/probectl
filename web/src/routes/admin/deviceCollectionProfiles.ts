// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { DeviceCollectionProfile } from '../../api/agents'

export interface DeviceCollectionProfilePreview {
  value: DeviceCollectionProfile
  snmpInterval: string
  snmpWalks: readonly string[]
  gnmiInterval: string
  gnmiPaths: readonly string[]
}

const baseSNMPWalks = [
  'system identity and uptime',
  'interface identity and status',
  'interface counters',
  'interface addresses',
  'host CPU and memory',
] as const

export const deviceCollectionProfiles: readonly DeviceCollectionProfilePreview[] = [
  {
    value: 'minimal',
    snmpInterval: '5m',
    snmpWalks: baseSNMPWalks,
    gnmiInterval: '2m',
    gnmiPaths: ['/interfaces/interface/state/oper-status'],
  },
  {
    value: 'standard',
    snmpInterval: '1m',
    snmpWalks: baseSNMPWalks,
    gnmiInterval: '30s',
    gnmiPaths: ['/interfaces/interface/state/counters', '/interfaces/interface/state/oper-status'],
  },
  {
    value: 'topology-rich',
    snmpInterval: '1m',
    snmpWalks: [...baseSNMPWalks, 'entity temperature sensors', 'LLDP neighbors', 'CDP neighbors'],
    gnmiInterval: '30s',
    gnmiPaths: ['/interfaces/interface/state/counters', '/interfaces/interface/state/oper-status'],
  },
] as const

export function deviceCollectionProfile(
  value: DeviceCollectionProfile,
): DeviceCollectionProfilePreview {
  return deviceCollectionProfiles.find((profile) => profile.value === value)!
}
