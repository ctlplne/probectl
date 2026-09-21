// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { SVGProps } from 'react'
import {
  AlertTriangle,
  Check,
  ChevronDown,
  CircleDollarSign,
  ClipboardCheck,
  Gauge,
  GlobeLock,
  Info,
  LayoutDashboard,
  Menu,
  MonitorSmartphone,
  Moon,
  Route,
  Search,
  Settings2,
  ShieldCheck,
  Siren,
  Sparkles,
  Sun,
  Target,
  X,
  type LucideIcon,
} from 'lucide-react'

/**
 * Icons are named for what they MEAN in probectl, not for what they look like,
 * so a glyph can change without touching the twenty-odd call sites. The names
 * are the product's vocabulary; lucide-react supplies the drawing, which is what
 * makes the iconography match the sibling console.
 */
export type IconName =
  | 'targets'
  | 'endpoints'
  | 'path'
  | 'incidents'
  | 'security'
  | 'cost'
  | 'slo'
  | 'ask'
  | 'dashboards'
  | 'compliance'
  | 'outage'
  | 'admin'
  | 'search'
  | 'menu'
  | 'sun'
  | 'moon'
  | 'close'
  | 'chevron'
  | 'check'
  | 'alert'
  | 'info'

const glyphs: Record<IconName, LucideIcon> = {
  targets: Target,
  endpoints: MonitorSmartphone,
  path: Route,
  incidents: Siren,
  security: ShieldCheck,
  cost: CircleDollarSign,
  slo: Gauge,
  ask: Sparkles,
  dashboards: LayoutDashboard,
  compliance: ClipboardCheck,
  // A globe under a lock: the collective internet-outage view, which is public
  // data about reachability rather than anything tenant-owned.
  outage: GlobeLock,
  admin: Settings2,
  search: Search,
  menu: Menu,
  sun: Sun,
  moon: Moon,
  close: X,
  chevron: ChevronDown,
  check: Check,
  alert: AlertTriangle,
  info: Info,
}

/** Runtime list of every icon (for the design-system gallery). */
// eslint-disable-next-line react-refresh/only-export-components
export const ICON_NAMES: IconName[] = Object.keys(glyphs) as IconName[]

export function Icon({
  name,
  size = 18,
  ...rest
}: { name: IconName; size?: number } & Omit<SVGProps<SVGSVGElement>, 'name'>) {
  const Glyph = glyphs[name]
  return (
    <Glyph
      width={size}
      height={size}
      strokeWidth={1.75}
      aria-hidden="true"
      focusable="false"
      {...rest}
    />
  )
}
