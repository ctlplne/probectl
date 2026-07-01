import type { IconName } from '../components/Icon'
import type { MessageKey } from '../i18n/messages'

/**
 * Nav groups give the 14-item IA visible structure in the sidebar (it used to
 * render as one flat wall). Grouping is presentation only; routes are
 * unchanged, and surface-coverage still reads NAV[].to. Order here is the
 * render order.
 */
export type NavGroupId = 'monitor' | 'analyze' | 'secure' | 'operate'

export interface NavGroup {
  id: NavGroupId
  labelKey: MessageKey
}

export const NAV_GROUPS: NavGroup[] = [
  { id: 'monitor', labelKey: 'nav.group.monitor' },
  { id: 'analyze', labelKey: 'nav.group.analyze' },
  { id: 'secure', labelKey: 'nav.group.secure' },
  { id: 'operate', labelKey: 'nav.group.operate' },
]

export interface NavItem {
  to: string
  labelKey: MessageKey
  icon: IconName
  group: NavGroupId
}

/**
 * Tenant-context information architecture (PRD §6.2), grouped:
 *   monitor - live signals: tests, path, topology, incidents, outages, alerts, endpoints
 *   analyze - cross-plane reasoning + views: Ask (AI), dashboards
 *   secure  - posture: security, compliance
 *   operate - run the platform: cost, SLOs, admin
 *
 * Later sprints fill each route; the shell + nav are stable from here.
 */
export const NAV: NavItem[] = [
  { to: '/onboarding', labelKey: 'nav.onboarding', icon: 'check', group: 'operate' },
  { to: '/targets', labelKey: 'nav.targets', icon: 'targets', group: 'monitor' },
  { to: '/path', labelKey: 'nav.path', icon: 'path', group: 'monitor' },
  { to: '/planes', labelKey: 'nav.planes', icon: 'path', group: 'monitor' },
  { to: '/topology', labelKey: 'nav.topology', icon: 'path', group: 'monitor' },
  { to: '/incidents', labelKey: 'nav.incidents', icon: 'incidents', group: 'monitor' },
  { to: '/outages', labelKey: 'nav.outages', icon: 'outage', group: 'monitor' },
  { to: '/alerts', labelKey: 'nav.alerts', icon: 'alert', group: 'monitor' },
  { to: '/endpoints', labelKey: 'nav.endpoints', icon: 'endpoints', group: 'monitor' },
  { to: '/ask', labelKey: 'nav.ask', icon: 'ask', group: 'analyze' },
  { to: '/dashboards', labelKey: 'nav.dashboards', icon: 'dashboards', group: 'analyze' },
  { to: '/security', labelKey: 'nav.security', icon: 'security', group: 'secure' },
  { to: '/compliance', labelKey: 'nav.compliance', icon: 'compliance', group: 'secure' },
  { to: '/audit', labelKey: 'nav.audit', icon: 'compliance', group: 'secure' },
  { to: '/cost', labelKey: 'nav.cost', icon: 'cost', group: 'operate' },
  { to: '/slos', labelKey: 'nav.slos', icon: 'slo', group: 'operate' },
  { to: '/admin', labelKey: 'nav.admin', icon: 'admin', group: 'operate' },
  { to: '/docs/api', labelKey: 'nav.apiDocs', icon: 'info', group: 'operate' },
]
