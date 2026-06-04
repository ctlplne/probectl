import type { IconName } from '../components/Icon'

export interface NavItem {
  to: string
  label: string
  icon: IconName
}

/**
 * Tenant-context information architecture (PRD §6.2):
 * Targets/Tests → Path/Topology → Incidents → Security → Cost → SLOs → Ask (AI)
 * → Dashboards → Compliance → Admin/Settings.
 *
 * Later sprints fill each route; the shell + nav are stable from here.
 */
export const NAV: NavItem[] = [
  { to: '/targets', label: 'Targets & Tests', icon: 'targets' },
  { to: '/path', label: 'Path & Topology', icon: 'path' },
  { to: '/incidents', label: 'Incidents', icon: 'incidents' },
  { to: '/alerts', label: 'Alerts', icon: 'alert' },
  { to: '/endpoints', label: 'Endpoints', icon: 'endpoints' },
  { to: '/security', label: 'Security', icon: 'security' },
  { to: '/cost', label: 'Cost', icon: 'cost' },
  { to: '/slos', label: 'SLOs', icon: 'slo' },
  { to: '/ask', label: 'Ask (AI)', icon: 'ask' },
  { to: '/dashboards', label: 'Dashboards', icon: 'dashboards' },
  { to: '/compliance', label: 'Compliance', icon: 'compliance' },
  { to: '/admin', label: 'Admin & Settings', icon: 'admin' },
]
