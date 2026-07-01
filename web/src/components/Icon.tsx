import type { ReactNode, SVGProps } from 'react'

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

const paths: Record<IconName, ReactNode> = {
  outage: (
    // A globe with a broken meridian — the collective internet-outage view.
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M4 12h7M14.5 12H20" />
      <path d="M12 4a12.5 12.5 0 0 1 0 16" />
      <path d="M12 4a12.5 12.5 0 0 0-2.5 5.5M9 14.5A12.5 12.5 0 0 0 12 20" />
    </>
  ),
  endpoints: (
    <>
      <rect x="4" y="6" width="16" height="10" rx="1.5" />
      <path d="M2 19h20" />
      <path d="M9 12.5a4.2 4.2 0 0 1 6 0" />
      <circle cx="12" cy="14.5" r="0.6" />
    </>
  ),
  targets: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3.5" />
    </>
  ),
  path: (
    <>
      <circle cx="5" cy="6" r="2" />
      <circle cx="19" cy="18" r="2" />
      <path d="M7 6h6a3 3 0 0 1 3 3v6" />
    </>
  ),
  incidents: (
    <>
      <path d="M12 4 2.5 20h19L12 4Z" />
      <path d="M12 10v4" />
      <path d="M12 17.5v.5" />
    </>
  ),
  security: (
    <>
      <path d="M12 3 5 6v5c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6l-7-3Z" />
      <path d="m9 12 2 2 4-4" />
    </>
  ),
  cost: (
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 8v8M9.5 9.5h3.5a1.8 1.8 0 0 1 0 3.6h-2a1.8 1.8 0 0 0 0 3.6H15" />
    </>
  ),
  slo: (
    <>
      <path d="M4 18a8 8 0 0 1 16 0" />
      <path d="m12 18 4-5" />
    </>
  ),
  ask: (
    <>
      <path d="M5 5h14v10H9l-4 4V5Z" />
      <path d="M12 8.5a1.7 1.7 0 1 1 1.7 1.7c-.9 0-1.2.6-1.2 1.3" />
      <path d="M12.5 13.5v.3" />
    </>
  ),
  dashboards: (
    <>
      <rect x="4" y="4" width="7" height="7" rx="1" />
      <rect x="13" y="4" width="7" height="4" rx="1" />
      <rect x="13" y="11" width="7" height="9" rx="1" />
      <rect x="4" y="14" width="7" height="6" rx="1" />
    </>
  ),
  compliance: (
    <>
      <rect x="6" y="4" width="12" height="16" rx="1.5" />
      <path d="M9 4.5h6V7H9z" />
      <path d="m9.5 13 2 2 3.5-4" />
    </>
  ),
  admin: (
    <>
      <path d="M5 7h14M5 12h14M5 17h14" />
      <circle cx="9" cy="7" r="1.6" />
      <circle cx="15" cy="12" r="1.6" />
      <circle cx="9" cy="17" r="1.6" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6" />
      <path d="m20 20-3.5-3.5" />
    </>
  ),
  menu: (
    <>
      <path d="M4 7h16" />
      <path d="M4 12h16" />
      <path d="M4 17h16" />
    </>
  ),
  sun: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4 12H2M22 12h-2M5 5 4 4M20 20l-1-1M19 5l1-1M4 20l1-1" />
    </>
  ),
  moon: <path d="M20 13.5A8 8 0 1 1 10.5 4 6.5 6.5 0 0 0 20 13.5Z" />,
  close: <path d="M6 6l12 12M18 6 6 18" />,
  chevron: <path d="m6 9 6 6 6-6" />,
  check: <path d="m5 12 4.5 4.5L19 7" />,
  alert: (
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 8v5M12 16v.5" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 11v5M12 8v.5" />
    </>
  ),
}

export function Icon({
  name,
  size = 18,
  ...rest
}: { name: IconName; size?: number } & Omit<SVGProps<SVGSVGElement>, 'name'>) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {paths[name]}
    </svg>
  )
}
