// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Client-side scheme allow-lists for server-provided link targets (WEB-14).
// Hrefs and router targets can originate from open-data feeds, deployment
// config, or other tenant-influenced data, so the UI must refuse hostile
// schemes (javascript:, data:), plaintext http:, and protocol-relative //host
// targets rather than rendering them as live links.

// safeHref returns url only when it is an absolute https URL safe to use as an
// external link target; otherwise undefined, so the caller renders plain text
// instead of an anchor. http:, javascript:, data:, and relative/'//host' values
// are all refused.
export function safeHref(url: string | undefined | null): string | undefined {
  if (!url) {
    return undefined
  }
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return undefined
  }
  return parsed.protocol === 'https:' ? url : undefined
}

// APP_BASENAME is the single source of truth for the SPA's router basename —
// App.tsx mounts <BrowserRouter basename={APP_BASENAME}> and the server serves
// the bundle under it. It matches the Vite build base ("/ui/").
export const APP_BASENAME = '/ui'

// appPath prefixes an in-app route with APP_BASENAME so an ABSOLUTE link built
// by hand (a copyable share URL, not a react-router <Link>, which applies the
// basename itself) resolves to a real served path instead of 404ing (WEB-07).
// appPath('/incidents') -> '/ui/incidents'.
export function appPath(path: string): string {
  return `${APP_BASENAME}${path.startsWith('/') ? path : `/${path}`}`
}

// safeInternalTo returns to only when it is an in-app absolute path (a single
// leading slash), never a scheme (javascript:/http:) or a protocol-relative
// //host target the browser would treat as external; otherwise undefined.
export function safeInternalTo(to: string | undefined | null): string | undefined {
  if (!to || !to.startsWith('/') || to.startsWith('//')) {
    return undefined
  }
  return to
}
