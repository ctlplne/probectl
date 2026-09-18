// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { lazy, Suspense, type ComponentType, type LazyExoticComponent } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { AppShell } from '../shell/AppShell'
import { NAV } from '../nav/ia'
import { DemoModeProvider } from '../demo/DemoMode'
import { LoadingState } from '../components'
import { NotFoundPage, PlaceholderPage } from './RoutePage'

const ProviderConsole = lazy(() =>
  import('@ee/provider/ProviderConsole').then((module) => ({ default: module.ProviderConsole })),
)
const TargetsPage = lazy(() =>
  import('./pages').then((module) => ({ default: module.TargetsPage })),
)
const PathPage = lazy(() => import('./PathPage').then((module) => ({ default: module.PathPage })))
const PlanesPage = lazy(() =>
  import('./PlanesPage').then((module) => ({ default: module.PlanesPage })),
)
const TopologyPage = lazy(() =>
  import('./TopologyPage').then((module) => ({ default: module.TopologyPage })),
)
const CostPage = lazy(() => import('./CostPage').then((module) => ({ default: module.CostPage })))
const SLOsPage = lazy(() => import('./SLOsPage').then((module) => ({ default: module.SLOsPage })))
const CompliancePage = lazy(() =>
  import('./CompliancePage').then((module) => ({ default: module.CompliancePage })),
)
const OutagesPage = lazy(() =>
  import('./OutagesPage').then((module) => ({ default: module.OutagesPage })),
)
const IncidentsPage = lazy(() =>
  import('./IncidentsPage').then((module) => ({ default: module.IncidentsPage })),
)
const AlertsPage = lazy(() =>
  import('./AlertsPage').then((module) => ({ default: module.AlertsPage })),
)
const SecurityPage = lazy(() =>
  import('./SecurityPage').then((module) => ({ default: module.SecurityPage })),
)
const EndpointsPage = lazy(() =>
  import('./EndpointsPage').then((module) => ({ default: module.EndpointsPage })),
)
const AskPage = lazy(() => import('./AskPage').then((module) => ({ default: module.AskPage })))
const ExplorerPage = lazy(() =>
  import('./ExplorerPage').then((module) => ({ default: module.ExplorerPage })),
)
const DashboardsPage = lazy(() =>
  import('./DashboardsPage').then((module) => ({ default: module.DashboardsPage })),
)
const OnboardingPage = lazy(() =>
  import('./OnboardingPage').then((module) => ({ default: module.OnboardingPage })),
)
const ApiDocsPage = lazy(() =>
  import('./ApiDocsPage').then((module) => ({ default: module.ApiDocsPage })),
)
const AuditPage = lazy(() =>
  import('./AuditPage').then((module) => ({ default: module.AuditPage })),
)
const Gallery = lazy(() => import('./Gallery').then((module) => ({ default: module.Gallery })))
const AdminPage = lazy(() =>
  import('./admin/AdminPage').then((module) => ({ default: module.AdminPage })),
)

/**
 * The provider console lives outside web/, so it cannot resolve react-router.
 * DPR-155: it still has to know whether the URL asks for the demo workspace —
 * it is outside DemoModeProvider by design, and without this it answered
 * `?demo=1` with live provider data. The route reads the query string and hands
 * it over; the console decides what to do with it.
 */
function ProviderRoute() {
  const { search } = useLocation()
  return (
    <Suspense fallback={<LoadingState label="Loading page…" />}>
      <ProviderConsole search={search} />
    </Suspense>
  )
}

function deferred(Page: LazyExoticComponent<ComponentType>) {
  return (
    <Suspense fallback={<LoadingState label="Loading page…" />}>
      <Page />
    </Suspense>
  )
}

/** The route tree (kept separate from the router so tests can supply their own). */
export function AppRoutes() {
  return (
    <Routes>
      {/* The provider/operator console (S-T1, ee/) — OUTSIDE the tenant
          AppShell: a visually-separate surface for a separate privilege
          domain. Not in the tenant nav; the API behind it is hidden
          (404) unless the deployment holds a provider license. */}
      <Route path="/provider/*" element={<ProviderRoute />} />
      <Route
        element={
          <DemoModeProvider>
            <AppShell />
          </DemoModeProvider>
        }
      >
        <Route index element={<Navigate to="/onboarding" replace />} />
        <Route path="/onboarding" element={deferred(OnboardingPage)} />
        <Route path="/targets" element={deferred(TargetsPage)} />
        <Route path="/path" element={deferred(PathPage)} />
        <Route path="/planes" element={deferred(PlanesPage)} />
        <Route path="/planes/:plane" element={deferred(PlanesPage)} />
        <Route path="/incidents" element={deferred(IncidentsPage)} />
        <Route path="/alerts" element={deferred(AlertsPage)} />
        <Route path="/security" element={deferred(SecurityPage)} />
        <Route path="/endpoints" element={deferred(EndpointsPage)} />
        <Route path="/ask" element={deferred(AskPage)} />
        <Route path="/explore" element={deferred(ExplorerPage)} />
        <Route path="/dashboards" element={deferred(DashboardsPage)} />
        <Route path="/topology" element={deferred(TopologyPage)} />
        <Route path="/cost" element={deferred(CostPage)} />
        <Route path="/slos" element={deferred(SLOsPage)} />
        <Route path="/compliance" element={deferred(CompliancePage)} />
        <Route path="/outages" element={deferred(OutagesPage)} />
        <Route path="/admin" element={deferred(AdminPage)} />
        <Route path="/docs/api" element={deferred(ApiDocsPage)} />
        <Route path="/audit" element={deferred(AuditPage)} />
        {NAV.filter(
          (n) =>
            ![
              '/targets',
              '/onboarding',
              '/path',
              '/planes',
              '/incidents',
              '/alerts',
              '/security',
              '/endpoints',
              '/ask',
              '/explore',
              '/dashboards',
              '/topology',
              '/cost',
              '/slos',
              '/compliance',
              '/outages',
              '/admin',
              '/docs/api',
              '/audit',
            ].includes(n.to),
        ).map((n) => (
          <Route key={n.to} path={n.to} element={<PlaceholderPage to={n.to} />} />
        ))}
        <Route path="/gallery" element={deferred(Gallery)} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
