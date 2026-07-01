import { Navigate, Route, Routes } from 'react-router-dom'
import { ProviderConsole } from '@ee/provider/ProviderConsole'
import { AppShell } from '../shell/AppShell'
import { NAV } from '../nav/ia'
import { AdminPage, NotFoundPage, PlaceholderPage, TargetsPage } from './pages'
import { PathPage } from './PathPage'
import { PlanesPage } from './PlanesPage'
import { TopologyPage } from './TopologyPage'
import { CostPage } from './CostPage'
import { SLOsPage } from './SLOsPage'
import { CompliancePage } from './CompliancePage'
import { OutagesPage } from './OutagesPage'
import { IncidentsPage } from './IncidentsPage'
import { AlertsPage } from './AlertsPage'
import { SecurityPage } from './SecurityPage'
import { EndpointsPage } from './EndpointsPage'
import { AskPage } from './AskPage'
import { DashboardsPage } from './DashboardsPage'
import { OnboardingPage } from './OnboardingPage'
import { ApiDocsPage } from './ApiDocsPage'
import { Gallery } from './Gallery'

/** The route tree (kept separate from the router so tests can supply their own). */
export function AppRoutes() {
  return (
    <Routes>
      {/* The provider/operator console (S-T1, ee/) — OUTSIDE the tenant
          AppShell: a visually-separate surface for a separate privilege
          domain. Not in the tenant nav; the API behind it is hidden
          (404) unless the deployment holds a provider license. */}
      <Route path="/provider/*" element={<ProviderConsole />} />
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/onboarding" replace />} />
        <Route path="/onboarding" element={<OnboardingPage />} />
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/path" element={<PathPage />} />
        <Route path="/planes" element={<PlanesPage />} />
        <Route path="/planes/:plane" element={<PlanesPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/security" element={<SecurityPage />} />
        <Route path="/endpoints" element={<EndpointsPage />} />
        <Route path="/ask" element={<AskPage />} />
        <Route path="/dashboards" element={<DashboardsPage />} />
        <Route path="/topology" element={<TopologyPage />} />
        <Route path="/cost" element={<CostPage />} />
        <Route path="/slos" element={<SLOsPage />} />
        <Route path="/compliance" element={<CompliancePage />} />
        <Route path="/outages" element={<OutagesPage />} />
        <Route path="/admin" element={<AdminPage />} />
        <Route path="/docs/api" element={<ApiDocsPage />} />
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
              '/dashboards',
              '/topology',
              '/cost',
              '/slos',
              '/compliance',
              '/outages',
              '/admin',
              '/docs/api',
            ].includes(n.to),
        ).map((n) => (
          <Route key={n.to} path={n.to} element={<PlaceholderPage to={n.to} />} />
        ))}
        <Route path="/gallery" element={<Gallery />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
