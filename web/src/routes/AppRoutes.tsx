import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from '../shell/AppShell'
import { NAV } from '../nav/ia'
import { AdminPage, NotFoundPage, PlaceholderPage, TargetsPage } from './pages'
import { PathPage } from './PathPage'
import { TopologyPage } from './TopologyPage'
import { CostPage } from './CostPage'
import { IncidentsPage } from './IncidentsPage'
import { AlertsPage } from './AlertsPage'
import { SecurityPage } from './SecurityPage'
import { EndpointsPage } from './EndpointsPage'
import { AskPage } from './AskPage'
import { Gallery } from './Gallery'

/** The route tree (kept separate from the router so tests can supply their own). */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/targets" replace />} />
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/path" element={<PathPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/security" element={<SecurityPage />} />
        <Route path="/endpoints" element={<EndpointsPage />} />
        <Route path="/ask" element={<AskPage />} />
        <Route path="/topology" element={<TopologyPage />} />
        <Route path="/cost" element={<CostPage />} />
        <Route path="/admin" element={<AdminPage />} />
        {NAV.filter((n) => !['/targets', '/path', '/incidents', '/alerts', '/security', '/endpoints', '/ask', '/topology', '/cost', '/admin'].includes(n.to)).map((n) => (
          <Route key={n.to} path={n.to} element={<PlaceholderPage to={n.to} />} />
        ))}
        <Route path="/gallery" element={<Gallery />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
