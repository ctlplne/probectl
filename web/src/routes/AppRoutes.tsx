import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from '../shell/AppShell'
import { NAV } from '../nav/ia'
import { AdminPage, NotFoundPage, PlaceholderPage, TargetsPage } from './pages'
import { Gallery } from './Gallery'

/** The route tree (kept separate from the router so tests can supply their own). */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/targets" replace />} />
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/admin" element={<AdminPage />} />
        {NAV.filter((n) => n.to !== '/targets' && n.to !== '/admin').map((n) => (
          <Route key={n.to} path={n.to} element={<PlaceholderPage to={n.to} />} />
        ))}
        <Route path="/gallery" element={<Gallery />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
