// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { setDemoTransportIsolation } from '../api/client'
import { DemoModeContext } from './context'

/**
 * Demo mode is deliberately URL-entered (`?demo=1`) so it cannot be confused
 * with a tenant preference. Once entered the marker follows in-app routes,
 * keeping refreshes isolated without browser storage. Shift+D exits and
 * removes the URL marker.
 */
export function DemoModeProvider({ children }: { children: ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()
  const requestedByURL = new URLSearchParams(location.search).get('demo') === '1'
  const [latched, setLatched] = useState(requestedByURL)
  const [exiting, setExiting] = useState(false)
  const active = !exiting && (latched || requestedByURL)

  // This assignment is intentionally synchronous and idempotent: descendants
  // must not start a live query during the render that enters demo mode.
  setDemoTransportIsolation(active)

  useEffect(() => {
    if (requestedByURL && !exiting) setLatched(true)
    if (!requestedByURL && exiting) setExiting(false)
  }, [exiting, requestedByURL])

  useEffect(() => {
    if (!active || requestedByURL) return
    const params = new URLSearchParams(location.search)
    params.set('demo', '1')
    void navigate(`${location.pathname}?${params.toString()}${location.hash}`, { replace: true })
  }, [active, location.hash, location.pathname, location.search, navigate, requestedByURL])

  useEffect(() => () => setDemoTransportIsolation(false), [])

  const exit = useCallback(() => {
    setExiting(true)
    setLatched(false)
    setDemoTransportIsolation(false)
    const params = new URLSearchParams(location.search)
    params.delete('demo')
    const search = params.toString()
    void navigate(`${location.pathname}${search ? `?${search}` : ''}${location.hash}`, {
      replace: true,
    })
  }, [location.hash, location.pathname, location.search, navigate])

  useEffect(() => {
    if (!active) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.shiftKey && event.key.toLowerCase() === 'd') {
        event.preventDefault()
        exit()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [active, exit])

  const value = useMemo(() => ({ active, exit }), [active, exit])
  return <DemoModeContext.Provider value={value}>{children}</DemoModeContext.Provider>
}
