// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { Link, useLocation } from 'react-router-dom'
import { useDemoMode } from './useDemoMode'
import { useI18n } from '../i18n/useI18n'
import styles from './SampleTourLink.module.css'

/**
 * The bridge from a cold surface to the isolated product tour: appends
 * `?demo=1` to the CURRENT route, so "see a sample" lands on the same screen
 * populated. Deliberately quiet (secondary to the real next action — we never
 * steer an operator toward fiction first), and the destination is
 * unmistakable once entered: demo banner, badges, Shift+D out. Renders
 * nothing inside demo mode itself.
 */
export function SampleTourLink() {
  const location = useLocation()
  const { active } = useDemoMode()
  const { t } = useI18n()
  if (active) return null
  const params = new URLSearchParams(location.search)
  params.set('demo', '1')
  return (
    <Link className={styles.link} to={`${location.pathname}?${params.toString()}`}>
      {t('demo.sampleLink')}
    </Link>
  )
}
