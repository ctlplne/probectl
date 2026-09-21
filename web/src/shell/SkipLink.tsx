// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import styles from './SkipLink.module.css'

/** A keyboard skip-to-content link (WCAG 2.4.1), visible only when focused. */
export function SkipLink() {
  return (
    <a className={styles.skip} href="#main-content">
      Skip to content
    </a>
  )
}
