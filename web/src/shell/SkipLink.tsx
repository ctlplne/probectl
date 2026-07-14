// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import styles from './SkipLink.module.css'

/** A keyboard skip-to-content link (WCAG 2.4.1), visible only when focused. */
export function SkipLink() {
  return (
    <a className={styles.skip} href="#main-content">
      Skip to content
    </a>
  )
}
