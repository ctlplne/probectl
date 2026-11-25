// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useBrand } from './BrandProvider'
import styles from './ProductIdentity.module.css'

function ProbectlMark({ small = false }: { small?: boolean }) {
  const size = small ? 14 : 26
  return (
    <svg aria-hidden="true" viewBox="0 0 32 32" width={size} height={size} className={styles.mark}>
      <circle cx="16" cy="16" r="16" fill="#8e480b" />
      <circle cx="16" cy="16" r="10" fill="none" stroke="#fffefa" strokeWidth="2.2" />
      <circle cx="16" cy="16" r="4.2" fill="none" stroke="#fffefa" strokeWidth="1.8" />
      <circle cx="16" cy="16" r="1.8" fill="#fffefa" />
    </svg>
  )
}

export function PoweredByProbectl() {
  return (
    <a className={styles.attribution} href="https://probectl.com" referrerPolicy="no-referrer">
      <ProbectlMark small />
      Powered by probectl
    </a>
  )
}

export function ProductIdentity({ platform = false }: { platform?: boolean }) {
  const brand = useBrand()
  const customer = platform ? undefined : brand.customer
  return (
    <div className={styles.identity}>
      <span className={styles.wordmark}>
        {customer?.logo_data_uri ? (
          <img className={styles.customerLogo} src={customer.logo_data_uri} alt="" />
        ) : customer ? null : (
          <ProbectlMark />
        )}
        <span className={styles.name}>{customer?.name ?? 'probectl'}</span>
      </span>
      {customer ? <PoweredByProbectl /> : null}
    </div>
  )
}
