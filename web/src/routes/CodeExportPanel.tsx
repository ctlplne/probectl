// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMemo, useState } from 'react'
import { Button, Icon } from '../components'
import styles from './CodeExportPanel.module.css'

export function CodeExportPanel({ title, code }: { title: string; code: string }) {
  const [copied, setCopied] = useState(false)
  const copyLabel = copied ? 'Copied YAML' : 'Copy YAML'
  const lineCount = useMemo(() => code.trimEnd().split('\n').length, [code])

  function copy() {
    if (!navigator.clipboard) {
      setCopied(true)
      return
    }
    void navigator.clipboard.writeText(code).then(() => setCopied(true))
  }

  return (
    <section className={styles.panel} aria-label={title}>
      <div className={styles.toolbar}>
        <span className={styles.title}>
          {title} · {lineCount} lines
        </span>
        <Button variant="secondary" size="sm" onClick={copy}>
          <Icon name="check" /> {copyLabel}
        </Button>
      </div>
      <pre className={styles.code}>
        <code>{code}</code>
      </pre>
    </section>
  )
}
