// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
