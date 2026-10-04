// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { Button, type ButtonVariant } from './Button'
import { Modal } from './Modal'

export interface ConfirmDialogProps {
  open: boolean
  title: string
  /** What the operator is confirming — the blast radius / what will be removed. */
  children: ReactNode
  confirmLabel: string
  busyLabel?: string
  confirmVariant?: ButtonVariant
  confirmDisabled?: boolean
  pending?: boolean
  onConfirm: () => void
  onClose: () => void
}

// ConfirmDialog is a focus-trapped confirmation step for an irreversible or
// human-gated action (docs/guardrails.md G8-N): the action fires only from this
// dialog's Confirm button, never from the triggering row control, so a single
// stray click can neither delete nor approve. It shares Modal's a11y contract.
export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  busyLabel,
  confirmVariant = 'danger',
  confirmDisabled,
  pending,
  onConfirm,
  onClose,
}: ConfirmDialogProps) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={confirmVariant}
            disabled={pending || confirmDisabled}
            onClick={onConfirm}
          >
            {pending ? (busyLabel ?? confirmLabel) : confirmLabel}
          </Button>
        </>
      }
    >
      {children}
    </Modal>
  )
}
