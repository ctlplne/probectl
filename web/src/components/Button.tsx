// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '../lib/cn'

/**
 * One action path: `primary` is the brand fill and there is at most one per
 * view. `secondary` is the default because most buttons are not the point of
 * the screen. Every variant keeps the same geometry so a row of mixed buttons
 * still aligns, and the focus ring is the token ring rather than the browser's.
 *
 * Height comes from the density tokens, so compact mode reshapes every control
 * without touching this file, and a coarse pointer still gets its 44px target.
 */
const button = cva(
  [
    'inline-flex items-center justify-center gap-2 whitespace-nowrap',
    'rounded-control border font-sans font-medium',
    'transition-colors duration-fast ease-standard',
    'outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2',
    'focus-visible:ring-offset-background',
    'disabled:pointer-events-none disabled:opacity-50',
  ],
  {
    variants: {
      variant: {
        primary: 'border-transparent bg-primary text-primary-foreground hover:bg-primary/90',
        secondary: 'border-border bg-card text-foreground hover:bg-muted',
        ghost:
          'border-transparent bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground',
        danger:
          'border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/90',
      },
      size: {
        sm: 'h-control-sm px-3 text-caption',
        md: 'h-control px-4 text-data',
      },
      iconOnly: {
        true: 'aspect-square px-0',
        false: '',
      },
    },
    defaultVariants: { variant: 'secondary', size: 'md', iconOnly: false },
  },
)

export type ButtonVariant = NonNullable<VariantProps<typeof button>['variant']>
export type ButtonSize = NonNullable<VariantProps<typeof button>['size']>

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  iconOnly?: boolean
  children?: ReactNode
}

export function Button({
  variant = 'secondary',
  size = 'md',
  iconOnly = false,
  className,
  type = 'button',
  children,
  ...rest
}: ButtonProps) {
  return (
    <button type={type} className={cn(button({ variant, size, iconOnly }), className)} {...rest}>
      {children}
    </button>
  )
}
