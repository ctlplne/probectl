// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

/**
 * cn() merges Tailwind classes, and a merge that guesses wrong DELETES styling
 * silently — no error, no failing token test, just an element missing a class.
 *
 * That is not hypothetical: the six semantic type rungs (text-caption, text-data,
 * …) look exactly like text-COLOUR utilities to tailwind-merge, so it grouped
 * them together and dropped the colour. Every primary and danger button rendered
 * its label in the inherited body colour — 2.41:1 in light, 1.53:1 in dark — while
 * the palette tests stayed green, because the tokens were never the problem.
 */
import { describe, expect, test } from 'vitest'
import { render, screen } from '@testing-library/react'
import { cn } from '../lib/cn'
import { Button } from '../components/Button'

const TYPE_RUNGS = ['caption', 'data', 'body', 'title', 'heading', 'display']

describe('class merging', () => {
  test('a type rung never displaces a text colour', () => {
    for (const rung of TYPE_RUNGS) {
      const merged = cn('text-primary-foreground', `text-${rung}`).split(' ')
      expect(merged, `text-${rung} swallowed the text colour`).toContain('text-primary-foreground')
      expect(merged).toContain(`text-${rung}`)
    }
  })

  test('text colours still merge with each other', () => {
    expect(cn('text-foreground', 'text-muted-foreground')).toBe('text-muted-foreground')
  })

  test('type rungs still merge with each other', () => {
    expect(cn('text-body', 'text-caption')).toBe('text-caption')
    expect(cn('text-caption', 'text-sm')).toBe('text-sm')
  })

  test('an explicit caller colour still wins over the component default', () => {
    expect(cn('text-primary-foreground', 'text-destructive')).toBe('text-destructive')
  })

  // The end-to-end proof: the class the contrast depends on reaches the DOM.
  test.each([
    ['primary', 'text-primary-foreground', 'bg-primary'],
    ['danger', 'text-destructive-foreground', 'bg-destructive'],
  ] as const)('a %s button carries its paired foreground AND its type rung', (variant, fg, bg) => {
    render(
      <Button variant={variant} size="md">
        Run
      </Button>,
    )
    const classes = screen.getByRole('button', { name: 'Run' }).className.split(' ')
    expect(classes, `${variant} button lost ${fg}`).toContain(fg)
    expect(classes).toContain(bg)
    expect(classes).toContain('text-data')
  })
})
