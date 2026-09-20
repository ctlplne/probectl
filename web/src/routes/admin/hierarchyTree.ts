// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type { Hierarchy } from '../../api/hierarchy'

/** One flattened row: the tree is rendered as an indented table so it stays
 * one scan, one tab order, and legible to a screen reader at any depth. */
export interface HierarchyRow {
  id: string
  level: 'organization' | 'team' | 'project'
  name: string
  slug: string
  parent?: string
  updated_at: string
}

export function flattenHierarchy(tree: Hierarchy): HierarchyRow[] {
  const rows: HierarchyRow[] = []
  for (const org of tree.items) {
    rows.push({
      id: `org:${org.id}`,
      level: 'organization',
      name: org.name,
      slug: org.slug,
      updated_at: org.updated_at,
    })
    for (const team of org.teams) {
      rows.push({
        id: `team:${team.id}`,
        level: 'team',
        name: team.name,
        slug: team.slug,
        parent: org.name,
        updated_at: team.updated_at,
      })
      for (const project of team.projects) {
        rows.push({
          id: `project:${project.id}`,
          level: 'project',
          name: project.name,
          slug: project.slug,
          parent: team.name,
          updated_at: project.updated_at,
        })
      }
    }
  }
  return rows
}
