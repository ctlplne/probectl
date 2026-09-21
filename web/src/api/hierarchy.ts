// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The tenant org/team/project hierarchy (F24, surface S-T3). Every node carries
 * its own `tenant_id` because the server scopes the whole tree at the storage
 * layer and ABAC can prune individual branches a principal may not read — so a
 * returned tree is "what this principal is allowed to see", never "what exists".
 * The read needs `org.read`; each create needs `org.write`.
 */

export interface HierarchyProject {
  id: string
  tenant_id: string
  team_id: string
  slug: string
  name: string
  created_at: string
  updated_at: string
}

export interface HierarchyTeamFlat {
  id: string
  tenant_id: string
  org_id: string
  slug: string
  name: string
  created_at: string
  updated_at: string
}

export interface HierarchyTeam extends HierarchyTeamFlat {
  projects: HierarchyProject[]
}

export interface HierarchyOrganizationFlat {
  id: string
  tenant_id: string
  slug: string
  name: string
  created_at: string
  updated_at: string
}

export interface HierarchyOrganization extends HierarchyOrganizationFlat {
  teams: HierarchyTeam[]
}

export interface Hierarchy {
  items: HierarchyOrganization[]
}

/** The wire form: the server may omit an empty array rather than send `[]`. */
interface HierarchyWire {
  items?: HierarchyOrganization[] | null
}

interface OrganizationWire extends Omit<HierarchyOrganization, 'teams'> {
  teams?: HierarchyTeam[] | null
}

interface TeamWire extends Omit<HierarchyTeam, 'projects'> {
  projects?: HierarchyProject[] | null
}

/**
 * normalizeHierarchy makes every level a real array. A missing `teams` is an
 * organization with no teams, which the card must render as an explicit "no
 * teams yet" rather than crashing on `.map` or, worse, silently dropping the
 * organization from the tree.
 */
export function normalizeHierarchy(wire: HierarchyWire): Hierarchy {
  return {
    items: (wire.items ?? []).map((org) => {
      const orgWire = org as OrganizationWire
      return {
        ...org,
        teams: (orgWire.teams ?? []).map((team) => {
          const teamWire = team as TeamWire
          return { ...team, projects: teamWire.projects ?? [] }
        }),
      }
    }),
  }
}

export function useHierarchy() {
  return useQuery({
    queryKey: ['hierarchy'],
    queryFn: async () => normalizeHierarchy(await apiFetch<HierarchyWire>('/hierarchy')),
  })
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

export interface HierarchyNodeInput {
  slug: string
  name: string
}

export function useCreateOrganization() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: HierarchyNodeInput) =>
      apiFetch<HierarchyOrganizationFlat>('/hierarchy/orgs', jsonInit('POST', input)),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hierarchy'] }),
  })
}

export function useCreateTeam() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ orgID, input }: { orgID: string; input: HierarchyNodeInput }) =>
      apiFetch<HierarchyTeamFlat>(
        `/hierarchy/orgs/${encodeURIComponent(orgID)}/teams`,
        jsonInit('POST', input),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hierarchy'] }),
  })
}

export function useCreateProject() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ teamID, input }: { teamID: string; input: HierarchyNodeInput }) =>
      apiFetch<HierarchyProject>(
        `/hierarchy/teams/${encodeURIComponent(teamID)}/projects`,
        jsonInit('POST', input),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hierarchy'] }),
  })
}
