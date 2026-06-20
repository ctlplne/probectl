import { useInfiniteQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface Agent {
  id: string
  name: string
  hostname: string
  agent_version: string
  status: 'registered' | 'online' | 'offline'
  capabilities: string[]
  last_seen_at?: string
}

interface AgentsPage {
  items: Agent[]
  next_cursor?: string
}

export interface MintAgentEnrollTokenInput {
  agent_id?: string
  name?: string
  ttl_seconds?: number
}

export interface AgentEnrollToken {
  token: string
  id: string
  tenant_id: string
  expires_at: string
  server_cert_pin?: string
}

// UX-004: the agent fleet can be large, so the list MUST ride the backend's
// cursor pagination (handleListAgents: ?after=<id>&limit=<n>, next_cursor when a
// full page is returned). Previously useAgents() fetched bare `/agents` and
// rendered every row — unbounded at fleet scale. Now it pages with
// useInfiniteQuery; the page wires a load-more control and the Table bounds the
// rows it actually renders.
export const AGENTS_PAGE_SIZE = 100

export function useAgents() {
  return useInfiniteQuery({
    queryKey: ['agents'],
    initialPageParam: '',
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ limit: String(AGENTS_PAGE_SIZE) })
      if (pageParam) params.set('after', pageParam)
      return apiFetch<AgentsPage>(`/agents?${params.toString()}`)
    },
    // next_cursor is present only when the page was full; absent = end of set.
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  })
}

export function useMintAgentEnrollToken() {
  return useMutation({
    mutationFn: (input: MintAgentEnrollTokenInput) =>
      apiFetch<AgentEnrollToken>('/agents/enroll-tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
  })
}

/** Flatten the paged result into the agent rows fetched so far. */
export function flattenAgents(pages: AgentsPage[] | undefined): Agent[] {
  return (pages ?? []).flatMap((p) => p.items)
}
