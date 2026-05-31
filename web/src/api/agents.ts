import { useQuery } from '@tanstack/react-query'
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

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => apiFetch<{ items: Agent[] }>('/agents').then((r) => r.items),
  })
}
