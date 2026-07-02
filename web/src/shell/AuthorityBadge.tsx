import { Badge } from '../components'
import { useAuth } from '../auth/useAuth'
import { authorityPosture } from './authority'

export function AuthorityBadge() {
  const { permissions } = useAuth()
  const posture = authorityPosture(permissions)

  return (
    <span
      role="status"
      aria-label={`Authority posture: ${posture.label}`}
      title={posture.detail}
    >
      <Badge tone={posture.tone}>{posture.label}</Badge>
    </span>
  )
}
