import type { ReactNode } from 'react'
import { useTime } from './useTime'

export type DateTimeValue = string | number | Date | undefined | null

export function DateTime({
  value,
  empty = '—',
  className,
}: {
  value: DateTimeValue
  empty?: ReactNode
  className?: string
}) {
  const { format } = useTime()
  const formatted = format(value)
  if (!formatted.text) return <>{empty}</>
  if (!formatted.valid) return <span className={className}>{formatted.text}</span>
  return (
    <time
      className={className}
      dateTime={formatted.dateTime}
      title={`${formatted.dateTime} (${formatted.timeZone})`}
    >
      {formatted.text}
    </time>
  )
}
