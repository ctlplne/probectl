import { useContext } from 'react'
import { TimeContext } from './context'

export function useTime() {
  const ctx = useContext(TimeContext)
  if (!ctx) throw new Error('useTime must be used inside TimeProvider')
  return ctx
}
