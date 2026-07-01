import type { ReactNode } from 'react'
import styles from './States.module.css'
import { Icon, type IconName } from './Icon'

export function EmptyState({
  icon = 'dashboards',
  title,
  description,
  action,
  preview,
}: {
  icon?: IconName
  title: string
  description?: ReactNode
  action?: ReactNode
  preview?: ReactNode
}) {
  return (
    <div className={styles.state}>
      <span className={styles.glyph}>
        <Icon name={icon} size={24} />
      </span>
      <h3 className={styles.title}>{title}</h3>
      {description ? <p className={styles.description}>{description}</p> : null}
      {action ? <div className={styles.action}>{action}</div> : null}
      {preview ? <div className={styles.preview}>{preview}</div> : null}
    </div>
  )
}

export function ErrorState({
  title = 'Something went wrong',
  description,
  action,
}: {
  title?: string
  description?: ReactNode
  action?: ReactNode
}) {
  return (
    <div className={styles.state} role="alert">
      <span className={[styles.glyph, styles.danger].join(' ')}>
        <Icon name="alert" size={24} />
      </span>
      <h3 className={styles.title}>{title}</h3>
      {description ? <p className={styles.description}>{description}</p> : null}
      {action ? <div className={styles.action}>{action}</div> : null}
    </div>
  )
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className={styles.state} aria-busy="true">
      <span className={styles.spinner} aria-hidden="true" />
      <p className={styles.description}>{label}</p>
    </div>
  )
}

export function Skeleton({
  width = '100%',
  height = 14,
}: {
  width?: string | number
  height?: string | number
}) {
  return <span className={styles.skeleton} style={{ width, height }} aria-hidden="true" />
}
