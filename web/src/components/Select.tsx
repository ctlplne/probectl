import { useId, type SelectHTMLAttributes } from 'react'
import styles from './Input.module.css'

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label: string
  options: { value: string; label: string }[]
}

/** Select is a labeled native select, styled from the same field tokens as Field. */
export function Select({ label, options, id, className, ...rest }: SelectProps) {
  const reactId = useId()
  const selectId = id ?? reactId
  return (
    <div className={[styles.field, className].filter(Boolean).join(' ')}>
      <label className={styles.label} htmlFor={selectId}>
        {label}
      </label>
      <div className={styles.control}>
        <select id={selectId} className={styles.input} {...rest}>
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
    </div>
  )
}
