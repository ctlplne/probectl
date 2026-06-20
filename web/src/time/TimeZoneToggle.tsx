import { shortTimeZoneLabel, UTC_TIME_ZONE, type TimeMode } from './format'
import { useTime } from './useTime'
import styles from './TimeZoneToggle.module.css'

export function TimeZoneToggle() {
  const { mode, setMode, preferredTimeZone, timeZoneLabel } = useTime()
  const preferredLabel = shortTimeZoneLabel(preferredTimeZone)
  const preferredIsUtc = preferredTimeZone === UTC_TIME_ZONE

  if (preferredIsUtc) {
    return (
      <div className={styles.toggle} role="group" aria-label="Time zone display">
        <ToggleButton
          label={UTC_TIME_ZONE}
          mode="utc"
          active
          title="Show times in UTC"
          onSelect={setMode}
        />
      </div>
    )
  }

  return (
    <div className={styles.toggle} role="group" aria-label="Time zone display">
      <ToggleButton
        label={preferredLabel}
        mode="preferred"
        active={mode === 'preferred'}
        title={`Show times in preferred zone: ${preferredTimeZone}`}
        onSelect={setMode}
      />
      <ToggleButton
        label={UTC_TIME_ZONE}
        mode="utc"
        active={mode === 'utc'}
        title={`Show times in UTC (current: ${timeZoneLabel})`}
        onSelect={setMode}
      />
    </div>
  )
}

function ToggleButton({
  label,
  mode,
  active,
  disabled = false,
  title,
  onSelect,
}: {
  label: string
  mode: TimeMode
  active: boolean
  disabled?: boolean
  title: string
  onSelect: (mode: TimeMode) => void
}) {
  return (
    <button
      type="button"
      className={styles.button}
      aria-pressed={active}
      disabled={disabled}
      title={title}
      onClick={() => onSelect(mode)}
    >
      {label}
    </button>
  )
}
