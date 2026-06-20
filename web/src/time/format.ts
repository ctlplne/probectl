export const UTC_TIME_ZONE = 'UTC'

export type TimeMode = 'preferred' | 'utc'

export interface FormatDateTimeOptions {
  locale?: string
  timeZone?: string
}

export interface FormattedDateTime {
  text: string
  dateTime: string
  timeZone: string
  valid: boolean
}

export function resolveTimeZone(candidate?: string | null): string {
  const trimmed = candidate?.trim()
  if (!trimmed) return UTC_TIME_ZONE
  return isValidTimeZone(trimmed) ? trimmed : UTC_TIME_ZONE
}

export function isValidTimeZone(candidate: string): boolean {
  try {
    new Intl.DateTimeFormat('en', { timeZone: candidate }).format(new Date(0))
    return true
  } catch {
    return false
  }
}

export function formatDateTime(
  value: string | number | Date | undefined | null,
  options: FormatDateTimeOptions = {},
): FormattedDateTime {
  if (value === undefined || value === null || value === '') {
    return { text: '', dateTime: '', timeZone: options.timeZone ?? UTC_TIME_ZONE, valid: false }
  }
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) {
    return {
      text: String(value),
      dateTime: String(value),
      timeZone: options.timeZone ?? UTC_TIME_ZONE,
      valid: false,
    }
  }
  const timeZone = resolveTimeZone(options.timeZone)
  const locale = options.locale || 'en'
  const text = new Intl.DateTimeFormat(locale, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    timeZone,
    timeZoneName: 'short',
  }).format(date)
  return { text, dateTime: date.toISOString(), timeZone, valid: true }
}

export function shortTimeZoneLabel(timeZone: string): string {
  if (timeZone === UTC_TIME_ZONE) return UTC_TIME_ZONE
  const parts = timeZone.split('/')
  return parts[parts.length - 1]?.split('_').join(' ') || timeZone
}
