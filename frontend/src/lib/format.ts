const DATE = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" })
const DATE_TIME = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  timeZoneName: "short",
})
const NUMBER = new Intl.NumberFormat()

export function formatDate(value: string | null | undefined) {
  return value ? DATE.format(new Date(value)) : "—"
}

export function formatDateTime(value: string | null | undefined) {
  return value ? DATE_TIME.format(new Date(value)) : "—"
}

export function formatNumber(value: number) {
  return NUMBER.format(value)
}

export function plural(count: number, one: string, many = `${one}s`) {
  return `${formatNumber(count)} ${count === 1 ? one : many}`
}

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

/** "in 12 days", "3 hours ago", "in 20 minutes": the distance of a date from now, in the unit that suits it. */
export function fromNow(value: string | null | undefined, now = Date.now()) {
  if (!value) return "—"
  const distance = new Date(value).getTime() - now
  const size = Math.abs(distance)
  const amount =
    size < HOUR
      ? plural(Math.max(Math.round(size / MINUTE), 1), "minute")
      : size < 2 * DAY
        ? plural(Math.round(size / HOUR), "hour")
        : plural(Math.round(size / DAY), "day")
  return distance >= 0 ? `in ${amount}` : `${amount} ago`
}

/** A certificate's lifetime: how much of it has passed (0 to 1), and its length in days. */
export function lifetime(notBefore: string | null, notAfter: string | null, now = Date.now()) {
  if (!notBefore || !notAfter) return null
  const start = new Date(notBefore).getTime()
  const end = new Date(notAfter).getTime()
  const span = Math.max(end - start, 1)
  return { elapsed: Math.min(Math.max((now - start) / span, 0), 1), days: span / DAY, start, end }
}
