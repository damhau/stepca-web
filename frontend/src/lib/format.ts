const DATE = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" })
const DATE_TIME = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
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
const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })

/** "in 14 hours", "yesterday", "29 days ago": the distance of a date from now, in the unit that suits it. */
export function fromNow(value: string | null | undefined, now = Date.now()) {
  if (!value) return "—"
  const distance = new Date(value).getTime() - now
  const size = Math.abs(distance)
  if (size < HOUR) return RELATIVE.format(Math.sign(distance || 1) * Math.max(Math.round(size / MINUTE), 1), "minute")
  if (size < 2 * DAY) return RELATIVE.format(Math.round(distance / HOUR), "hour")
  // Years only for CA certificates and the like: an expiry within two years stays exact to the day
  if (size >= 730 * DAY) return RELATIVE.format(Math.round(distance / (365.25 * DAY)), "year")
  return RELATIVE.format(Math.round(distance / DAY), "day")
}

/** A certificate's lifetime: how much of it has passed (0 to 1), and its length in days. */
export function lifetime(notBefore: string | null, notAfter: string | null, now = Date.now()) {
  if (!notBefore || !notAfter) return null
  const start = new Date(notBefore).getTime()
  const end = new Date(notAfter).getTime()
  const span = Math.max(end - start, 1)
  return { elapsed: Math.min(Math.max((now - start) / span, 0), 1), days: span / DAY, start, end }
}

/** A serial as the step CLI prints it: hex bytes separated by colons. */
export function colonHex(hex: string) {
  const even = hex.length % 2 ? `0${hex}` : hex
  return even.match(/../g)?.join(":") ?? hex
}

const CURVES: Record<string, string> = {
  secp256r1: "P-256",
  prime256v1: "P-256",
  secp384r1: "P-384",
  secp521r1: "P-521",
}

/** A key type as people write it: "P-256" rather than the curve's OID name. */
export function keyLabel(key: string | null | undefined) {
  if (!key) return "—"
  return CURVES[key] ?? key
}

/**
 * A Go duration as people write it: "24h0m0s" becomes "24h", "2160h0m0s" "90d", "1h30m0s" "1h30m".
 * Without days, it stays a duration step-ca accepts ("2160h").
 */
export function shortDuration(value: string | null | undefined, { days = true } = {}) {
  if (!value) return value ?? null
  const units: Record<string, number> = { h: 3600, m: 60, s: 1, ms: 0.001, us: 0.000001, µs: 0.000001, ns: 0.000000001 }
  let seconds = 0
  for (const [, number, unit] of value.matchAll(/(\d+(?:\.\d+)?)(ms|us|µs|ns|h|m|s)/g))
    seconds += Number(number) * (units[unit!] ?? 0)
  if (!seconds || !Number.isInteger(seconds)) return value
  if (days && seconds >= 2 * 86400 && seconds % 86400 === 0) return `${seconds / 86400}d`
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const rest = seconds % 60
  return `${h ? `${h}h` : ""}${m ? `${m}m` : ""}${rest ? `${rest}s` : ""}`
}
