import type { CertificateStatus } from "@/api/types"
import { formatDate, formatDateTime, fromNow, lifetime } from "@/lib/format"
import { cn } from "@/lib/utils"
import { certificateTone } from "./status"

const FILL = {
  valid: "bg-valid",
  expiring: "bg-expiring",
  expired: "bg-expired",
  revoked: "bg-revoked",
  pending: "bg-primary",
  neutral: "bg-expired",
} as const

/** A certificate's lifetime drawn to scale, with today marked on it. */
export function Lifetime({
  notBefore,
  notAfter,
  status,
  expiring,
  revokedAt,
}: {
  notBefore: string | null
  notAfter: string | null
  status: CertificateStatus
  expiring: boolean
  revokedAt: string | null
}) {
  const span = lifetime(notBefore, notAfter)
  if (!span) return null
  const tone = certificateTone(status, expiring)
  const revoked = revokedAt ? lifetime(notBefore, notAfter, new Date(revokedAt).getTime()) : null
  const headline =
    status === "revoked"
      ? `Revoked ${fromNow(revokedAt)}`
      : status === "not_yet_valid"
        ? `Valid from ${formatDate(notBefore)}, ${fromNow(notBefore)}`
        : status === "valid"
          ? `Expires ${fromNow(notAfter)}`
          : `Expired ${fromNow(notAfter)}`
  const length = span.days >= 2 ? `${Math.round(span.days)} days` : `${Math.round(span.days * 24)} hours`
  return (
    <div className="flex flex-col gap-3">
      <p
        className={cn(
          "text-lg font-medium",
          tone === "expiring" && "text-expiring",
          tone === "revoked" && "text-revoked",
        )}
      >
        {headline}
      </p>
      <div className="relative pt-6 pb-1">
        <div className="h-2.5 overflow-hidden rounded-full bg-track">
          <div
            className={cn("h-full rounded-full", FILL[tone])}
            style={{ width: `${(revoked ?? span).elapsed * 100}%` }}
          />
        </div>
        {status !== "revoked" && span.elapsed > 0 && span.elapsed < 1 && (
          <div
            className="absolute top-0 bottom-0 flex flex-col items-center"
            style={{ left: `${span.elapsed * 100}%` }}
          >
            <span className="-translate-x-1/2 text-xs font-medium whitespace-nowrap">Today</span>
            <span className="mt-0.5 h-full w-0.5 -translate-x-1/2 rounded-full bg-foreground" aria-hidden />
          </div>
        )}
      </div>
      <div className="flex flex-wrap justify-between gap-2 text-sm">
        <span>
          <span className="text-muted-foreground">From </span>
          {formatDateTime(notBefore)}
        </span>
        <span className="text-muted-foreground">{length}</span>
        <span>
          <span className="text-muted-foreground">To </span>
          {formatDateTime(notAfter)}
        </span>
      </div>
    </div>
  )
}
