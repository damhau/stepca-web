import type { CertificateStatus } from "@/api/types"
import { formatDate, fromNow, lifetime } from "@/lib/format"
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

const LABEL = {
  valid: "text-muted-foreground",
  expiring: "text-expiring",
  expired: "text-muted-foreground",
  revoked: "text-revoked",
  pending: "text-muted-foreground",
  neutral: "text-muted-foreground",
} as const

type Props = {
  notBefore: string | null
  notAfter: string | null
  status: CertificateStatus
  expiring: boolean
  revokedAt?: string | null
  className?: string
}

/** Where a certificate is in its lifetime: the elapsed part of the bar, and what is left. */
export function ValidityBar({ notBefore, notAfter, status, expiring, revokedAt, className }: Props) {
  const span = lifetime(notBefore, notAfter)
  if (!span) return <span className="text-muted-foreground">—</span>
  const tone = certificateTone(status, expiring)
  const label =
    status === "revoked"
      ? revokedAt
        ? `revoked ${fromNow(revokedAt)}`
        : "revoked"
      : status === "not_yet_valid"
        ? `starts ${fromNow(notBefore)}`
        : status === "valid"
          ? `ends ${fromNow(notAfter)}`
          : `ended ${fromNow(notAfter)}`
  return (
    <div
      className={cn("flex min-w-32 flex-col gap-1", className)}
      title={`${formatDate(notBefore)} to ${formatDate(notAfter)}`}
    >
      <div
        className="h-1.5 overflow-hidden rounded-full bg-track"
        role="meter"
        aria-label="Lifetime elapsed"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(span.elapsed * 100)}
      >
        <div
          className={cn("h-full rounded-full", FILL[tone])}
          style={{ width: `${Math.max(span.elapsed * 100, 2)}%` }}
        />
      </div>
      <span className={cn("text-xs", LABEL[tone])}>{label}</span>
    </div>
  )
}
