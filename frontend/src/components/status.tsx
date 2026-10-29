import type { CertificateStatus } from "@/api/types"
import { cn } from "@/lib/utils"

/** Valid certificates this close to their end are expiring, unless short-lived (the server decides: `expiring`). */
export const EXPIRING_DAYS = 30

type Tone = "valid" | "expiring" | "expired" | "revoked" | "pending" | "neutral"

const TONES: Record<Tone, string> = {
  valid: "bg-valid-soft text-valid",
  expiring: "bg-expiring-soft text-expiring",
  expired: "bg-expired-soft text-expired",
  revoked: "bg-revoked-soft text-revoked",
  pending: "bg-accent text-accent-foreground",
  neutral: "bg-muted text-muted-foreground",
}

export function Pill({ tone, children, className }: { tone: Tone; children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        TONES[tone],
        className,
      )}
    >
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {children}
    </span>
  )
}

export function certificateTone(status: CertificateStatus, expiring: boolean): Tone {
  if (status === "valid") return expiring ? "expiring" : "valid"
  if (status === "revoked") return "revoked"
  if (status === "not_yet_valid") return "pending"
  return "expired"
}

const CERTIFICATE_LABELS: Record<CertificateStatus, string> = {
  valid: "Valid",
  expired: "Expired",
  not_yet_valid: "Not yet valid",
  revoked: "Revoked",
  invalid: "Unreadable",
}

export function CertificateStatusPill({ status, expiring }: { status: CertificateStatus; expiring: boolean }) {
  const tone = certificateTone(status, expiring)
  return <Pill tone={tone}>{tone === "expiring" ? "Expiring" : CERTIFICATE_LABELS[status]}</Pill>
}

const ACME_TONES: Record<string, Tone> = {
  valid: "valid",
  ready: "pending",
  processing: "pending",
  pending: "expiring",
  invalid: "revoked",
  revoked: "revoked",
  deactivated: "expired",
  expired: "expired",
}

/** The status of an ACME account, order, authorization or challenge (RFC 8555). */
export function AcmeStatusPill({ status }: { status: string }) {
  return <Pill tone={ACME_TONES[status] ?? "neutral"}>{status || "unknown"}</Pill>
}
