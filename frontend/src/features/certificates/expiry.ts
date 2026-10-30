import type { CertificateItem } from "@/api/types"
import { fromNow } from "@/lib/format"

/** "in 14 hours", "29 days ago", "revoked yesterday": the list's Expires column. */
export function expiryLabel(cert: Pick<CertificateItem, "status" | "not_after" | "not_before" | "revoked_at">) {
  if (cert.status === "revoked") return `revoked ${fromNow(cert.revoked_at)}`
  if (cert.status === "not_yet_valid") return `starts ${fromNow(cert.not_before)}`
  return fromNow(cert.not_after)
}
