import type { SshCertificateItem } from "@/api/types"
import { fromNow } from "@/lib/format"

/** "in 14 hours", "29 days ago", "never", "revoked yesterday": the list's Expires column. */
export function sshExpiryLabel(
  cert: Pick<SshCertificateItem, "status" | "valid_after" | "valid_before" | "revoked_at">,
) {
  if (cert.status === "revoked") return `revoked ${fromNow(cert.revoked_at)}`
  if (cert.status === "not_yet_valid") return `starts ${fromNow(cert.valid_after)}`
  if (cert.status === "invalid") return "—"
  return cert.valid_before ? fromNow(cert.valid_before) : "never"
}
