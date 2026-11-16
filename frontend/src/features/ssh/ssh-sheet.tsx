import { X } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { $api } from "@/api/client"
import type { SshCertificateDetail, SshCertificateItem } from "@/api/types"
import { CopyButton, Identifier } from "@/components/copy-button"
import {
  DefinitionList,
  ErrorState,
  LineTabs,
  Loading,
  Mono,
  Pill,
  StatusDot,
  certificateState,
} from "@/components/kit"
import { Button } from "@/components/ui/button"
import { formatDateTime } from "@/lib/format"
import { sshExpiryLabel } from "./expiry"

type Tab = "details" | "key"

/** An SSH certificate's details beside the list: overlays the content, the list stays usable. */
export function SshSheet({
  serial,
  preview,
  onClose,
}: {
  serial: string
  preview?: SshCertificateItem
  onClose: () => void
}) {
  const [tab, setTab] = useState<Tab>("details")
  const detail = $api.useQuery("get", "/api/v1/ssh/certificates/{serial}", { params: { path: { serial } } })
  const panel = useRef<HTMLElement>(null)
  // Another certificate: back to its details, and focus on the panel for keyboard users
  const [shown, setShown] = useState(serial)
  if (shown !== serial) {
    setShown(serial)
    setTab("details")
  }
  useEffect(() => {
    panel.current?.focus()
  }, [serial])
  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !document.querySelector("[role=dialog],[role=alertdialog]")) onClose()
    }
    document.addEventListener("keydown", close)
    return () => document.removeEventListener("keydown", close)
  }, [onClose])

  const cert = detail.data?.certificate ?? preview
  const state = cert ? certificateState(cert.status, false) : null
  return (
    <aside
      ref={panel}
      tabIndex={-1}
      aria-label="SSH certificate details"
      className="fixed top-14 right-0 bottom-0 z-20 flex w-[440px] max-w-full flex-col border-l bg-card shadow-[-12px_0_32px_rgba(9,9,11,0.08)] outline-none"
    >
      <div className="flex items-start justify-between gap-2 border-b border-border-subtle px-4 py-3.5">
        <div className="min-w-0">
          <p className="font-mono text-sm font-medium [overflow-wrap:anywhere]">{cert?.key_id || serial}</p>
          {cert && state && (
            <p className="mt-1">
              <StatusDot tone={state.tone}>
                {state.label} · {sshExpiryLabel(cert)}
              </StatusDot>
            </p>
          )}
        </div>
        <Button variant="ghost" size="icon-sm" onClick={onClose} aria-label="Close details">
          <X className="size-4" />
        </Button>
      </div>
      <LineTabs
        size="sm"
        label="Detail sections"
        className="px-4"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "details", label: "Details" },
          { value: "key", label: "Certificate file" },
        ]}
      />
      <div className="flex-1 overflow-y-auto px-4 py-3.5">
        {detail.error ? (
          <ErrorState error={detail.error} onRetry={() => detail.refetch()} />
        ) : !detail.data ? (
          <Loading lines={6} className="px-0" />
        ) : tab === "details" ? (
          <Details detail={detail.data} />
        ) : (
          <div className="flex flex-col gap-2">
            {detail.data.public_line ? (
              <>
                <p className="text-[13px] text-muted-foreground">
                  The contents of an <Mono>id_*-cert.pub</Mono> file: <Mono>ssh-keygen -L -f</Mono> reads it.
                </p>
                <div className="flex justify-end">
                  <CopyButton value={detail.data.public_line} label="certificate" />
                </div>
                <pre className="rounded-lg border border-border-subtle bg-sidebar p-3 font-mono text-[11px] leading-relaxed [overflow-wrap:anywhere] whitespace-pre-wrap">
                  {detail.data.public_line}
                </pre>
              </>
            ) : (
              <p className="text-[13px] text-muted-foreground">This certificate cannot be shown as a file.</p>
            )}
          </div>
        )}
      </div>
      <div className="flex flex-wrap gap-2 border-t border-border-subtle px-4 py-3">
        <Button variant="outline" size="md" asChild>
          <a
            href={`/api/v1/ssh/certificates/${encodeURIComponent(serial)}/download`}
            download
            className="text-foreground no-underline hover:text-foreground"
          >
            Download
          </a>
        </Button>
      </div>
    </aside>
  )
}

function Details({ detail }: { detail: SshCertificateDetail }) {
  const { certificate: cert } = detail
  const reason = detail.revocation
    ? `${detail.revocation.reason || "No reason given"}${detail.revocation.reason_code !== null ? ` (code ${detail.revocation.reason_code})` : ""}`
    : null
  return (
    <div className="flex flex-col gap-5">
      {cert.error && (
        <p
          role="alert"
          className="rounded-lg border border-danger-border bg-danger-bg px-3 py-2 text-[13px] text-danger-fg"
        >
          This certificate cannot be read: {cert.error}.
        </p>
      )}
      <DefinitionList
        rows={[
          [
            "Type",
            cert.kind ? (
              <Pill key="k" tone={cert.kind === "host" ? "brand" : "neutral"}>
                {cert.kind}
              </Pill>
            ) : (
              "—"
            ),
          ],
          [
            "Key ID",
            <Mono key="i" className="[overflow-wrap:anywhere]">
              {cert.key_id || "—"}
            </Mono>,
          ],
          [
            cert.kind === "host" ? "Hosts" : "Principals",
            <Mono key="p" className="[overflow-wrap:anywhere] whitespace-pre-line">
              {cert.principals.join("\n") || "—"}
            </Mono>,
          ],
          [
            "Serial",
            <span key="s" className="flex items-start gap-1">
              <Mono className="[overflow-wrap:anywhere]">{cert.serial}</Mono>
              <CopyButton value={cert.serial} label="serial" />
            </span>,
          ],
          ["Key", cert.key_type || "—"],
          ["Fingerprint", cert.fingerprint ? <Identifier key="f" value={cert.fingerprint} label="fingerprint" /> : "—"],
          [
            "Signed by",
            cert.ca_fingerprint ? <Identifier key="c" value={cert.ca_fingerprint} label="CA fingerprint" /> : "—",
          ],
          ["Valid from", cert.valid_after ? formatDateTime(cert.valid_after) : cert.error ? "—" : "the beginning"],
          ["Valid until", cert.valid_before ? formatDateTime(cert.valid_before) : cert.error ? "—" : "never expires"],
          ...(detail.revocation
            ? ([
                ["Revoked", formatDateTime(detail.revocation.revoked_at)],
                ["Reason", reason],
                ["Revoked by", detail.revocation.provisioner_name ?? "—"],
              ] as [React.ReactNode, React.ReactNode][])
            : []),
        ]}
      />
      <Section title="Critical options" empty="None: the certificate has no restrictions.">
        {detail.critical_options.map((option) => (
          <li key={option.name}>
            <Mono>{option.name}</Mono>
            {option.value && <Mono className="text-muted-foreground"> = {option.value}</Mono>}
          </li>
        ))}
      </Section>
      <Section title="Extensions" empty="None.">
        {detail.extensions.map((extension) => (
          <li key={extension.name}>
            <Mono>{extension.name}</Mono>
            {extension.value && <Mono className="text-muted-foreground"> = {extension.value}</Mono>}
          </li>
        ))}
      </Section>
    </div>
  )
}

function Section({ title, empty, children }: { title: string; empty: string; children: React.ReactNode[] }) {
  return (
    <div>
      <h3 className="mb-1.5 text-xs font-medium text-muted-foreground">{title}</h3>
      {children.length ? (
        <ul className="flex flex-col gap-1">{children}</ul>
      ) : (
        <p className="text-[13px] text-muted-foreground">{empty}</p>
      )}
    </div>
  )
}
