import { Link } from "@tanstack/react-router"
import { ChevronDown, X } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { $api } from "@/api/client"
import { useCan } from "@/api/session"
import type { CertificateItem } from "@/api/types"
import { CopyButton } from "@/components/copy-button"
import {
  certificateState,
  DefinitionList,
  ErrorState,
  LineTabs,
  Loading,
  Mono,
  StatusDot,
  type Tone,
} from "@/components/kit"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { colonHex, formatDateTime, keyLabel } from "@/lib/format"
import { expiryLabel } from "./expiry"

type Tab = "details" | "events" | "pem"

const EVENT_TONES: Record<string, Tone> = {
  issued: "success",
  ok: "success",
  info: "neutral",
  revoked: "danger",
  expires: "brand",
  expired: "neutral",
}

/** A certificate's details beside the list: overlays the content, the list stays usable. */
export function CertificateSheet({
  serial,
  preview,
  onClose,
  onRevoke,
}: {
  serial: string
  preview?: CertificateItem
  onClose: () => void
  onRevoke: (target: { serial: string; name: string }) => void
}) {
  const can = useCan()
  const [tab, setTab] = useState<Tab>("details")
  const detail = $api.useQuery("get", "/api/v1/certificates/{serial}", { params: { path: { serial } } })
  const events = $api.useQuery(
    "get",
    "/api/v1/certificates/{serial}/events",
    { params: { path: { serial } } },
    { enabled: tab === "events" },
  )
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
  const name = cert ? (cert.common_name ?? cert.subject) : serial
  const state = cert ? certificateState(cert.status, cert.expiring) : null
  const download = (format: string) =>
    `/api/v1/certificates/${serial}/download${format === "pem" ? "" : `?format=${format}`}`
  return (
    <aside
      ref={panel}
      tabIndex={-1}
      aria-label="Certificate details"
      className="fixed top-14 right-0 bottom-0 z-20 flex w-[440px] max-w-full flex-col border-l bg-card shadow-[-12px_0_32px_rgba(9,9,11,0.08)] outline-none"
    >
      <div className="flex items-start justify-between gap-2 border-b border-border-subtle px-4 py-3.5">
        <div className="min-w-0">
          <p className="font-mono text-sm font-medium [overflow-wrap:anywhere]">{name}</p>
          {cert && state && (
            <p className="mt-1">
              <StatusDot tone={state.tone}>
                {state.label} · {expiryLabel(cert)}
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
          { value: "events", label: "Events" },
          { value: "pem", label: "PEM" },
        ]}
      />
      <div className="flex-1 overflow-y-auto px-4 py-3.5">
        {detail.error ? (
          <ErrorState error={detail.error} onRetry={() => detail.refetch()} />
        ) : !detail.data ? (
          <Loading lines={6} className="px-0" />
        ) : tab === "details" ? (
          <div className="flex flex-col gap-5">
            <DefinitionList
              rows={[
                [
                  "SANs",
                  <Mono key="s" className="whitespace-pre-line">
                    {detail.data.certificate.dns_names.join("\n") || "—"}
                  </Mono>,
                ],
                [
                  "Serial",
                  <span key="h" className="flex items-start gap-1">
                    <Mono className="[overflow-wrap:anywhere]">{colonHex(detail.data.certificate.serial_hex)}</Mono>
                    <CopyButton value={detail.data.certificate.serial} label="decimal serial" />
                  </span>,
                ],
                [
                  "Provisioner",
                  detail.data.certificate.provisioner_name ? (
                    <Link key="p" to="/provisioners/$name" params={{ name: detail.data.certificate.provisioner_name }}>
                      {detail.data.certificate.provisioner_name}
                    </Link>
                  ) : (
                    "—"
                  ),
                ],
                ["Key", keyLabel(detail.data.certificate.key)],
                ["Valid from", formatDateTime(detail.data.certificate.not_before)],
                ["Valid until", formatDateTime(detail.data.certificate.not_after)],
                ["Issuer", detail.data.certificate.issuer],
                ...(detail.data.acme_order_id
                  ? ([
                      [
                        "ACME order",
                        <Link
                          key="o"
                          to="/acme/orders/$id"
                          params={{ id: detail.data.acme_order_id }}
                          className="font-mono text-[13px]"
                        >
                          {detail.data.acme_order_id.slice(0, 16)}…
                        </Link>,
                      ],
                    ] as [React.ReactNode, React.ReactNode][])
                  : []),
                ...(detail.data.revocation
                  ? ([
                      ["Revoked", formatDateTime(detail.data.revocation.revoked_at)],
                      [
                        "Reason",
                        `${detail.data.revocation.reason || "No reason given"}${detail.data.revocation.reason_code !== null ? ` (code ${detail.data.revocation.reason_code})` : ""}`,
                      ],
                    ] as [React.ReactNode, React.ReactNode][])
                  : []),
              ]}
            />
            <details className="text-[13px]">
              <summary className="min-h-7 cursor-pointer text-fg-2">Extensions</summary>
              <div className="mt-2">
                <DefinitionList
                  labelWidth="150px"
                  rows={detail.data.extensions.map((extension) => [
                    <span key="n">
                      {extension.name}
                      {extension.critical && <span className="text-muted-foreground"> · critical</span>}
                    </span>,
                    extension.value,
                  ])}
                />
              </div>
            </details>
          </div>
        ) : tab === "events" ? (
          events.error ? (
            <ErrorState error={events.error} onRetry={() => events.refetch()} />
          ) : !events.data ? (
            <Loading lines={3} className="px-0" />
          ) : (
            <ol className="flex flex-col gap-3 text-[13px]">
              {events.data.items.map((event, index) => (
                <li key={index} className="grid grid-cols-[14px_minmax(0,1fr)] gap-2.5">
                  <span
                    className={`mt-[5px] size-2 rounded-full ${dot(EVENT_TONES[event.kind] ?? "neutral")}`}
                    aria-hidden
                  />
                  <div>
                    <p className="font-medium">{event.label}</p>
                    <p className="mt-0.5 text-muted-foreground">{formatDateTime(event.at)}</p>
                  </div>
                </li>
              ))}
            </ol>
          )
        ) : (
          <div className="flex flex-col gap-2">
            <div className="flex justify-end">
              <CopyButton value={detail.data.pem} label="PEM" />
            </div>
            <pre className="rounded-lg border border-border-subtle bg-sidebar p-3 font-mono text-[11px] leading-relaxed [overflow-wrap:anywhere] whitespace-pre-wrap">
              {detail.data.pem}
            </pre>
          </div>
        )}
      </div>
      <div className="flex flex-wrap gap-2 border-t border-border-subtle px-4 py-3">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button size="md">
              Download <ChevronDown />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuItem asChild>
              <a href={download("pem")} download className="text-foreground no-underline">
                Certificate (PEM)
              </a>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href={download("chain")} download className="text-foreground no-underline">
                With its chain (PEM)
              </a>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href={download("der")} download className="text-foreground no-underline">
                Certificate (DER)
              </a>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        {can("operator") && cert && cert.status !== "revoked" && (
          <Button variant="destructive" size="md" className="ml-auto" onClick={() => onRevoke({ serial, name })}>
            Revoke
          </Button>
        )}
      </div>
    </aside>
  )
}

function dot(tone: Tone) {
  return {
    success: "bg-success",
    warning: "bg-warning",
    danger: "bg-danger",
    neutral: "bg-neutral-dot",
    brand: "bg-brand",
  }[tone]
}
