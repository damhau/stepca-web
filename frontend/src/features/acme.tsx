import { Link, useRouterState } from "@tanstack/react-router"
import type { AcmeIdentifier } from "@/api/types"
import { plural } from "@/lib/format"
import { listSearch, oneOf, type ListSearch } from "@/lib/search-params"
import { cn } from "@/lib/utils"

export type AcmeSearch = ListSearch & { status?: string }

export function acmeSearch(statuses: readonly string[]) {
  return (search: Record<string, unknown>): AcmeSearch => ({
    ...listSearch(search),
    status: oneOf(search.status, statuses),
  })
}

export function acmeQuery(search: AcmeSearch) {
  return { page: search.page ?? 1, per_page: 50, q: search.q, status: search.status }
}

const TABS = [
  { to: "/acme/orders", label: "Orders" },
  { to: "/acme/accounts", label: "Accounts" },
  { to: "/acme/authorizations", label: "Authorizations" },
  { to: "/acme/challenges", label: "Challenges" },
  { to: "/acme/certificates", label: "Certificates" },
] as const

/** The ACME pages, as tabs under one heading. */
export function AcmeHeader({ description, actions }: { description: string; actions?: React.ReactNode }) {
  const path = useRouterState({ select: (state) => state.location.pathname })
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-[-0.02em]">ACME</h1>
          <p className="mt-1 text-muted-foreground">{description}</p>
        </div>
        {actions && <div className="flex gap-2">{actions}</div>}
      </div>
      <nav
        aria-label="ACME objects"
        className="flex [scrollbar-width:none] gap-5 overflow-x-auto shadow-[inset_0_-1px_0_var(--border)]"
      >
        {TABS.map((tab) => {
          const current = path === tab.to
          return (
            <Link
              key={tab.to}
              to={tab.to}
              aria-current={current ? "page" : undefined}
              className={cn(
                "inline-flex min-h-10 shrink-0 items-center border-b-2 px-0.5 font-medium whitespace-nowrap no-underline",
                current
                  ? "border-foreground text-foreground hover:text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              {tab.label}
            </Link>
          )
        })}
      </nav>
    </>
  )
}

/** While the app's copy of step-ca's ACME tables is first built, the lists say how much is left. */
export function StillReading({ pending, noun }: { pending?: number; noun: string }) {
  if (!pending) return null
  return <span className="text-[13px] text-muted-foreground">Still reading {plural(pending, noun)} from step-ca…</span>
}

export function Identifiers({ values }: { values: AcmeIdentifier[] }) {
  if (values.length === 0) return <span className="text-muted-foreground">—</span>
  return (
    <span className="font-mono text-[13px] break-words">
      {values
        .map((identifier) =>
          identifier.type === "dns" ? identifier.value : `${identifier.value} (${identifier.type})`,
        )
        .join(", ")}
    </span>
  )
}

/** A short form of an ACME id (they are long random strings), linking to its page. */
export function AcmeLink({ kind, id }: { kind: "account" | "order"; id: string | null }) {
  if (!id) return <span className="text-muted-foreground">—</span>
  const label = (
    <code className="font-mono text-[13px]" title={id}>
      {id.length > 14 ? `${id.slice(0, 12)}…` : id}
    </code>
  )
  return kind === "account" ? (
    <Link to="/acme/accounts/$id" params={{ id }}>
      {label}
    </Link>
  ) : (
    <Link to="/acme/orders/$id" params={{ id }}>
      {label}
    </Link>
  )
}

export function CertificateLink({ serial, name }: { serial: string | null; name?: string | null }) {
  if (!serial) return <span className="text-muted-foreground">—</span>
  return (
    <Link to="/certificates" search={{ cert: serial }} className="font-mono text-[13px]" title={serial}>
      {name ?? (serial.length > 14 ? `${serial.slice(0, 12)}…` : serial)}
    </Link>
  )
}
