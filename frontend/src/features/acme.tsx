import { Link } from "@tanstack/react-router"
import type { AcmeIdentifier } from "@/api/types"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { listSearch, oneOf, type ListSearch } from "@/lib/search-params"

export type AcmeSearch = ListSearch & { status?: string }

export function acmeSearch(statuses: readonly string[]) {
  return (search: Record<string, unknown>): AcmeSearch => ({
    ...listSearch(search),
    status: oneOf(search.status, statuses),
  })
}

export function acmeQuery(search: AcmeSearch) {
  return { page: search.page ?? 1, per_page: search.per_page ?? 50, q: search.q, status: search.status }
}

export function StatusFilter({
  value,
  statuses,
  onChange,
}: {
  value?: string
  statuses: readonly string[]
  onChange: (value?: string) => void
}) {
  return (
    <Select value={value ?? "*"} onValueChange={(next) => onChange(next === "*" ? undefined : next)}>
      <SelectTrigger className="w-auto min-w-36" aria-label="Status">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="*">Any status</SelectItem>
        {statuses.map((status) => (
          <SelectItem key={status} value={status} className="capitalize">
            {status}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

export function Identifiers({ values }: { values: AcmeIdentifier[] }) {
  if (values.length === 0) return <span className="text-muted-foreground">—</span>
  return (
    <span className="break-words">
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
    <code className="font-mono text-[0.8125rem]" title={id}>
      {id.length > 14 ? `${id.slice(0, 12)}…` : id}
    </code>
  )
  return kind === "account" ? (
    <Link to="/acme/accounts/$id" params={{ id }} className="underline-offset-4 hover:underline">
      {label}
    </Link>
  ) : (
    <Link to="/acme/orders/$id" params={{ id }} className="underline-offset-4 hover:underline">
      {label}
    </Link>
  )
}

export function CertificateLink({ serial }: { serial: string | null }) {
  if (!serial) return <span className="text-muted-foreground">—</span>
  return (
    <Link
      to="/certificates/$serial"
      params={{ serial }}
      className="font-mono text-[0.8125rem] underline-offset-4 hover:underline"
      title={serial}
    >
      {serial.length > 14 ? `${serial.slice(0, 12)}…` : serial}
    </Link>
  )
}
