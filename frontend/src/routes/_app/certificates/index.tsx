import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import { AlertTriangle, Download, MoreHorizontal, ShieldOff } from "lucide-react"
import { useCallback, useState } from "react"
import { $api } from "@/api/client"
import { useCan } from "@/api/session"
import type { CertificateItem } from "@/api/types"
import { Identifier } from "@/components/copy-button"
import { columnHelper, DataTable, type SortOrder } from "@/components/data-table"
import { ExportLink, FilterInput, Toolbar } from "@/components/list-toolbar"
import { PageHeader } from "@/components/page"
import { CertificateStatusPill } from "@/components/status"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ValidityBar } from "@/components/validity-bar"
import { RevokeDialog } from "@/features/certificates/revoke-dialog"
import { SignDialog } from "@/features/certificates/sign-dialog"
import { formatDateTime, plural } from "@/lib/format"
import { int, listSearch, oneOf, text, type ListSearch } from "@/lib/search-params"

const STATUSES = ["all", "valid", "expiring", "expired", "not_yet_valid", "revoked"] as const
const SORTS = ["not_after", "not_before", "subject", "serial", "provisioner"] as const
const EXPIRING_WINDOWS = [7, 30, 90]

type Search = ListSearch & {
  status?: (typeof STATUSES)[number]
  days?: number
  provisioner?: string
  sort?: (typeof SORTS)[number]
  order?: SortOrder
}

export const Route = createFileRoute("/_app/certificates/")({
  validateSearch: (search: Record<string, unknown>): Search => ({
    ...listSearch(search),
    status: oneOf(search.status, STATUSES),
    days: int(search.days, 1, 3650),
    provisioner: text(search.provisioner),
    sort: oneOf(search.sort, SORTS),
    order: oneOf(search.order, ["asc", "desc"] as const),
  }),
  component: Certificates,
})

const TABS: { status: Search["status"]; label: string }[] = [
  { status: "all", label: "All" },
  { status: "valid", label: "Valid" },
  { status: "expiring", label: "Expiring" },
  { status: "expired", label: "Expired" },
  { status: "revoked", label: "Revoked" },
]

const helper = columnHelper<CertificateItem>()

function Certificates() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const can = useCan()
  const [revoking, setRevoking] = useState<{ serial: string; name: string } | null>(null)
  const status = search.status ?? "all"
  const query = {
    status,
    days: status === "expiring" ? (search.days ?? 30) : undefined,
    q: search.q,
    provisioner: search.provisioner,
    sort: search.sort ?? (status === "expiring" ? "not_after" : "not_before"),
    order: search.order ?? (status === "expiring" ? "asc" : "desc"),
    page: search.page ?? 1,
    per_page: search.per_page ?? 50,
  } as const
  const list = $api.useQuery(
    "get",
    "/api/v1/certificates",
    { params: { query } },
    { placeholderData: keepPreviousData },
  )
  const provisioners = $api.useQuery("get", "/api/v1/certificates/provisioners", {}, { staleTime: 60_000 })
  const update = useCallback(
    (changes: Partial<Search>) =>
      navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true }),
    [navigate],
  )

  const columns = helper.columns([
    helper.accessor("subject", {
      header: "Certificate",
      meta: { sortKey: "subject" },
      cell: ({ row }) => {
        const item = row.original
        return (
          <div className="flex min-w-48 flex-col gap-0.5">
            <Link
              to="/certificates/$serial"
              params={{ serial: item.serial }}
              className="max-w-80 truncate font-medium underline-offset-4 hover:underline"
            >
              {item.common_name ?? item.subject ?? "—"}
            </Link>
            <span className="max-w-80 truncate text-xs text-muted-foreground" title={item.dns_names.join(", ")}>
              {item.dns_names.filter((name) => name !== item.common_name).join(", ") || item.subject}
            </span>
          </div>
        )
      },
    }),
    helper.accessor("status", {
      header: "Status",
      cell: ({ row }) => <CertificateStatusPill status={row.original.status} expiring={row.original.expiring} />,
    }),
    helper.accessor("not_after", {
      header: "Validity",
      meta: { sortKey: "not_after" },
      cell: ({ row }) => (
        <ValidityBar
          notBefore={row.original.not_before}
          notAfter={row.original.not_after}
          status={row.original.status}
          expiring={row.original.expiring}
          revokedAt={row.original.revoked_at}
        />
      ),
    }),
    ...(status === "revoked"
      ? [
          helper.accessor("revoked_at", {
            header: "Revoked",
            cell: ({ row }) => (
              <div className="flex flex-col text-sm">
                <span>{formatDateTime(row.original.revoked_at)}</span>
                <span className="text-xs text-muted-foreground">
                  {row.original.revocation_reason || "No reason given"}
                </span>
              </div>
            ),
          }),
        ]
      : []),
    helper.accessor("provisioner_name", {
      header: "Provisioner",
      meta: { sortKey: "provisioner" },
      cell: ({ getValue }) => getValue() ?? <span className="text-muted-foreground">—</span>,
    }),
    helper.accessor("serial", {
      header: "Serial",
      meta: { sortKey: "serial", className: "max-w-56" },
      cell: ({ getValue }) => <Identifier value={getValue()} label="serial" truncate />,
    }),
    helper.display({
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      meta: { className: "w-10" },
      cell: ({ row }) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={`Actions for ${row.original.common_name ?? row.original.serial}`}
            >
              <MoreHorizontal />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <a href={`/api/v1/certificates/${row.original.serial}/download`} download>
                <Download /> Download PEM
              </a>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href={`/api/v1/certificates/${row.original.serial}/download?format=chain`} download>
                <Download /> Download with its chain
              </a>
            </DropdownMenuItem>
            {can("operator") && row.original.status !== "revoked" && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  variant="destructive"
                  onSelect={() =>
                    setRevoking({ serial: row.original.serial, name: row.original.common_name ?? row.original.serial })
                  }
                >
                  <ShieldOff /> Revoke…
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    }),
  ])

  return (
    <>
      <PageHeader
        title="Certificates"
        description={
          status === "expiring"
            ? "Valid certificates that end soon. Those issued for 30 days or less are left out: they are meant to be renewed automatically."
            : "Every X.509 certificate step-ca has issued, however it was requested."
        }
        actions={
          <>
            <ExportLink path="/api/v1/certificates" query={query} />
            {can("operator") && <SignDialog />}
          </>
        }
      >
        <Tabs
          value={status}
          onValueChange={(value) => update({ status: value as Search["status"], sort: undefined, order: undefined })}
        >
          <TabsList>
            {TABS.map((tab) => (
              <TabsTrigger key={tab.status} value={tab.status ?? "all"}>
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </PageHeader>
      <Toolbar>
        <FilterInput
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Filter by name or serial"
        />
        <Select
          value={search.provisioner ?? "*"}
          onValueChange={(value) => update({ provisioner: value === "*" ? undefined : value })}
        >
          <SelectTrigger className="w-auto min-w-44" aria-label="Provisioner">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="*">Every provisioner</SelectItem>
            {provisioners.data?.names.map((name) => (
              <SelectItem key={name} value={name}>
                {name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {status === "expiring" && (
          <Select value={String(query.days)} onValueChange={(value) => update({ days: Number(value) })}>
            <SelectTrigger className="w-auto" aria-label="Expiring within">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {EXPIRING_WINDOWS.map((days) => (
                <SelectItem key={days} value={String(days)}>
                  Within {days} days
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {list.data && list.data.pending > 0 && (
          <span className="text-sm text-muted-foreground">
            Still reading {plural(list.data.pending, "certificate")} from step-ca…
          </span>
        )}
      </Toolbar>
      {status === "revoked" && <UnmatchedRevocations />}
      <DataTable
        label="Certificates"
        columns={columns}
        rows={list.data?.items}
        rowId={(row) => row.serial}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty={search.q || search.provisioner ? "No certificate matches these filters." : "No certificates here."}
        sorting={{
          sort: query.sort,
          order: query.order,
          onSort: (sort, order) => update({ sort: sort as Search["sort"], order }),
        }}
        paging={{
          total: list.data?.total ?? 0,
          page: query.page,
          perPage: query.per_page,
          onPage: (page) => navigate({ search: (previous) => ({ ...previous, page }) }),
          onPerPage: (per_page) => update({ per_page }),
        }}
      />
      <RevokeDialog target={revoking} onClose={() => setRevoking(null)} />
    </>
  )
}

/** Revocations of serials step-ca never issued: an older version of this UI revoked the wrong serial. */
function UnmatchedRevocations() {
  const { data } = $api.useQuery("get", "/api/v1/revocations/unmatched")
  const misdirected = data?.items.filter((item) => item.misdirected_serial) ?? []
  if (misdirected.length === 0) return null
  return (
    <div role="note" className="mb-4 rounded-lg border border-expiring/40 bg-expiring-soft/50 p-4 text-sm">
      <p className="flex items-center gap-2 font-medium">
        <AlertTriangle className="size-4 text-expiring" aria-hidden />
        {plural(misdirected.length, "revocation")} by an older version of this app missed the certificate
      </p>
      <p className="mt-1 text-muted-foreground">
        It revoked a serial that was never issued. These certificates are still valid: revoke them again.
      </p>
      <ul className="mt-2 flex flex-wrap gap-2">
        {misdirected.map((item) => (
          <li key={item.revocation.serial}>
            <Link
              to="/certificates/$serial"
              params={{ serial: item.misdirected_serial! }}
              className="font-mono text-xs text-primary underline-offset-4 hover:underline"
            >
              {item.misdirected_serial}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  )
}
