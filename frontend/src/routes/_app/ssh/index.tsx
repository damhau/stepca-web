import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { useCallback } from "react"
import { $api } from "@/api/client"
import type { SshCertificateItem } from "@/api/types"
import { columnHelper, DataTable, type SortOrder } from "@/components/data-table"
import { CertificateStatus, LineTabs, PageHeader, Pill } from "@/components/kit"
import { ChoiceFilter, ExportButton, SearchBox, Toolbar } from "@/components/list-tools"
import { sshExpiryLabel } from "@/features/ssh/expiry"
import { SshSheet } from "@/features/ssh/ssh-sheet"
import { formatNumber } from "@/lib/format"
import { int, oneOf, text } from "@/lib/search-params"
import { cn } from "@/lib/utils"

// The page opens on the active certificates: step-ca keeps every certificate it ever issued, and the expired ones pile up
const TABS = ["active", "expired", "revoked", "all"] as const
type Tab = (typeof TABS)[number]
const STATUS: Record<Tab, "valid" | "expired" | "revoked" | "all"> = {
  active: "valid",
  expired: "expired",
  revoked: "revoked",
  all: "all",
}
const EMPTY: Record<Tab, string> = {
  active: "No active SSH certificates.",
  expired: "No expired SSH certificates.",
  revoked: "No revoked SSH certificates.",
  all: "No SSH certificates yet. step-ca issues them once SSH is enabled on the authority.",
}
const KINDS = ["user", "host"] as const
const KIND_NAMES = { user: "User certificates", host: "Host certificates" }
const SORTS = ["valid_after", "valid_before", "key_id", "serial"] as const
const PER_PAGE = 50

type Search = {
  tab?: Tab
  kind?: (typeof KINDS)[number]
  q?: string
  sort?: (typeof SORTS)[number]
  order?: SortOrder
  page?: number
  cert?: string
}

export const Route = createFileRoute("/_app/ssh/")({
  validateSearch: (search: Record<string, unknown>): Search => ({
    tab: oneOf(search.tab, TABS),
    kind: oneOf(search.kind, KINDS),
    q: text(search.q),
    sort: oneOf(search.sort, SORTS),
    order: oneOf(search.order, ["asc", "desc"] as const),
    page: int(search.page),
    cert: text(search.cert, 80),
  }),
  component: SshCertificates,
})

// The newest first, except the expired: the ones that expired last come first
const DEFAULT_SORT: Record<Tab, { sort: (typeof SORTS)[number]; order: SortOrder }> = {
  active: { sort: "valid_after", order: "desc" },
  expired: { sort: "valid_before", order: "desc" },
  revoked: { sort: "valid_after", order: "desc" },
  all: { sort: "valid_after", order: "desc" },
}

const helper = columnHelper<SshCertificateItem>()

function SshCertificates() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const tab = search.tab ?? "active"
  const sort = search.sort ?? DEFAULT_SORT[tab].sort
  const order = search.order ?? DEFAULT_SORT[tab].order
  const page = search.page ?? 1
  const query = {
    kind: search.kind ?? "all",
    status: STATUS[tab],
    q: search.q,
    sort,
    order,
    page,
    per_page: PER_PAGE,
  } as const
  const list = $api.useQuery(
    "get",
    "/api/v1/ssh/certificates",
    { params: { query } },
    { placeholderData: keepPreviousData },
  )
  const counts = $api.useQuery(
    "get",
    "/api/v1/ssh/certificates/counts",
    { params: { query: { kind: search.kind ?? "all" } } },
    { staleTime: 30_000, placeholderData: keepPreviousData },
  )
  const update = useCallback(
    (changes: Partial<Search>) =>
      navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true }),
    [navigate],
  )
  const open = (serial?: string) => navigate({ search: (previous) => ({ ...previous, cert: serial }), replace: true })

  const columns = helper.columns([
    helper.accessor("key_id", {
      header: "Key ID",
      meta: { sortKey: "key_id" },
      cell: ({ row }) => (
        <button
          type="button"
          onClick={() => open(row.original.serial)}
          className="min-h-9 max-w-[22rem] truncate text-left font-mono text-[13px] font-medium text-foreground hover:underline"
          title={row.original.key_id || row.original.serial}
        >
          {row.original.key_id || row.original.serial}
        </button>
      ),
    }),
    helper.accessor("kind", {
      header: "Type",
      cell: ({ getValue }) =>
        getValue() ? <Pill tone={getValue() === "host" ? "brand" : "neutral"}>{getValue()}</Pill> : "—",
    }),
    helper.accessor("principals", {
      header: "Principals",
      meta: { className: "max-w-72 truncate font-mono text-xs text-fg-2" },
      cell: ({ getValue }) => <span title={getValue().join(", ")}>{getValue().join(", ") || "—"}</span>,
    }),
    helper.accessor("status", {
      header: "Status",
      cell: ({ row }) => <CertificateStatus status={row.original.status} expiring={false} />,
    }),
    helper.accessor("valid_before", {
      header: "Expires",
      meta: { sortKey: "valid_before", className: "whitespace-nowrap" },
      cell: ({ row }) => (
        <span
          className={cn(row.original.status === "valid" ? "text-foreground" : "text-muted-foreground")}
          title={row.original.valid_before ?? undefined}
        >
          {sshExpiryLabel(row.original)}
        </span>
      ),
    }),
    helper.accessor("key_type", {
      header: "Key",
      meta: { className: "pr-3 text-muted-foreground whitespace-nowrap" },
      cell: ({ getValue }) => getValue() || "—",
    }),
  ])

  const rows = list.data?.items
  const preview = rows?.find((row) => row.serial === search.cert)
  const count = (tabName: Tab) => (counts.data ? formatNumber(counts.data[STATUS[tabName]]) : undefined)

  return (
    <>
      <PageHeader
        title="SSH"
        description="User and host certificates issued by this authority."
        actions={<ExportButton path="/api/v1/ssh/certificates" query={{ ...query, per_page: undefined }} />}
      />
      <LineTabs
        label="Views"
        value={tab}
        onChange={(value) => update({ tab: value === "active" ? undefined : value, sort: undefined, order: undefined })}
        tabs={[
          { value: "active", label: "Active", count: count("active") },
          { value: "expired", label: "Expired", count: count("expired") },
          { value: "revoked", label: "Revoked", count: count("revoked") },
          { value: "all", label: "All", count: count("all") },
        ]}
      />
      <Toolbar>
        <SearchBox
          id="ssh-search"
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Search by key ID, principal or serial"
        />
        <ChoiceFilter
          label="Type"
          any="All types"
          value={search.kind}
          options={KINDS}
          names={KIND_NAMES}
          onChange={(kind) => update({ kind: oneOf(kind, KINDS) })}
        />
      </Toolbar>
      <DataTable
        label="SSH certificate list"
        columns={columns}
        rows={rows}
        rowId={(row) => row.serial}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty={search.q || search.kind ? "No SSH certificate matches these filters." : EMPTY[tab]}
        activeId={search.cert}
        sorting={{
          sort,
          order,
          onSort: (next, nextOrder) => update({ sort: next as Search["sort"], order: nextOrder }),
        }}
        paging={{
          total: list.data?.total ?? 0,
          page,
          perPage: PER_PAGE,
          onPage: (next) => navigate({ search: (previous) => ({ ...previous, page: next }) }),
        }}
      />
      {search.cert && <SshSheet serial={search.cert} preview={preview} onClose={() => open(undefined)} />}
    </>
  )
}
