import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AcmeAuthorizationItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { AcmeStatus } from "@/components/kit"
import { ChoiceFilter, ExportButton, SearchBox, Toolbar } from "@/components/list-tools"
import { AcmeLink, acmeQuery, acmeSearch, AcmeHeader, type AcmeSearch, StillReading } from "@/features/acme"
import { formatDateTime, plural } from "@/lib/format"

const STATUSES = ["pending", "valid", "invalid", "deactivated", "expired", "revoked"] as const

export const Route = createFileRoute("/_app/acme/authorizations")({
  validateSearch: acmeSearch(STATUSES),
  component: Authorizations,
})

const helper = columnHelper<AcmeAuthorizationItem>()
const columns = helper.columns([
  helper.accessor("identifier", {
    header: "For",
    cell: ({ row }) => (
      <span className="font-mono text-[13px] font-medium">
        {row.original.wildcard ? `*.${row.original.identifier.value}` : row.original.identifier.value}
      </span>
    ),
  }),
  helper.accessor("status", { header: "Status", cell: ({ getValue }) => <AcmeStatus status={getValue()} /> }),
  helper.accessor("challenge_ids", {
    header: "Challenges",
    meta: { className: "text-fg-2" },
    cell: ({ getValue }) => plural(getValue().length, "challenge"),
  }),
  helper.accessor("expires_at", {
    header: "Expires",
    meta: { className: "whitespace-nowrap text-muted-foreground" },
    cell: ({ getValue }) => formatDateTime(getValue()),
  }),
  helper.accessor("order_id", {
    header: "Order",
    meta: { className: "pr-4" },
    cell: ({ getValue }) => <AcmeLink kind="order" id={getValue()} />,
  }),
])

function Authorizations() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const query = acmeQuery(search)
  const list = $api.useQuery(
    "get",
    "/api/v1/acme/authorizations",
    { params: { query } },
    { placeholderData: keepPreviousData },
  )
  const update = (changes: Partial<AcmeSearch>) =>
    navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true })
  return (
    <>
      <AcmeHeader
        description="A client's proof that it controls a name: one per name of an order."
        actions={<ExportButton path="/api/v1/acme/authorizations" query={query} />}
      />
      <Toolbar>
        <SearchBox
          id="acme-search"
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Search by name or id"
        />
        <ChoiceFilter
          label="Status"
          any="Any status"
          value={search.status}
          options={STATUSES}
          onChange={(status) => update({ status })}
        />
        <StillReading pending={list.data?.pending} noun="authorization" />
      </Toolbar>
      <DataTable
        label="ACME authorizations"
        columns={columns}
        rows={list.data?.items}
        rowId={(row) => row.id}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty="No ACME authorization here."
        paging={{
          total: list.data?.total ?? 0,
          page: query.page,
          perPage: query.per_page,
          onPage: (page) => navigate({ search: (previous) => ({ ...previous, page }) }),
        }}
      />
    </>
  )
}
