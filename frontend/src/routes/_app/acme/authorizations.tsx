import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AcmeAuthorizationItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { ExportLink, FilterInput, Toolbar } from "@/components/list-toolbar"
import { PageHeader } from "@/components/page"
import { AcmeStatusPill } from "@/components/status"
import { AcmeLink, acmeQuery, acmeSearch, StatusFilter, type AcmeSearch } from "@/features/acme"
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
      <span className="font-medium">
        {row.original.wildcard ? `*.${row.original.identifier.value}` : row.original.identifier.value}
      </span>
    ),
  }),
  helper.accessor("status", { header: "Status", cell: ({ getValue }) => <AcmeStatusPill status={getValue()} /> }),
  helper.accessor("challenge_ids", {
    header: "Challenges",
    cell: ({ getValue }) => plural(getValue().length, "challenge"),
  }),
  helper.accessor("created_at", { header: "Created", cell: ({ getValue }) => formatDateTime(getValue()) }),
  helper.accessor("expires_at", { header: "Expires", cell: ({ getValue }) => formatDateTime(getValue()) }),
  helper.accessor("order_id", { header: "Order", cell: ({ getValue }) => <AcmeLink kind="order" id={getValue()} /> }),
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
      <PageHeader
        title="ACME authorizations"
        description="A client's proof that it controls a name: one per name of an order."
        actions={<ExportLink path="/api/v1/acme/authorizations" query={query} />}
      />
      <Toolbar>
        <FilterInput
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Filter by name or id"
        />
        <StatusFilter value={search.status} statuses={STATUSES} onChange={(status) => update({ status })} />
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
          onPerPage: (per_page) => update({ per_page }),
        }}
      />
    </>
  )
}
