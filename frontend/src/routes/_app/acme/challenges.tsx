import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AcmeChallengeItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { ExportLink, FilterInput, Toolbar } from "@/components/list-toolbar"
import { PageHeader } from "@/components/page"
import { AcmeStatusPill } from "@/components/status"
import { AcmeLink, acmeQuery, acmeSearch, StatusFilter, type AcmeSearch } from "@/features/acme"
import { formatDateTime } from "@/lib/format"

const STATUSES = ["pending", "processing", "valid", "invalid"] as const

export const Route = createFileRoute("/_app/acme/challenges")({
  validateSearch: acmeSearch(STATUSES),
  component: Challenges,
})

const helper = columnHelper<AcmeChallengeItem>()
const columns = helper.columns([
  helper.accessor("type", {
    header: "Type",
    cell: ({ getValue }) => <span className="font-medium">{getValue()}</span>,
  }),
  helper.accessor("value", { header: "For" }),
  helper.accessor("status", {
    header: "Status",
    cell: ({ row }) => (
      <div className="flex flex-col items-start gap-1">
        <AcmeStatusPill status={row.original.status} />
        {row.original.error && (
          <span className="max-w-72 text-xs whitespace-normal text-revoked">{row.original.error}</span>
        )}
      </div>
    ),
  }),
  helper.accessor("validated_at", { header: "Validated", cell: ({ getValue }) => formatDateTime(getValue()) }),
  helper.accessor("created_at", { header: "Created", cell: ({ getValue }) => formatDateTime(getValue()) }),
  helper.accessor("order_id", { header: "Order", cell: ({ getValue }) => <AcmeLink kind="order" id={getValue()} /> }),
])

function Challenges() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const query = acmeQuery(search)
  const list = $api.useQuery(
    "get",
    "/api/v1/acme/challenges",
    { params: { query } },
    { placeholderData: keepPreviousData },
  )
  const update = (changes: Partial<AcmeSearch>) =>
    navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true })
  return (
    <>
      <PageHeader
        title="ACME challenges"
        description="The ways a client offered to prove control of a name (http-01, dns-01, tls-alpn-01), and which one worked."
        actions={<ExportLink path="/api/v1/acme/challenges" query={query} />}
      />
      <Toolbar>
        <FilterInput
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Filter by name, type or id"
        />
        <StatusFilter value={search.status} statuses={STATUSES} onChange={(status) => update({ status })} />
      </Toolbar>
      <DataTable
        label="ACME challenges"
        columns={columns}
        rows={list.data?.items}
        rowId={(row) => row.id}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty="No ACME challenge here."
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
