import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AcmeChallengeItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { AcmeStatus } from "@/components/kit"
import { ChoiceFilter, ExportButton, SearchBox, Toolbar } from "@/components/list-tools"
import { AcmeLink, acmeQuery, acmeSearch, AcmeHeader, type AcmeSearch, StillReading } from "@/features/acme"
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
    cell: ({ getValue }) => <span className="font-mono text-[13px] font-medium">{getValue()}</span>,
  }),
  helper.accessor("value", {
    header: "For",
    cell: ({ getValue }) => <span className="font-mono text-[13px]">{getValue()}</span>,
  }),
  helper.accessor("status", {
    header: "Status",
    cell: ({ row }) => (
      <div className="flex flex-col items-start gap-0.5 py-1">
        <AcmeStatus status={row.original.status} />
        {row.original.error && (
          <span className="max-w-72 text-xs whitespace-normal text-danger-fg">{row.original.error}</span>
        )}
      </div>
    ),
  }),
  helper.accessor("validated_at", {
    header: "Validated",
    meta: { className: "whitespace-nowrap text-muted-foreground" },
    cell: ({ getValue }) => formatDateTime(getValue()),
  }),
  helper.accessor("order_id", {
    header: "Order",
    meta: { className: "pr-4" },
    cell: ({ getValue }) => <AcmeLink kind="order" id={getValue()} />,
  }),
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
      <AcmeHeader
        description="The ways a client offered to prove control of a name (http-01, dns-01, tls-alpn-01), and which one worked."
        actions={<ExportButton path="/api/v1/acme/challenges" query={query} />}
      />
      <Toolbar>
        <SearchBox
          id="acme-search"
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Search by name, type or id"
        />
        <ChoiceFilter
          label="Status"
          any="Any status"
          value={search.status}
          options={STATUSES}
          onChange={(status) => update({ status })}
        />
        <StillReading pending={list.data?.pending} noun="challenge" />
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
        }}
      />
    </>
  )
}
