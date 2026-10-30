import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AcmeAccountItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { AcmeStatus } from "@/components/kit"
import { ChoiceFilter, ExportButton, SearchBox, Toolbar } from "@/components/list-tools"
import { AcmeLink, acmeQuery, acmeSearch, AcmeHeader, type AcmeSearch } from "@/features/acme"
import { formatDateTime } from "@/lib/format"

const STATUSES = ["valid", "deactivated", "revoked"] as const

export const Route = createFileRoute("/_app/acme/accounts/")({
  validateSearch: acmeSearch(STATUSES),
  component: Accounts,
})

const helper = columnHelper<AcmeAccountItem>()
const columns = helper.columns([
  helper.accessor("contact", {
    header: "Contact",
    cell: ({ row }) => (
      <span className="font-medium">
        {row.original.contact.map((contact) => contact.replace(/^mailto:/, "")).join(", ") || "—"}
      </span>
    ),
  }),
  helper.accessor("status", { header: "Status", cell: ({ getValue }) => <AcmeStatus status={getValue()} /> }),
  helper.accessor("provisioner_name", {
    header: "Provisioner",
    meta: { className: "text-fg-2" },
    cell: ({ getValue }) => getValue() ?? "—",
  }),
  helper.accessor("id", { header: "Account", cell: ({ getValue }) => <AcmeLink kind="account" id={getValue()} /> }),
  helper.accessor("created_at", {
    header: "Created",
    meta: { className: "pr-4 whitespace-nowrap text-muted-foreground" },
    cell: ({ getValue }) => formatDateTime(getValue()),
  }),
])

function Accounts() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const query = acmeQuery(search)
  const list = $api.useQuery(
    "get",
    "/api/v1/acme/accounts",
    { params: { query } },
    { placeholderData: keepPreviousData },
  )
  const update = (changes: Partial<AcmeSearch>) =>
    navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true })
  return (
    <>
      <AcmeHeader
        description="The ACME clients (cert-manager, certbot, Caddy…) registered with step-ca, newest first."
        actions={<ExportButton path="/api/v1/acme/accounts" query={query} />}
      />
      <Toolbar>
        <SearchBox
          id="acme-search"
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Search by contact or id"
        />
        <ChoiceFilter
          label="Status"
          any="Any status"
          value={search.status}
          options={STATUSES}
          onChange={(status) => update({ status })}
        />
      </Toolbar>
      <DataTable
        label="ACME accounts"
        columns={columns}
        rows={list.data?.items}
        rowId={(row) => row.id}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty="No ACME account here."
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
