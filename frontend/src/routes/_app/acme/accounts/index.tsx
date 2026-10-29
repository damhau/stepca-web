import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AcmeAccountItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { ExportLink, FilterInput, Toolbar } from "@/components/list-toolbar"
import { PageHeader } from "@/components/page"
import { AcmeStatusPill } from "@/components/status"
import { AcmeLink, acmeQuery, acmeSearch, StatusFilter, type AcmeSearch } from "@/features/acme"
import { formatDateTime } from "@/lib/format"

const STATUSES = ["valid", "deactivated", "revoked"] as const

export const Route = createFileRoute("/_app/acme/accounts/")({
  validateSearch: acmeSearch(STATUSES),
  component: Accounts,
})

const helper = columnHelper<AcmeAccountItem>()
const columns = helper.columns([
  helper.accessor("id", { header: "Account", cell: ({ getValue }) => <AcmeLink kind="account" id={getValue()} /> }),
  helper.accessor("contact", {
    header: "Contact",
    cell: ({ getValue }) =>
      getValue()
        .map((contact) => contact.replace(/^mailto:/, ""))
        .join(", ") || <span className="text-muted-foreground">—</span>,
  }),
  helper.accessor("provisioner_name", { header: "Provisioner", cell: ({ getValue }) => getValue() ?? "—" }),
  helper.accessor("status", { header: "Status", cell: ({ getValue }) => <AcmeStatusPill status={getValue()} /> }),
  helper.accessor("created_at", { header: "Created", cell: ({ getValue }) => formatDateTime(getValue()) }),
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
      <PageHeader
        title="ACME accounts"
        description="The ACME clients (certbot, cert-manager, Caddy…) registered with step-ca, newest first."
        actions={<ExportLink path="/api/v1/acme/accounts" query={query} />}
      />
      <Toolbar>
        <FilterInput
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Filter by id or contact"
        />
        <StatusFilter value={search.status} statuses={STATUSES} onChange={(status) => update({ status })} />
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
          onPerPage: (per_page) => update({ per_page }),
        }}
      />
    </>
  )
}
