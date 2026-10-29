import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AcmeCertificateItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { ExportLink, FilterInput, Toolbar } from "@/components/list-toolbar"
import { PageHeader } from "@/components/page"
import { AcmeLink, acmeQuery, acmeSearch, CertificateLink, type AcmeSearch } from "@/features/acme"
import { formatDateTime } from "@/lib/format"

export const Route = createFileRoute("/_app/acme/certificates")({
  validateSearch: acmeSearch([]),
  component: AcmeCertificates,
})

const helper = columnHelper<AcmeCertificateItem>()
const columns = helper.columns([
  helper.accessor("subject", {
    header: "Certificate",
    cell: ({ row }) => (
      <div className="flex flex-col gap-0.5">
        <span className="font-medium">{row.original.dns_names[0] ?? row.original.subject ?? "—"}</span>
        <span className="max-w-80 truncate text-xs text-muted-foreground">
          {row.original.dns_names.slice(1).join(", ")}
        </span>
      </div>
    ),
  }),
  helper.accessor("not_after", { header: "Valid to", cell: ({ getValue }) => formatDateTime(getValue()) }),
  helper.accessor("serial", { header: "Serial", cell: ({ getValue }) => <CertificateLink serial={getValue()} /> }),
  helper.accessor("order_id", { header: "Order", cell: ({ getValue }) => <AcmeLink kind="order" id={getValue()} /> }),
  helper.accessor("account_id", {
    header: "Account",
    cell: ({ getValue }) => <AcmeLink kind="account" id={getValue()} />,
  }),
])

function AcmeCertificates() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const query = acmeQuery(search)
  const list = $api.useQuery(
    "get",
    "/api/v1/acme/certificates",
    { params: { query } },
    { placeholderData: keepPreviousData },
  )
  const update = (changes: Partial<AcmeSearch>) =>
    navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true })
  return (
    <>
      <PageHeader
        title="ACME certificates"
        description="Certificates issued to ACME orders, newest first."
        actions={<ExportLink path="/api/v1/acme/certificates" query={query} />}
      />
      <Toolbar>
        <FilterInput
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Filter by name, serial or id"
        />
      </Toolbar>
      <DataTable
        label="ACME certificates"
        columns={columns}
        rows={list.data?.items}
        rowId={(row) => row.id}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty="No certificate issued over ACME yet."
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
