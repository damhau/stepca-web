import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AcmeCertificateItem } from "@/api/types"
import { columnHelper, DataTable } from "@/components/data-table"
import { ExportButton, SearchBox, Toolbar } from "@/components/list-tools"
import {
  AcmeLink,
  acmeQuery,
  acmeSearch,
  AcmeHeader,
  CertificateLink,
  type AcmeSearch,
  StillReading,
} from "@/features/acme"
import { fromNow } from "@/lib/format"

export const Route = createFileRoute("/_app/acme/certificates")({
  validateSearch: acmeSearch([]),
  component: AcmeCertificates,
})

const helper = columnHelper<AcmeCertificateItem>()
const columns = helper.columns([
  helper.accessor("subject", {
    header: "Name",
    cell: ({ row }) => (
      <CertificateLink serial={row.original.serial} name={row.original.dns_names[0] ?? row.original.subject} />
    ),
  }),
  helper.accessor("dns_names", {
    header: "Other names",
    meta: { className: "max-w-72 truncate font-mono text-xs text-muted-foreground" },
    cell: ({ getValue }) => getValue().slice(1).join(", ") || "—",
  }),
  helper.accessor("not_after", {
    header: "Expires",
    meta: { className: "whitespace-nowrap" },
    cell: ({ getValue }) => fromNow(getValue()),
  }),
  helper.accessor("order_id", { header: "Order", cell: ({ getValue }) => <AcmeLink kind="order" id={getValue()} /> }),
  helper.accessor("account_id", {
    header: "Account",
    meta: { className: "pr-4" },
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
      <AcmeHeader
        description="Certificates issued to ACME orders, newest first."
        actions={<ExportButton path="/api/v1/acme/certificates" query={query} />}
      />
      <Toolbar>
        <SearchBox
          id="acme-search"
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Search by name, serial or id"
        />
        <StillReading pending={list.data?.pending} noun="certificate" />
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
        }}
      />
    </>
  )
}
