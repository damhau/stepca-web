import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import { DataTable } from "@/components/data-table"
import { ExportLink, FilterInput, Toolbar } from "@/components/list-toolbar"
import { PageHeader } from "@/components/page"
import { acmeQuery, acmeSearch, StatusFilter, type AcmeSearch } from "@/features/acme"
import { orderColumns } from "@/features/acme-orders-table"

const STATUSES = ["pending", "ready", "processing", "valid", "invalid"] as const

export const Route = createFileRoute("/_app/acme/orders/")({ validateSearch: acmeSearch(STATUSES), component: Orders })

function Orders() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const query = acmeQuery(search)
  const list = $api.useQuery("get", "/api/v1/acme/orders", { params: { query } }, { placeholderData: keepPreviousData })
  const update = (changes: Partial<AcmeSearch>) =>
    navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true })
  return (
    <>
      <PageHeader
        title="ACME orders"
        description="Each request for a certificate over ACME, with what it was for and how it ended."
        actions={<ExportLink path="/api/v1/acme/orders" query={query} />}
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
        label="ACME orders"
        columns={orderColumns}
        rows={list.data?.items}
        rowId={(row) => row.id}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty="No ACME order here."
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
