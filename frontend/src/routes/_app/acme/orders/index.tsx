import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import { DataTable } from "@/components/data-table"
import { ChoiceFilter, ExportButton, SearchBox, Toolbar } from "@/components/list-tools"
import { acmeQuery, acmeSearch, AcmeHeader, type AcmeSearch } from "@/features/acme"
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
      <AcmeHeader
        description="Each request for a certificate over ACME: what it was for, how it was proven and how it ended."
        actions={<ExportButton path="/api/v1/acme/orders" query={query} />}
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
        }}
      />
    </>
  )
}
