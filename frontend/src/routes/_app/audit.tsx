import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AuditItem } from "@/api/types"
import { AdminOnly } from "@/components/admin-only"
import { columnHelper, DataTable } from "@/components/data-table"
import { PageHeader, StatusDot } from "@/components/kit"
import { ChoiceFilter, ExportButton, SearchBox, Toolbar } from "@/components/list-tools"
import { formatDateTime } from "@/lib/format"
import { listSearch, oneOf, text, type ListSearch } from "@/lib/search-params"

type Search = ListSearch & { action?: string; result?: "succeeded" | "failed" }

export const Route = createFileRoute("/_app/audit")({
  validateSearch: (search: Record<string, unknown>): Search => ({
    ...listSearch(search),
    action: text(search.action, 100),
    result: oneOf(search.result, ["succeeded", "failed"] as const),
  }),
  component: () => (
    <AdminOnly>
      <Audit />
    </AdminOnly>
  ),
})

const helper = columnHelper<AuditItem>()
const columns = helper.columns([
  helper.accessor("created_at", {
    header: "When",
    meta: { className: "whitespace-nowrap text-muted-foreground" },
    cell: ({ getValue }) => formatDateTime(getValue()),
  }),
  helper.accessor("user", {
    header: "Who",
    cell: ({ row }) => (
      <span>
        <span className="font-medium">{row.original.user}</span>{" "}
        <span className="text-xs text-muted-foreground capitalize">{row.original.role ?? ""}</span>
      </span>
    ),
  }),
  helper.accessor("action", { header: "Action", cell: ({ getValue }) => getValue().replaceAll("_", " ") }),
  helper.accessor("target", {
    header: "On",
    meta: { className: "max-w-56" },
    cell: ({ getValue }) => <span className="font-mono text-[13px] break-all">{getValue()}</span>,
  }),
  helper.accessor("success", {
    header: "Result",
    cell: ({ getValue }) =>
      getValue() ? <StatusDot tone="success">ok</StatusDot> : <StatusDot tone="danger">failed</StatusDot>,
  }),
  helper.accessor("detail", {
    header: "Detail",
    meta: { className: "max-w-96 pr-4 text-[13px] whitespace-normal text-muted-foreground" },
  }),
])

function Audit() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const query = {
    page: search.page ?? 1,
    per_page: 50,
    q: search.q,
    action: search.action,
    success: search.result === undefined ? undefined : search.result === "succeeded",
  }
  const list = $api.useQuery("get", "/api/v1/audit", { params: { query } }, { placeholderData: keepPreviousData })
  const update = (changes: Partial<Search>) =>
    navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true })
  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every sign-in and change made through this app, newest first."
        actions={<ExportButton path="/api/v1/audit" query={query} />}
      />
      <Toolbar>
        <SearchBox
          id="audit-search"
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Search by user, target or detail"
        />
        <ChoiceFilter
          label="Action"
          any="Every action"
          value={search.action}
          options={list.data?.actions ?? (search.action ? [search.action] : [])}
          onChange={(action) => update({ action })}
        />
        <ChoiceFilter
          label="Result"
          any="Any result"
          value={search.result}
          options={["succeeded", "failed"]}
          onChange={(result) => update({ result: result as Search["result"] })}
        />
      </Toolbar>
      <DataTable
        label="Audit log"
        columns={columns}
        rows={list.data?.items}
        rowId={(row) => String(row.id)}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty="Nothing recorded here."
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
