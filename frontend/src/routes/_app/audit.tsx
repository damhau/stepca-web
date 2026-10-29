import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { $api } from "@/api/client"
import type { AuditItem } from "@/api/types"
import { AdminOnly } from "@/components/admin-only"
import { columnHelper, DataTable } from "@/components/data-table"
import { ExportLink, FilterInput, Toolbar } from "@/components/list-toolbar"
import { PageHeader } from "@/components/page"
import { Pill } from "@/components/status"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { formatDateTime } from "@/lib/format"
import { listSearch, oneOf, text, type ListSearch } from "@/lib/search-params"

type Search = ListSearch & { action?: string; result?: "ok" | "failed" }

export const Route = createFileRoute("/_app/audit")({
  validateSearch: (search: Record<string, unknown>): Search => ({
    ...listSearch(search),
    action: text(search.action, 100),
    result: oneOf(search.result, ["ok", "failed"] as const),
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
    cell: ({ getValue }) => <span className="whitespace-nowrap">{formatDateTime(getValue())}</span>,
  }),
  helper.accessor("user", {
    header: "Who",
    cell: ({ row }) => (
      <div className="flex flex-col">
        <span className="font-medium">{row.original.user}</span>
        <span className="text-xs text-muted-foreground capitalize">{row.original.role ?? "—"}</span>
      </div>
    ),
  }),
  helper.accessor("action", { header: "Action", cell: ({ getValue }) => getValue().replaceAll("_", " ") }),
  helper.accessor("target", {
    header: "On",
    meta: { className: "max-w-56" },
    cell: ({ getValue }) => <code className="font-mono text-[0.8125rem] break-all">{getValue()}</code>,
  }),
  helper.accessor("success", {
    header: "Result",
    cell: ({ getValue }) => (getValue() ? <Pill tone="valid">ok</Pill> : <Pill tone="revoked">failed</Pill>),
  }),
  helper.accessor("detail", {
    header: "Detail",
    meta: { className: "max-w-96 whitespace-normal text-sm text-muted-foreground" },
  }),
])

function Audit() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const query = {
    page: search.page ?? 1,
    per_page: search.per_page ?? 50,
    q: search.q,
    action: search.action,
    success: search.result === undefined ? undefined : search.result === "ok",
  }
  const list = $api.useQuery("get", "/api/v1/audit", { params: { query } }, { placeholderData: keepPreviousData })
  const update = (changes: Partial<Search>) =>
    navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true })
  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every sign-in and change made through this app, newest first."
        actions={<ExportLink path="/api/v1/audit" query={query} />}
      />
      <Toolbar>
        <FilterInput
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Filter by user, target or detail"
        />
        <Select
          value={search.action ?? "*"}
          onValueChange={(value) => update({ action: value === "*" ? undefined : value })}
        >
          <SelectTrigger className="w-auto min-w-40" aria-label="Action">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="*">Every action</SelectItem>
            {list.data?.actions.map((action) => (
              <SelectItem key={action} value={action}>
                {action.replaceAll("_", " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={search.result ?? "*"}
          onValueChange={(value) => update({ result: value === "*" ? undefined : (value as Search["result"]) })}
        >
          <SelectTrigger className="w-auto" aria-label="Result">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="*">Any result</SelectItem>
            <SelectItem value="ok">Succeeded</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
          </SelectContent>
        </Select>
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
          onPerPage: (per_page) => update({ per_page }),
        }}
      />
    </>
  )
}
