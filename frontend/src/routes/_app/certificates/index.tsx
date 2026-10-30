import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { Plus } from "lucide-react"
import { useCallback, useState } from "react"
import { $api } from "@/api/client"
import type { CertificateItem } from "@/api/types"
import { columnHelper, DataTable, type SortOrder } from "@/components/data-table"
import { CertificateStatus, LineTabs, PageHeader } from "@/components/kit"
import { SearchBox } from "@/components/list-tools"
import { Button } from "@/components/ui/button"
import { CertificateSheet } from "@/features/certificates/certificate-sheet"
import { expiryLabel } from "@/features/certificates/expiry"
import { FilterBar } from "@/features/certificates/filters"
import { RevokeDialog, type RevokeTarget } from "@/features/certificates/revoke-dialog"
import { useIssue } from "@/features/issue/issue-context"
import { formatNumber, keyLabel, plural } from "@/lib/format"
import { int, oneOf, text } from "@/lib/search-params"
import { cn } from "@/lib/utils"

const TABS = ["all", "expiring", "revoked", "expired"] as const
const SORTS = ["not_after", "not_before", "subject", "serial", "provisioner"] as const
const PER_PAGE = 50

type Search = {
  tab?: (typeof TABS)[number]
  q?: string
  provisioner?: string[]
  key?: string[]
  sort?: (typeof SORTS)[number]
  order?: SortOrder
  page?: number
  cert?: string
}

function strings(value: unknown) {
  const list = (Array.isArray(value) ? value : typeof value === "string" ? [value] : []).filter(
    (item): item is string => typeof item === "string",
  )
  return list.length ? list.slice(0, 20) : undefined
}

export const Route = createFileRoute("/_app/certificates/")({
  validateSearch: (search: Record<string, unknown>): Search => ({
    // ?status= from links to the previous version of this page
    tab: oneOf(search.tab, TABS) ?? oneOf(search.status, TABS),
    q: text(search.q),
    provisioner: strings(search.provisioner),
    key: strings(search.key),
    sort: oneOf(search.sort, SORTS),
    order: oneOf(search.order, ["asc", "desc"] as const),
    page: int(search.page),
    cert: text(search.cert, 80),
  }),
  component: Certificates,
})

const DEFAULT_SORT: Record<(typeof TABS)[number], { sort: Search["sort"]; order: SortOrder }> = {
  all: { sort: "not_before", order: "desc" },
  expiring: { sort: "not_after", order: "asc" },
  revoked: { sort: "not_before", order: "desc" },
  expired: { sort: "not_after", order: "desc" },
}

const helper = columnHelper<CertificateItem>()

function Certificates() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const issue = useIssue()
  const tab = search.tab ?? "all"
  const sort = search.sort ?? DEFAULT_SORT[tab].sort ?? "not_before"
  const order = search.order ?? DEFAULT_SORT[tab].order
  const page = search.page ?? 1
  const query = {
    status: tab,
    days: tab === "expiring" ? 30 : undefined,
    q: search.q,
    provisioner: search.provisioner,
    key: search.key,
    sort,
    order,
    page,
    per_page: PER_PAGE,
  } as const
  const list = $api.useQuery(
    "get",
    "/api/v1/certificates",
    { params: { query } },
    { placeholderData: keepPreviousData },
  )
  const counts = $api.useQuery("get", "/api/v1/certificates/counts", {}, { staleTime: 30_000 })
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [revoking, setRevoking] = useState<RevokeTarget[]>([])
  const update = useCallback(
    (changes: Partial<Search>) =>
      navigate({ search: (previous) => ({ ...previous, page: undefined, ...changes }), replace: true }),
    [navigate],
  )
  const open = (serial?: string) => navigate({ search: (previous) => ({ ...previous, cert: serial }), replace: true })

  const columns = helper.columns([
    helper.accessor("common_name", {
      header: "Name",
      meta: { sortKey: "subject" },
      cell: ({ row }) => (
        <button
          type="button"
          onClick={() => open(row.original.serial)}
          className="min-h-9 max-w-[22rem] truncate text-left font-mono text-[13px] font-medium text-foreground hover:underline"
          title={row.original.subject}
        >
          {row.original.common_name ?? row.original.dns_names[0] ?? row.original.subject}
        </button>
      ),
    }),
    helper.accessor("status", {
      header: "Status",
      cell: ({ row }) => <CertificateStatus status={row.original.status} expiring={row.original.expiring} />,
    }),
    helper.accessor("provisioner_name", {
      header: "Provisioner",
      meta: { sortKey: "provisioner", className: "text-fg-2 whitespace-nowrap" },
      cell: ({ getValue }) => getValue() ?? "—",
    }),
    helper.accessor("not_after", {
      header: "Expires",
      meta: { sortKey: "not_after", className: "whitespace-nowrap" },
      cell: ({ row }) => (
        <span
          className={cn(
            row.original.expiring
              ? "text-warning-fg"
              : row.original.status === "valid"
                ? "text-foreground"
                : "text-muted-foreground",
          )}
          title={row.original.not_after ?? undefined}
        >
          {expiryLabel(row.original)}
        </span>
      ),
    }),
    helper.accessor("key", {
      header: "Key",
      meta: { className: "pr-3 text-muted-foreground whitespace-nowrap" },
      cell: ({ getValue }) => keyLabel(getValue()),
    }),
  ])

  const rows = list.data?.items
  const preview = rows?.find((row) => row.serial === search.cert)
  const selectedTargets = () => {
    const names = new Map((rows ?? []).map((row) => [row.serial, row.common_name ?? row.subject]))
    return [...selected].map((serial) => ({ serial, name: names.get(serial) ?? serial }))
  }
  const count = (status: keyof NonNullable<typeof counts.data>) =>
    counts.data ? formatNumber(counts.data[status]) : undefined
  const exportUrl = (() => {
    const params = new URLSearchParams({ format: "csv", status: tab, sort, order })
    if (search.q) params.set("q", search.q)
    if (tab === "expiring") params.set("days", "30")
    search.provisioner?.forEach((value) => params.append("provisioner", value))
    search.key?.forEach((value) => params.append("key", value))
    return `/api/v1/certificates?${params}`
  })()

  return (
    <>
      <PageHeader
        title="Certificates"
        description="X.509 certificates issued by this authority."
        actions={
          <>
            <Button variant="outline" asChild>
              <a href={exportUrl} download className="text-foreground no-underline hover:text-foreground">
                Export
              </a>
            </Button>
            {issue.allowed && (
              <Button onClick={issue.open}>
                <Plus strokeWidth={2.2} /> New certificate
              </Button>
            )}
          </>
        }
      />
      <LineTabs
        label="Views"
        value={tab}
        onChange={(value) => {
          setSelected(new Set())
          update({ tab: value === "all" ? undefined : value, sort: undefined, order: undefined })
        }}
        tabs={[
          { value: "all", label: "All", count: count("all") },
          { value: "expiring", label: "Expiring soon", count: count("expiring") },
          { value: "revoked", label: "Revoked", count: count("revoked") },
          { value: "expired", label: "Expired", count: count("expired") },
        ]}
      />
      <div className="-mt-1 flex flex-wrap items-center gap-2">
        <SearchBox
          id="certificate-search"
          value={search.q ?? ""}
          onChange={(q) => update({ q: q || undefined })}
          placeholder="Search by name, SAN or serial"
        />
        <FilterBar
          value={{ provisioner: search.provisioner, key: search.key }}
          onChange={(filters) => update(filters)}
        />
        {list.data && list.data.pending > 0 && (
          <span className="text-[13px] text-muted-foreground">
            Still reading {plural(list.data.pending, "certificate")} from step-ca…
          </span>
        )}
      </div>
      {selected.size > 0 && (
        <div className="-mt-1 flex flex-wrap items-center gap-3 rounded-xl bg-inverse px-3 py-2 text-inverse-foreground">
          <span className="font-medium">{selected.size} selected</span>
          <span aria-hidden className="h-[18px] w-px bg-fg-2" />
          <Button variant="inverse" size="sm" asChild>
            <a
              href={`/api/v1/certificates/bundle?${new URLSearchParams([...selected].map((serial) => ["serial", serial]))}`}
              download
              className="text-inverse-foreground no-underline hover:text-inverse-foreground"
            >
              Download
            </a>
          </Button>
          {issue.allowed && (
            <Button
              variant="inverse"
              size="sm"
              className="text-red-300 dark:text-danger-fg"
              onClick={() => setRevoking(selectedTargets())}
            >
              Revoke
            </Button>
          )}
          <button
            type="button"
            onClick={() => setSelected(new Set())}
            className="ml-auto min-h-8 px-2.5 text-[13px] text-neutral-dot hover:text-inverse-foreground"
          >
            Clear
          </button>
        </div>
      )}
      <DataTable
        label="Certificate list"
        columns={columns}
        rows={rows}
        rowId={(row) => row.serial}
        isPending={list.isPending}
        error={list.error}
        onRetry={() => list.refetch()}
        empty={
          search.q || search.provisioner || search.key
            ? "No certificate matches these filters."
            : "No certificates here."
        }
        activeId={search.cert}
        sorting={{
          sort,
          order,
          onSort: (next, nextOrder) => update({ sort: next as Search["sort"], order: nextOrder }),
        }}
        paging={{
          total: list.data?.total ?? 0,
          page,
          perPage: PER_PAGE,
          onPage: (next) => navigate({ search: (previous) => ({ ...previous, page: next }) }),
        }}
        selection={{
          selected,
          label: (row) => `Select ${row.common_name ?? row.subject}`,
          onToggle: (id) =>
            setSelected((current) => {
              const next = new Set(current)
              if (next.has(id)) next.delete(id)
              else next.add(id)
              return next
            }),
          onToggleAll: (ids, on) =>
            setSelected((current) => {
              const next = new Set(current)
              ids.forEach((id) => (on ? next.add(id) : next.delete(id)))
              return next
            }),
        }}
      />
      {search.cert && (
        <CertificateSheet
          serial={search.cert}
          preview={preview}
          onClose={() => open(undefined)}
          onRevoke={(target) => setRevoking([target])}
        />
      )}
      <RevokeDialog targets={revoking} onClose={() => setRevoking([])} onDone={() => setSelected(new Set())} />
    </>
  )
}

/** The text filter: updates the URL a moment after typing stops. */
