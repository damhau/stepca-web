import {
  createColumnHelper,
  FlexRender,
  tableFeatures,
  useTable,
  type CellData,
  type ColumnDef,
  type RowData,
  type TableFeatures,
} from "@tanstack/react-table"
import { ArrowDown, ArrowUp } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Skeleton } from "@/components/ui/skeleton"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"
import { ErrorState } from "./kit"

declare module "@tanstack/react-table" {
  // The type parameters must repeat the library's for the declarations to merge
  /* eslint-disable @typescript-eslint/no-unused-vars */
  interface ColumnMeta<
    in out TFeatures extends TableFeatures,
    in out TData extends RowData,
    TValue extends CellData = CellData,
  > {
    /* eslint-enable @typescript-eslint/no-unused-vars */
    /** The server's sort key for this column: its header then sorts the list */
    sortKey?: string
    className?: string
  }
}

// The server filters, sorts and pages: the table only lays out the page it returns
const features = tableFeatures({})
type Features = typeof features

export function columnHelper<T extends RowData>() {
  return createColumnHelper<Features, T>()
}

export type Columns<T extends RowData> = Array<ColumnDef<Features, T, any>> // eslint-disable-line @typescript-eslint/no-explicit-any

export type SortOrder = "asc" | "desc"

type Paging = { total: number; page: number; perPage: number; onPage: (page: number) => void }
type Sorting = { sort: string; order: SortOrder; onSort: (sort: string, order: SortOrder) => void }
type Selection = {
  selected: ReadonlySet<string>
  onToggle: (id: string) => void
  onToggleAll: (ids: string[], on: boolean) => void
  label: (row: never) => string
}

type Props<T extends RowData> = {
  columns: Columns<T>
  rows: T[] | undefined
  rowId: (row: T) => string
  isPending: boolean
  error?: unknown
  onRetry?: () => void
  empty: React.ReactNode
  label: string
  paging?: Paging
  sorting?: Sorting
  selection?: Omit<Selection, "label"> & { label: (row: T) => string }
  /** The row shown in the detail sheet */
  activeId?: string | null
  className?: string
}

const NO_ROWS: never[] = []

export function DataTable<T extends RowData>({
  columns,
  rows,
  rowId,
  isPending,
  error,
  onRetry,
  empty,
  label,
  paging,
  sorting,
  selection,
  activeId,
  className,
}: Props<T>) {
  const table = useTable({ features, columns, data: rows ?? NO_ROWS, getRowId: rowId })
  if (error && !rows) return <ErrorState error={error} onRetry={onRetry} />
  const ids = (rows ?? []).map(rowId)
  const allSelected = !!selection && ids.length > 0 && ids.every((id) => selection.selected.has(id))
  const someSelected = !!selection && ids.some((id) => selection.selected.has(id))
  const span = columns.length + (selection ? 1 : 0)
  return (
    <section aria-label={label} className={cn("min-w-0 overflow-hidden rounded-xl border bg-card", className)}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse" aria-busy={isPending}>
          <thead>
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id} className="bg-sidebar text-left text-xs text-muted-foreground">
                {selection && (
                  <th scope="col" className="w-5 px-3 py-2.5 font-medium">
                    <Checkbox
                      aria-label="Select every row of this page"
                      checked={allSelected ? true : someSelected ? "indeterminate" : false}
                      onCheckedChange={(checked) => selection.onToggleAll(ids, checked === true)}
                    />
                  </th>
                )}
                {group.headers.map((header, index) => {
                  const meta = header.column.columnDef.meta
                  const sortKey = meta?.sortKey
                  const active = sorting && sortKey === sorting.sort
                  return (
                    <th
                      key={header.id}
                      scope="col"
                      className={cn(
                        "px-2 py-2.5 whitespace-nowrap",
                        !selection && index === 0 && "pl-4",
                        meta?.className,
                        // A column's padding and width apply to its header, not its cells' type and colour
                        "font-sans text-xs font-medium text-muted-foreground",
                      )}
                      aria-sort={active ? (sorting.order === "asc" ? "ascending" : "descending") : undefined}
                    >
                      {header.isPlaceholder ? null : sorting && sortKey ? (
                        <button
                          type="button"
                          className="inline-flex items-center gap-1 hover:text-foreground"
                          onClick={() => sorting.onSort(sortKey, active && sorting.order === "asc" ? "desc" : "asc")}
                        >
                          <FlexRender header={header} />
                          {active &&
                            (sorting.order === "asc" ? (
                              <ArrowUp className="size-3" />
                            ) : (
                              <ArrowDown className="size-3" />
                            ))}
                        </button>
                      ) : (
                        <FlexRender header={header} />
                      )}
                    </th>
                  )
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {isPending && !rows ? (
              Array.from({ length: 6 }, (_, index) => (
                <tr key={index} className="border-t border-border-subtle">
                  {Array.from({ length: span }, (_, cell) => (
                    <td key={cell} className="px-2 py-3 first:pl-4">
                      <Skeleton className="h-4 w-full max-w-36" />
                    </td>
                  ))}
                </tr>
              ))
            ) : table.getRowModel().rows.length === 0 ? (
              <tr className="border-t border-border-subtle">
                <td colSpan={span} className="px-4 py-12 text-center text-muted-foreground">
                  {empty}
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => {
                const id = row.id
                const checked = selection?.selected.has(id) ?? false
                return (
                  <tr
                    key={id}
                    className={cn(
                      "border-t border-border-subtle",
                      activeId === id ? "bg-brand-soft" : checked ? "bg-sidebar" : "hover:bg-sidebar/60",
                    )}
                  >
                    {selection && (
                      <td className="px-3">
                        <Checkbox
                          aria-label={selection.label(row.original)}
                          checked={checked}
                          onCheckedChange={() => selection.onToggle(id)}
                        />
                      </td>
                    )}
                    {row.getAllCells().map((cell, index) => (
                      <td
                        key={cell.id}
                        className={cn(
                          "px-2 py-1.5 align-middle",
                          !selection && index === 0 && "pl-4",
                          cell.column.columnDef.meta?.className,
                        )}
                      >
                        <FlexRender cell={cell} />
                      </td>
                    ))}
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
      {paging && paging.total > 0 && <Pagination {...paging} />}
    </section>
  )
}

function Pagination({ total, page, perPage, onPage }: Paging) {
  const pages = Math.max(Math.ceil(total / perPage), 1)
  const first = (page - 1) * perPage + 1
  const last = Math.min(page * perPage, total)
  return (
    <nav
      aria-label="Pages"
      className="flex items-center justify-between gap-3 border-t border-border-subtle px-3 py-2.5 text-[13px] text-muted-foreground"
    >
      <span>
        {formatNumber(first)}–{formatNumber(last)} of {formatNumber(total)}
      </span>
      <div className="flex gap-1.5">
        <Button
          variant="outline"
          className="h-[30px] rounded-md px-2.5 text-[13px] font-normal"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
        >
          Previous
        </Button>
        <Button
          variant="outline"
          className="h-[30px] rounded-md px-2.5 text-[13px] font-normal"
          disabled={page >= pages}
          onClick={() => onPage(page + 1)}
        >
          Next
        </Button>
      </div>
    </nav>
  )
}
