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
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"
import { ErrorState } from "./page"

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

export const PAGE_SIZES = [25, 50, 100, 200]

type Paging = {
  total: number
  page: number
  perPage: number
  onPage: (page: number) => void
  onPerPage: (perPage: number) => void
}

type Sorting = { sort: string; order: SortOrder; onSort: (sort: string, order: SortOrder) => void }

type Props<T extends RowData> = {
  columns: Columns<T>
  rows: T[] | undefined
  rowId: (row: T) => string
  isPending: boolean
  error?: unknown
  onRetry?: () => void
  empty: React.ReactNode
  paging?: Paging
  sorting?: Sorting
  label: string
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
  paging,
  sorting,
  label,
}: Props<T>) {
  const table = useTable({ features, columns, data: rows ?? NO_ROWS, getRowId: rowId })
  if (error && !rows) return <ErrorState error={error} onRetry={onRetry} />
  return (
    <div className="flex flex-col gap-3">
      <div className="overflow-x-auto rounded-lg border bg-card">
        <Table aria-label={label} aria-busy={isPending}>
          <TableHeader>
            {table.getHeaderGroups().map((group) => (
              <TableRow key={group.id} className="hover:bg-transparent">
                {group.headers.map((header) => {
                  const meta = header.column.columnDef.meta
                  const sortKey = meta?.sortKey
                  const active = sorting && sortKey === sorting.sort
                  return (
                    <TableHead
                      key={header.id}
                      className={cn("h-10 text-xs font-medium text-muted-foreground", meta?.className)}
                      aria-sort={active ? (sorting.order === "asc" ? "ascending" : "descending") : undefined}
                    >
                      {header.isPlaceholder ? null : sorting && sortKey ? (
                        <button
                          type="button"
                          className="-ml-1 inline-flex items-center gap-1 rounded px-1 py-0.5 hover:text-foreground"
                          onClick={() => sorting.onSort(sortKey, active && sorting.order === "desc" ? "asc" : "desc")}
                        >
                          <FlexRender header={header} />
                          {active ? (
                            sorting.order === "asc" ? (
                              <ArrowUp className="size-3.5" />
                            ) : (
                              <ArrowDown className="size-3.5" />
                            )
                          ) : (
                            <ArrowUpDown className="size-3.5 opacity-40" />
                          )}
                        </button>
                      ) : (
                        <FlexRender header={header} />
                      )}
                    </TableHead>
                  )
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isPending && !rows ? (
              Array.from({ length: 6 }, (_, index) => (
                <TableRow key={index} className="hover:bg-transparent">
                  {columns.map((_column, cell) => (
                    <TableCell key={cell}>
                      <Skeleton className="h-4 w-full max-w-40" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={columns.length} className="py-10 text-center text-sm text-muted-foreground">
                  {empty}
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getAllCells().map((cell) => (
                    <TableCell key={cell.id} className={cn("align-middle", cell.column.columnDef.meta?.className)}>
                      <FlexRender cell={cell} />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      {paging && paging.total > 0 && <Pagination {...paging} />}
    </div>
  )
}

function Pagination({ total, page, perPage, onPage, onPerPage }: Paging) {
  const pages = Math.max(Math.ceil(total / perPage), 1)
  const first = (page - 1) * perPage + 1
  const last = Math.min(page * perPage, total)
  return (
    <nav className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground" aria-label="Pages">
      <p>
        {formatNumber(first)}–{formatNumber(last)} of {formatNumber(total)}
      </p>
      <div className="flex items-center gap-2">
        <Select value={String(perPage)} onValueChange={(value) => onPerPage(Number(value))}>
          <SelectTrigger size="sm" className="w-auto" aria-label="Rows per page">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PAGE_SIZES.map((size) => (
              <SelectItem key={size} value={String(size)}>
                {size} per page
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="icon-sm"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          aria-label="Previous page"
        >
          <ChevronLeft />
        </Button>
        <span className="tabular-nums">
          {formatNumber(page)} / {formatNumber(pages)}
        </span>
        <Button
          variant="outline"
          size="icon-sm"
          disabled={page >= pages}
          onClick={() => onPage(page + 1)}
          aria-label="Next page"
        >
          <ChevronRight />
        </Button>
      </div>
    </nav>
  )
}
