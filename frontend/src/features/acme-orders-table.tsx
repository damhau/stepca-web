import type { AcmeOrderItem } from "@/api/types"
import { columnHelper } from "@/components/data-table"
import { AcmeStatus } from "@/components/kit"
import { formatDateTime } from "@/lib/format"
import { AcmeLink, CertificateLink, Identifiers } from "./acme"

const helper = columnHelper<AcmeOrderItem>()

export const orderColumns = helper.columns([
  helper.accessor("identifiers", { header: "For", cell: ({ getValue }) => <Identifiers values={getValue()} /> }),
  helper.accessor("status", {
    header: "Status",
    cell: ({ row }) => (
      <div className="flex flex-col items-start gap-0.5 py-1">
        <AcmeStatus status={row.original.status} />
        {row.original.error && (
          <span className="max-w-72 text-xs whitespace-normal text-danger-fg">{row.original.error}</span>
        )}
      </div>
    ),
  }),
  helper.accessor("id", { header: "Order", cell: ({ getValue }) => <AcmeLink kind="order" id={getValue()} /> }),
  helper.accessor("created_at", {
    header: "Created",
    meta: { className: "whitespace-nowrap text-muted-foreground" },
    cell: ({ getValue }) => formatDateTime(getValue()),
  }),
  helper.accessor("certificate_serial", {
    header: "Certificate",
    meta: { className: "pr-4" },
    cell: ({ getValue }) => <CertificateLink serial={getValue()} />,
  }),
])
