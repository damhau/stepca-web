import type { AcmeOrderItem } from "@/api/types"
import { columnHelper } from "@/components/data-table"
import { AcmeStatusPill } from "@/components/status"
import { formatDateTime } from "@/lib/format"
import { AcmeLink, CertificateLink, Identifiers } from "./acme"

const helper = columnHelper<AcmeOrderItem>()

export const orderColumns = helper.columns([
  helper.accessor("id", { header: "Order", cell: ({ getValue }) => <AcmeLink kind="order" id={getValue()} /> }),
  helper.accessor("identifiers", { header: "For", cell: ({ getValue }) => <Identifiers values={getValue()} /> }),
  helper.accessor("status", {
    header: "Status",
    cell: ({ row }) => (
      <div className="flex flex-col items-start gap-1">
        <AcmeStatusPill status={row.original.status} />
        {row.original.error && <span className="max-w-64 text-xs text-revoked">{row.original.error}</span>}
      </div>
    ),
  }),
  helper.accessor("created_at", { header: "Created", cell: ({ getValue }) => formatDateTime(getValue()) }),
  helper.accessor("certificate_serial", {
    header: "Certificate",
    cell: ({ getValue }) => <CertificateLink serial={getValue()} />,
  }),
])
