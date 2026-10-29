import { createFileRoute, Link } from "@tanstack/react-router"
import { ChevronLeft } from "lucide-react"
import { $api } from "@/api/client"
import { Identifier } from "@/components/copy-button"
import { DataTable } from "@/components/data-table"
import { ErrorState, Fields, LoadingBlock, PageHeader, Section } from "@/components/page"
import { AcmeStatusPill } from "@/components/status"
import { orderColumns } from "@/features/acme-orders-table"
import { formatDateTime, plural } from "@/lib/format"

export const Route = createFileRoute("/_app/acme/accounts/$id")({ component: Account })

function Account() {
  const { id } = Route.useParams()
  const { data, error, refetch, isPending } = $api.useQuery("get", "/api/v1/acme/accounts/{id}", {
    params: { path: { id } },
  })
  return (
    <>
      <Link
        to="/acme/accounts"
        className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ChevronLeft className="size-4" aria-hidden /> ACME accounts
      </Link>
      {error ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : !data ? (
        <LoadingBlock />
      ) : (
        <>
          <PageHeader
            title={data.account.contact.map((contact) => contact.replace(/^mailto:/, "")).join(", ") || "ACME account"}
            description={`${plural(data.orders.length, "order")}, through provisioner ${data.account.provisioner_name ?? "unknown"}.`}
          />
          <div className="flex flex-col gap-6">
            <Section title="Account">
              <Fields
                rows={[
                  ["Id", <Identifier key="id" value={data.account.id} label="account id" />],
                  ["Status", <AcmeStatusPill key="s" status={data.account.status} />],
                  ["Created", formatDateTime(data.account.created_at)],
                  ...(data.account.deactivated_at
                    ? ([["Deactivated", formatDateTime(data.account.deactivated_at)]] as [string, string][])
                    : []),
                ]}
              />
            </Section>
            <div>
              <h2 className="mb-3 text-sm font-semibold">Orders</h2>
              <DataTable
                label="Orders of this account"
                columns={orderColumns}
                rows={data.orders}
                rowId={(row) => row.id}
                isPending={isPending}
                empty="This account has placed no order."
              />
            </div>
          </div>
        </>
      )}
    </>
  )
}
