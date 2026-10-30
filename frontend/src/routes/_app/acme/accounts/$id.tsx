import { createFileRoute, Link } from "@tanstack/react-router"
import { $api } from "@/api/client"
import { Identifier } from "@/components/copy-button"
import { DataTable } from "@/components/data-table"
import { AcmeStatus, ErrorState, Loading, PageHeader } from "@/components/kit"
import { Fields, Section } from "@/components/page"
import { orderColumns } from "@/features/acme-orders-table"
import { formatDateTime, formatNumber, plural } from "@/lib/format"

export const Route = createFileRoute("/_app/acme/accounts/$id")({ component: Account })

function Account() {
  const { id } = Route.useParams()
  const { data, error, refetch, isPending } = $api.useQuery("get", "/api/v1/acme/accounts/{id}", {
    params: { path: { id } },
  })
  return (
    <>
      <p className="-mb-1 text-[13px] text-muted-foreground">
        <Link to="/acme/accounts" className="text-muted-foreground hover:text-foreground">
          ACME accounts
        </Link>{" "}
        / {id.slice(0, 12)}…
      </p>
      {error ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : !data ? (
        <Loading />
      ) : (
        <>
          <PageHeader
            title={data.account.contact.map((contact) => contact.replace(/^mailto:/, "")).join(", ") || "ACME account"}
            description={`${plural(data.order_total, "order")}, through provisioner ${data.account.provisioner_name ?? "unknown"}.`}
          />
          <Section title="Account">
            <Fields
              rows={[
                ["Id", <Identifier key="id" value={data.account.id} label="account id" />],
                ["Status", <AcmeStatus key="s" status={data.account.status} />],
                ["Created", formatDateTime(data.account.created_at)],
                ...(data.account.deactivated_at
                  ? ([["Deactivated", formatDateTime(data.account.deactivated_at)]] as [string, string][])
                  : []),
              ]}
            />
          </Section>
          <DataTable
            label="Orders of this account"
            columns={orderColumns}
            rows={data.orders}
            rowId={(row) => row.id}
            isPending={isPending}
            empty="This account has placed no order."
          />
          {data.order_total > data.orders.length && (
            <p className="-mt-2 text-[13px] text-muted-foreground">
              The latest {data.orders.length}.{" "}
              <Link to="/acme/orders" search={{ q: data.account.id }}>
                See all {formatNumber(data.order_total)} in Orders
              </Link>
            </p>
          )}
        </>
      )}
    </>
  )
}
