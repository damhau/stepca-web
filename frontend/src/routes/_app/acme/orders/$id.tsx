import { createFileRoute, Link } from "@tanstack/react-router"
import { $api } from "@/api/client"
import { Identifier } from "@/components/copy-button"
import { AcmeStatus, ErrorState, Loading } from "@/components/kit"
import { Fields, Section } from "@/components/page"
import { AcmeLink, CertificateLink, Identifiers } from "@/features/acme"
import { formatDateTime } from "@/lib/format"

export const Route = createFileRoute("/_app/acme/orders/$id")({ component: Order })

function Order() {
  const { id } = Route.useParams()
  const { data, error, refetch } = $api.useQuery("get", "/api/v1/acme/orders/{id}", { params: { path: { id } } })
  return (
    <>
      <p className="-mb-1 text-[13px] text-muted-foreground">
        <Link to="/acme/orders" className="text-muted-foreground hover:text-foreground">
          ACME orders
        </Link>{" "}
        / {id.slice(0, 12)}…
      </p>
      {error ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : !data ? (
        <Loading lines={8} />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-[-0.02em]">
              <Identifiers values={data.order.identifiers} />
            </h1>
            <AcmeStatus status={data.order.status} />
          </div>
          {data.order.error && <p className="-mt-3 text-danger-fg">{data.order.error}</p>}
          <Section title="Order">
            <Fields
              rows={[
                ["Id", <Identifier key="id" value={data.order.id} label="order id" />],
                [
                  "Account",
                  <span key="a" className="flex flex-wrap items-center gap-2">
                    <AcmeLink kind="account" id={data.order.account_id} />
                    {data.account && (
                      <span className="text-muted-foreground">
                        {data.account.contact.map((c) => c.replace(/^mailto:/, "")).join(", ")}
                      </span>
                    )}
                  </span>,
                ],
                [
                  "Validity asked for",
                  `${formatDateTime(data.order.not_before)} to ${formatDateTime(data.order.not_after)}`,
                ],
                ["Created", formatDateTime(data.order.created_at)],
                ["Expires", formatDateTime(data.order.expires_at)],
                [
                  "Certificate",
                  <CertificateLink
                    key="c"
                    serial={data.order.certificate_serial}
                    name={data.certificate?.subject?.replace(/^CN=/, "")}
                  />,
                ],
              ]}
            />
          </Section>
          {data.authorizations.map(({ authorization, challenges }) => (
            <Section
              key={authorization.id}
              title={
                <span className="flex flex-wrap items-center gap-2.5">
                  Authorization for{" "}
                  <span className="font-mono">
                    {authorization.wildcard ? `*.${authorization.identifier.value}` : authorization.identifier.value}
                  </span>
                  <AcmeStatus status={authorization.status} />
                </span>
              }
              actions={
                <span className="text-xs text-muted-foreground">
                  expires {formatDateTime(authorization.expires_at)}
                </span>
              }
            >
              <div className="overflow-x-auto">
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="bg-sidebar text-left text-xs text-muted-foreground">
                      <th scope="col" className="py-2.5 pr-2 pl-4 font-medium">
                        Challenge
                      </th>
                      <th scope="col" className="px-2 py-2.5 font-medium">
                        Status
                      </th>
                      <th scope="col" className="px-2 py-2.5 font-medium">
                        Validated
                      </th>
                      <th scope="col" className="py-2.5 pr-4 pl-2 font-medium">
                        Error
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {challenges.map((challenge) => (
                      <tr key={challenge.id} className="border-t border-border-subtle">
                        <td className="py-2.5 pr-2 pl-4 font-mono text-[13px] font-medium">{challenge.type}</td>
                        <td className="px-2 py-2.5">
                          <AcmeStatus status={challenge.status} />
                        </td>
                        <td className="px-2 py-2.5 text-muted-foreground">{formatDateTime(challenge.validated_at)}</td>
                        <td className="py-2.5 pr-4 pl-2 text-[13px] text-danger-fg">{challenge.error}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          ))}
        </>
      )}
    </>
  )
}
