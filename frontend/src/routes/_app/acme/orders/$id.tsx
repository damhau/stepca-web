import { createFileRoute, Link } from "@tanstack/react-router"
import { ChevronLeft } from "lucide-react"
import { $api } from "@/api/client"
import { Identifier } from "@/components/copy-button"
import { ErrorState, Fields, LoadingBlock, PageHeader, Section } from "@/components/page"
import { AcmeStatusPill } from "@/components/status"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { AcmeLink, CertificateLink, Identifiers } from "@/features/acme"
import { formatDateTime } from "@/lib/format"

export const Route = createFileRoute("/_app/acme/orders/$id")({ component: Order })

function Order() {
  const { id } = Route.useParams()
  const { data, error, refetch } = $api.useQuery("get", "/api/v1/acme/orders/{id}", { params: { path: { id } } })
  return (
    <>
      <Link
        to="/acme/orders"
        className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ChevronLeft className="size-4" aria-hidden /> ACME orders
      </Link>
      {error ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : !data ? (
        <LoadingBlock lines={8} />
      ) : (
        <>
          <PageHeader
            title={
              <span className="flex flex-wrap items-center gap-3">
                <Identifiers values={data.order.identifiers} />
                <AcmeStatusPill status={data.order.status} />
              </span>
            }
            description={
              data.order.error ? (
                <span className="text-revoked">{data.order.error}</span>
              ) : (
                "An ACME order: the names asked for, how each was proven, and the certificate."
              )
            }
          />
          <div className="flex flex-col gap-6">
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
                  ["Certificate", <CertificateLink key="c" serial={data.order.certificate_serial} />],
                ]}
              />
            </Section>
            {data.authorizations.map(({ authorization, challenges }) => (
              <Section
                key={authorization.id}
                title={
                  <span className="flex flex-wrap items-center gap-2">
                    Authorization for{" "}
                    {authorization.wildcard ? `*.${authorization.identifier.value}` : authorization.identifier.value}
                    <AcmeStatusPill status={authorization.status} />
                  </span>
                }
                actions={
                  <span className="text-xs text-muted-foreground">
                    expires {formatDateTime(authorization.expires_at)}
                  </span>
                }
              >
                <div className="overflow-x-auto">
                  <Table aria-label={`Challenges for ${authorization.identifier.value}`}>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="text-xs text-muted-foreground">Challenge</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Status</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Validated</TableHead>
                        <TableHead className="text-xs text-muted-foreground">Error</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {challenges.map((challenge) => (
                        <TableRow key={challenge.id}>
                          <TableCell className="font-medium">{challenge.type}</TableCell>
                          <TableCell>
                            <AcmeStatusPill status={challenge.status} />
                          </TableCell>
                          <TableCell>{formatDateTime(challenge.validated_at)}</TableCell>
                          <TableCell className="max-w-96 text-sm whitespace-normal text-revoked">
                            {challenge.error}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </Section>
            ))}
            {data.certificate && (
              <Section title="Certificate">
                <Fields
                  rows={[
                    ["Subject", data.certificate.subject ?? "—"],
                    ["Names", data.certificate.dns_names.join(", ") || "—"],
                    [
                      "Valid",
                      `${formatDateTime(data.certificate.not_before)} to ${formatDateTime(data.certificate.not_after)}`,
                    ],
                    ["Serial", <CertificateLink key="s" serial={data.certificate.serial} />],
                  ]}
                />
              </Section>
            )}
          </div>
        </>
      )}
    </>
  )
}
