import { createFileRoute, Link } from "@tanstack/react-router"
import { $api } from "@/api/client"
import { ErrorState, LoadingBlock, PageHeader, Section } from "@/components/page"
import { AcmeStatusPill, CertificateStatusPill } from "@/components/status"
import { Identifiers } from "@/features/acme"
import { formatDate, plural } from "@/lib/format"
import { text } from "@/lib/search-params"

export const Route = createFileRoute("/_app/search")({
  validateSearch: (search: Record<string, unknown>): { q?: string } => ({ q: text(search.q) }),
  component: SearchPage,
})

function More({ shown }: { shown: boolean }) {
  return shown ? (
    <p className="border-t px-4 py-2 text-xs text-muted-foreground">Only the first 50 are shown: refine the search.</p>
  ) : null
}

function Row({ children }: { children: React.ReactNode }) {
  return <li className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1 px-4 py-2.5 text-sm">{children}</li>
}

function SearchPage() {
  const { q = "" } = Route.useSearch()
  const { data, error, refetch, isPending } = $api.useQuery(
    "get",
    "/api/v1/search",
    { params: { query: { q } } },
    { enabled: q.length >= 2 },
  )
  const header = (
    <PageHeader
      title={q ? `Results for “${q}”` : "Search"}
      description="Certificates, ACME accounts and orders, provisioners and admins."
    />
  )
  if (q.length < 2)
    return (
      <>
        {header}
        <p className="text-sm text-muted-foreground">Type at least two characters in the search box.</p>
      </>
    )
  if (error)
    return (
      <>
        {header}
        <ErrorState error={error} onRetry={() => refetch()} />
      </>
    )
  if (isPending || !data)
    return (
      <>
        {header}
        <LoadingBlock />
      </>
    )
  const count =
    data.certificates.length +
    data.acme_accounts.length +
    data.acme_orders.length +
    data.provisioners.length +
    data.admins.length
  const truncated = new Set(data.truncated)
  return (
    <>
      {header}
      {count === 0 ? (
        <p className="text-sm text-muted-foreground">
          Nothing matches. Serials work in decimal or hex, with or without colons; names match anywhere in the subject
          or DNS names.
        </p>
      ) : (
        <div className="flex flex-col gap-6">
          {data.certificates.length > 0 && (
            <Section title={plural(data.certificates.length, "certificate")}>
              <ul className="divide-y">
                {data.certificates.map((cert) => (
                  <Row key={cert.serial}>
                    <Link
                      to="/certificates/$serial"
                      params={{ serial: cert.serial }}
                      className="min-w-0 truncate font-medium underline-offset-4 hover:underline"
                    >
                      {cert.common_name ?? cert.subject}
                    </Link>
                    <span className="flex items-center gap-3 text-muted-foreground">
                      until {formatDate(cert.not_after)}
                      <CertificateStatusPill status={cert.status} expiring={cert.expiring} />
                    </span>
                  </Row>
                ))}
              </ul>
              <More shown={truncated.has("certificates")} />
            </Section>
          )}
          {data.acme_accounts.length > 0 && (
            <Section title={plural(data.acme_accounts.length, "ACME account")}>
              <ul className="divide-y">
                {data.acme_accounts.map((account) => (
                  <Row key={account.id}>
                    <Link
                      to="/acme/accounts/$id"
                      params={{ id: account.id }}
                      className="font-medium underline-offset-4 hover:underline"
                    >
                      {account.contact.map((c) => c.replace(/^mailto:/, "")).join(", ") || account.id}
                    </Link>
                    <AcmeStatusPill status={account.status} />
                  </Row>
                ))}
              </ul>
              <More shown={truncated.has("acme_accounts")} />
            </Section>
          )}
          {data.acme_orders.length > 0 && (
            <Section title={plural(data.acme_orders.length, "ACME order")}>
              <ul className="divide-y">
                {data.acme_orders.map((order) => (
                  <Row key={order.id}>
                    <Link
                      to="/acme/orders/$id"
                      params={{ id: order.id }}
                      className="font-medium underline-offset-4 hover:underline"
                    >
                      <Identifiers values={order.identifiers} />
                    </Link>
                    <span className="flex items-center gap-3 text-muted-foreground">
                      {formatDate(order.created_at)}
                      <AcmeStatusPill status={order.status} />
                    </span>
                  </Row>
                ))}
              </ul>
              <More shown={truncated.has("acme_orders")} />
            </Section>
          )}
          {data.provisioners.length > 0 && (
            <Section title={plural(data.provisioners.length, "provisioner")}>
              <ul className="divide-y">
                {data.provisioners.map((provisioner) => (
                  <Row key={provisioner.id}>
                    <Link
                      to="/provisioners/$name"
                      params={{ name: provisioner.name }}
                      className="font-medium underline-offset-4 hover:underline"
                    >
                      {provisioner.name}
                    </Link>
                    <span className="text-muted-foreground">{provisioner.type}</span>
                  </Row>
                ))}
              </ul>
            </Section>
          )}
          {data.admins.length > 0 && (
            <Section title={plural(data.admins.length, "admin")}>
              <ul className="divide-y">
                {data.admins.map((admin) => (
                  <Row key={admin.id}>
                    <Link to="/admins" className="font-medium underline-offset-4 hover:underline">
                      {admin.subject}
                    </Link>
                    <span className="text-muted-foreground">
                      {admin.type} on {admin.provisioner_name ?? "an unknown provisioner"}
                    </span>
                  </Row>
                ))}
              </ul>
            </Section>
          )}
        </div>
      )}
    </>
  )
}
