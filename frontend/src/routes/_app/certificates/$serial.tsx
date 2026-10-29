import { createFileRoute, Link } from "@tanstack/react-router"
import { ChevronLeft, Download, ShieldOff } from "lucide-react"
import { useState } from "react"
import { $api } from "@/api/client"
import { useCan } from "@/api/session"
import { CopyButton, Identifier } from "@/components/copy-button"
import { Lifetime } from "@/components/lifetime"
import { ErrorState, Fields, LoadingBlock, PageHeader, Section } from "@/components/page"
import { CertificateStatusPill } from "@/components/status"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { RevokeDialog } from "@/features/certificates/revoke-dialog"
import { formatDateTime } from "@/lib/format"

export const Route = createFileRoute("/_app/certificates/$serial")({ component: CertificatePage })

function CertificatePage() {
  const { serial } = Route.useParams()
  const can = useCan()
  const [revoking, setRevoking] = useState(false)
  const { data, error, refetch } = $api.useQuery("get", "/api/v1/certificates/{serial}", {
    params: { path: { serial } },
  })
  const back = (
    <Link
      to="/certificates"
      className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
    >
      <ChevronLeft className="size-4" aria-hidden /> Certificates
    </Link>
  )
  if (error) {
    return (
      <>
        {back}
        <ErrorState error={error} onRetry={() => refetch()} />
      </>
    )
  }
  if (!data) return <LoadingBlock lines={8} />
  const cert = data.certificate
  const name = cert.common_name ?? cert.subject
  const download = (format: string) =>
    `/api/v1/certificates/${cert.serial}/download${format === "pem" ? "" : `?format=${format}`}`
  return (
    <>
      {back}
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-3">
            {name}
            <CertificateStatusPill status={cert.status} expiring={cert.expiring} />
          </span>
        }
        description={cert.subject}
        actions={
          <>
            <Button variant="outline" size="sm" asChild>
              <a href={download("pem")} download>
                <Download /> PEM
              </a>
            </Button>
            <Button
              variant="outline"
              size="sm"
              asChild
              title="The certificate followed by the intermediate that issued it"
            >
              <a href={download("chain")} download>
                <Download /> With chain
              </a>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a href={download("der")} download>
                <Download /> DER
              </a>
            </Button>
            {can("operator") && cert.status !== "revoked" && (
              <Button variant="destructive" size="sm" onClick={() => setRevoking(true)}>
                <ShieldOff /> Revoke
              </Button>
            )}
          </>
        }
      />
      <div className="flex flex-col gap-6">
        <section className="rounded-lg border bg-card p-5" aria-label="Lifetime">
          <Lifetime
            notBefore={cert.not_before}
            notAfter={cert.not_after}
            status={cert.status}
            expiring={cert.expiring}
            revokedAt={cert.revoked_at}
          />
        </section>
        {data.revocation && (
          <Section title="Revocation" className="border-revoked/40">
            <Fields
              rows={[
                ["Revoked", formatDateTime(data.revocation.revoked_at)],
                [
                  "Reason",
                  `${data.revocation.reason || "No reason given"}${data.revocation.reason_code !== null ? ` (code ${data.revocation.reason_code})` : ""}`,
                ],
                ["Through provisioner", data.revocation.provisioner_name ?? data.revocation.provisioner_id ?? "—"],
                [
                  "Revoked over",
                  data.revocation.acme
                    ? "ACME"
                    : data.revocation.mtls
                      ? "mTLS (the certificate itself)"
                      : "a provisioner token",
                ],
              ]}
            />
          </Section>
        )}
        <div className="grid gap-6 xl:grid-cols-2">
          <Section title="Identity">
            <Fields
              rows={[
                ["Subject", cert.subject],
                ["Issuer", cert.issuer],
                ["Serial (decimal)", <Identifier key="d" value={cert.serial} label="decimal serial" />],
                ["Serial (hex)", <Identifier key="h" value={cert.serial_hex} label="hex serial" />],
                ["Key", cert.key],
                ["Names", cert.dns_names.length ? cert.dns_names.join(", ") : "—"],
                [
                  "Issued by provisioner",
                  cert.provisioner_name ? (
                    <Link to="/provisioners" className="underline-offset-4 hover:underline">
                      {cert.provisioner_name}
                    </Link>
                  ) : (
                    "—"
                  ),
                ],
                ...(data.acme_order_id
                  ? ([
                      [
                        "ACME order",
                        <Link
                          key="o"
                          to="/acme/orders/$id"
                          params={{ id: data.acme_order_id }}
                          className="font-mono text-[0.8125rem] underline-offset-4 hover:underline"
                        >
                          {data.acme_order_id}
                        </Link>,
                      ],
                    ] as [React.ReactNode, React.ReactNode][])
                  : []),
              ]}
            />
          </Section>
          <Section title="Extensions">
            <Fields
              rows={data.extensions.map((extension) => [
                <span key="n" className="flex flex-wrap items-center gap-2">
                  {extension.name}
                  {extension.critical && <Badge variant="outline">critical</Badge>}
                </span>,
                extension.value,
              ])}
            />
          </Section>
        </div>
        <Section title="PEM" actions={<CopyButton value={data.pem} label="PEM" />}>
          <pre className="max-h-72 overflow-auto p-4 font-mono text-xs leading-relaxed">{data.pem}</pre>
        </Section>
      </div>
      <RevokeDialog target={revoking ? { serial: cert.serial, name } : null} onClose={() => setRevoking(false)} />
    </>
  )
}
