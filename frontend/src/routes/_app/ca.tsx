import { createFileRoute } from "@tanstack/react-router"
import { Download } from "lucide-react"
import { $api } from "@/api/client"
import type { CaCertificate } from "@/api/types"
import { Identifier } from "@/components/copy-button"
import { ErrorState, Fields, LoadingBlock, PageHeader, Section } from "@/components/page"
import { Pill } from "@/components/status"
import { Button } from "@/components/ui/button"
import { formatDateTime, fromNow } from "@/lib/format"

export const Route = createFileRoute("/_app/ca")({ component: CaStatus })

function DownloadButton({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Button variant="outline" size="sm" asChild>
      <a href={href} download>
        <Download /> {children}
      </a>
    </Button>
  )
}

function CaCertificates({ certificates, kind }: { certificates: CaCertificate[] | null; kind: string }) {
  if (certificates === null) return <p className="p-4 text-sm text-muted-foreground">Could not be read from the CA.</p>
  if (certificates.length === 0) return <p className="p-4 text-sm text-muted-foreground">The CA returned no {kind}.</p>
  return (
    <ul className="divide-y">
      {certificates.map((cert) => (
        <li key={cert.fingerprint} className="flex flex-col gap-1.5 px-4 py-3 text-sm">
          <span className="flex flex-wrap items-center gap-2 font-medium">
            {cert.subject}
            {cert.pinned && <Pill tone="valid">pinned</Pill>}
          </span>
          <span className="flex flex-wrap gap-x-4 text-muted-foreground">
            <span className={cert.days_left < 30 ? "text-revoked" : cert.days_left < 180 ? "text-expiring" : undefined}>
              Expires {formatDateTime(cert.not_after)} ({fromNow(cert.not_after)})
            </span>
            <span>{cert.key}</span>
          </span>
          <span className="flex items-start gap-2 text-muted-foreground">
            <span className="whitespace-nowrap">SHA-256</span>
            <Identifier value={cert.fingerprint} label="fingerprint" />
          </span>
        </li>
      ))}
    </ul>
  )
}

function CaStatus() {
  const { data, error, refetch } = $api.useQuery("get", "/api/v1/ca")
  if (error) return <ErrorState error={error} onRetry={() => refetch()} />
  if (!data) return <LoadingBlock lines={8} />
  return (
    <>
      <PageHeader title="CA status" description="What step-ca reports about itself, asked just now." />
      <div className="flex flex-col gap-6">
        {data.errors.length > 0 && (
          <div role="alert" className="rounded-lg border border-revoked/30 bg-revoked-soft/50 px-4 py-3 text-sm">
            <p className="font-medium text-revoked">Some of it could not be read:</p>
            <ul className="mt-1 list-disc pl-5">
              {data.errors.map((message) => (
                <li key={message}>{message}</li>
              ))}
            </ul>
          </div>
        )}
        <Section title="step-ca">
          <Fields
            rows={[
              [
                "URL",
                <code key="u" className="font-mono text-[0.8125rem]">
                  {data.url}
                </code>,
              ],
              [
                "Health",
                data.health === "ok" ? (
                  <Pill key="h" tone="valid">
                    ok
                  </Pill>
                ) : (
                  <Pill key="h" tone="revoked">
                    {data.health ?? "unreachable"}
                  </Pill>
                ),
              ],
              [
                "Version",
                <span key="v" className="flex flex-wrap items-center gap-2">
                  {data.version ?? "—"}
                  {data.version && !data.version_tested && (
                    <>
                      <Pill tone="expiring">not tested</Pill>
                      <span className="text-muted-foreground">
                        This app is tested with step-ca {data.tested_versions.join(", ")}: it reads step-ca's database,
                        whose format can change.
                      </span>
                    </>
                  )}
                </span>,
              ],
            ]}
          />
        </Section>
        <div className="grid gap-6 xl:grid-cols-2">
          <Section
            title="Root certificates"
            actions={data.roots?.length ? <DownloadButton href="/api/v1/ca/roots.pem">roots.pem</DownloadButton> : null}
          >
            <CaCertificates certificates={data.roots} kind="roots" />
          </Section>
          <Section
            title="Intermediate certificates"
            actions={
              data.intermediates?.length ? (
                <DownloadButton href="/api/v1/ca/intermediates.pem">intermediates.pem</DownloadButton>
              ) : null
            }
          >
            <CaCertificates certificates={data.intermediates} kind="intermediates" />
          </Section>
        </div>
        <Section
          title="Certificate revocation list"
          actions={
            data.crl && (
              <>
                <DownloadButton href="/api/v1/ca/crl">DER</DownloadButton>
                <DownloadButton href="/api/v1/ca/crl?format=pem">PEM</DownloadButton>
              </>
            )
          }
        >
          {data.crl ? (
            <Fields
              rows={[
                ["Revoked certificates", data.crl.entries],
                ["Issued", formatDateTime(data.crl.this_update)],
                ["Next update", formatDateTime(data.crl.next_update)],
              ]}
            />
          ) : (
            !data.errors.some((message) => message.startsWith("crl")) && (
              <p className="p-4 text-sm text-muted-foreground">
                step-ca doesn't publish a CRL: set{" "}
                <code className="font-mono">
                  "crl": {"{"}"enabled": true{"}"}
                </code>{" "}
                in ca.json to turn it on.
              </p>
            )
          )}
        </Section>
      </div>
    </>
  )
}
