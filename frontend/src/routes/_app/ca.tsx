import { createFileRoute } from "@tanstack/react-router"
import { AlertTriangle, Download } from "lucide-react"
import { $api } from "@/api/client"
import { useCan } from "@/api/session"
import type { CaCertificate } from "@/api/types"
import { Identifier } from "@/components/copy-button"
import { ErrorState, LineTabs, Loading, PageHeader, Pill, StatusDot } from "@/components/kit"
import { Fields, Section } from "@/components/page"
import { Button } from "@/components/ui/button"
import { formatDateTime, fromNow, keyLabel } from "@/lib/format"
import { oneOf } from "@/lib/search-params"

export const Route = createFileRoute("/_app/ca")({
  validateSearch: (search: Record<string, unknown>): { tab?: "configuration" } => ({
    tab: oneOf(search.tab, ["configuration"] as const),
  }),
  component: Authority,
})

function Authority() {
  const { tab } = Route.useSearch()
  const navigate = Route.useNavigate()
  const can = useCan()
  const showing = can("admin") && tab === "configuration" ? "configuration" : "status"
  return (
    <>
      <PageHeader
        title="Authority"
        description="The step-ca this app manages, and how the app is set up to reach it."
      />
      {can("admin") && (
        <LineTabs
          label="Authority sections"
          value={showing}
          onChange={(value) =>
            navigate({ search: { tab: value === "configuration" ? "configuration" : undefined }, replace: true })
          }
          tabs={[
            { value: "status", label: "Status" },
            { value: "configuration", label: "Configuration" },
          ]}
        />
      )}
      {showing === "status" ? <Status /> : <Configuration />}
    </>
  )
}

function DownloadButton({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Button variant="outline" size="sm" asChild>
      <a href={href} download className="text-foreground no-underline hover:text-foreground">
        <Download /> {children}
      </a>
    </Button>
  )
}

function CaCertificates({ certificates, kind }: { certificates: CaCertificate[] | null; kind: string }) {
  if (certificates === null) return <p className="px-4 py-3.5 text-muted-foreground">Could not be read from the CA.</p>
  if (certificates.length === 0) return <p className="px-4 py-3.5 text-muted-foreground">The CA returned no {kind}.</p>
  return (
    <ul className="divide-y divide-border-subtle">
      {certificates.map((cert) => (
        <li key={cert.fingerprint} className="flex flex-col gap-1.5 px-4 py-3">
          <span className="flex flex-wrap items-center gap-2 font-medium">
            {cert.subject}
            {cert.pinned && <Pill tone="success">pinned</Pill>}
          </span>
          <span className="flex flex-wrap gap-x-4 text-[13px] text-muted-foreground">
            <span
              className={cert.days_left < 30 ? "text-danger-fg" : cert.days_left < 180 ? "text-warning-fg" : undefined}
            >
              Ends {formatDateTime(cert.not_after)} ({fromNow(cert.not_after)})
            </span>
            <span>{keyLabel(cert.key)}</span>
          </span>
          <span className="flex items-start gap-2 text-[13px] text-muted-foreground">
            <span className="whitespace-nowrap">SHA-256</span>
            <Identifier value={cert.fingerprint} label="fingerprint" />
          </span>
        </li>
      ))}
    </ul>
  )
}

function Status() {
  const { data, error, refetch } = $api.useQuery("get", "/api/v1/ca")
  if (error) return <ErrorState error={error} onRetry={() => refetch()} />
  if (!data) return <Loading lines={8} />
  return (
    <>
      {data.errors.length > 0 && (
        <div role="alert" className="rounded-xl border border-danger-border bg-danger-bg px-4 py-3 text-danger-fg">
          <p className="font-medium">Some of it could not be read:</p>
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
              <span key="u" className="font-mono text-[13px]">
                {data.url}
              </span>,
            ],
            [
              "Health",
              data.health === "ok" ? (
                <StatusDot key="h" tone="success">
                  ok
                </StatusDot>
              ) : (
                <StatusDot key="h" tone="danger">
                  {data.health ?? "unreachable"}
                </StatusDot>
              ),
            ],
            [
              "Version",
              <span key="v" className="flex flex-wrap items-center gap-2">
                {data.version ?? "—"}
                {data.version && !data.version_tested && (
                  <>
                    <Pill tone="warning">not tested</Pill>
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
      <div className="grid gap-4 xl:grid-cols-2">
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
            <p className="px-4 py-3.5 text-muted-foreground">
              step-ca doesn't publish a CRL: set{" "}
              <span className="font-mono text-[13px]">
                "crl": {"{"}"enabled": true{"}"}
              </span>{" "}
              in ca.json to turn it on.
            </p>
          )
        )}
      </Section>
    </>
  )
}

function Configuration() {
  const { data, error, refetch } = $api.useQuery("get", "/api/v1/settings")
  if (error) return <ErrorState error={error} onRetry={() => refetch()} />
  if (!data) return <Loading lines={8} />
  return (
    <>
      <p className="text-muted-foreground">
        The settings in effect, from the environment and settings.json. Passwords and keys are never shown: change them
        where the app is deployed, then restart it.
      </p>
      {data.warnings.map((warning) => (
        <p
          key={warning}
          role="alert"
          className="flex gap-2 rounded-xl border border-warning-border bg-warning-bg px-4 py-3 text-warning-strong"
        >
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning-fg" aria-hidden />
          {warning}
        </p>
      ))}
      <div className="grid gap-4 xl:grid-cols-2">
        {data.sections.map((section) => (
          <Section key={section.title} title={section.title}>
            <Fields rows={section.items.map((item) => [item.label, item.value])} />
          </Section>
        ))}
      </div>
    </>
  )
}
