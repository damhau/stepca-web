import { createFileRoute } from "@tanstack/react-router"
import { AlertTriangle, Download } from "lucide-react"
import { $api } from "@/api/client"
import { useCan } from "@/api/session"
import type { CaCertificate } from "@/api/types"
import { CopyButton } from "@/components/copy-button"
import { ErrorState, LineTabs, Loading, PageHeader, Pill, StatusDot } from "@/components/kit"
import { Fields, Section } from "@/components/page"
import { Button } from "@/components/ui/button"
import { formatDate, formatDateTime, fromNow, keyLabel, lifetime } from "@/lib/format"
import { oneOf } from "@/lib/search-params"
import { chainOf, commonName, type ChainLink } from "@/features/ca/chain"
import { cn } from "@/lib/utils"

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

function ChainOfTrust({
  roots,
  intermediates,
}: {
  roots: CaCertificate[] | null
  intermediates: CaCertificate[] | null
}) {
  const chain = chainOf(roots ?? [], intermediates ?? [])
  return (
    <div className="flex flex-col gap-3 p-4">
      {roots === null && <p className="text-muted-foreground">The roots could not be read from the CA.</p>}
      {intermediates === null && (
        <p className="text-muted-foreground">The intermediates could not be read from the CA.</p>
      )}
      {chain.length === 0 && roots !== null && intermediates !== null && (
        <p className="text-muted-foreground">The CA returned no root or intermediate.</p>
      )}
      {chain.length > 0 && (
        <ol aria-label="Chain of trust" className="flex flex-col">
          {chain.map((link, index) => (
            <li key={link.cert.fingerprint} className={cn("flex flex-col", index > 0 && !link.linked && "mt-4")}>
              {link.linked && <span aria-hidden className="ml-8 h-5 w-px bg-separator" />}
              <ChainCertificate {...link} />
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

function ChainCertificate({ cert, role, signing }: ChainLink) {
  const span = lifetime(cert.not_before, cert.not_after)
  const used = span ? Math.round(span.elapsed * 100) : null
  const level = used === null ? "ok" : used >= 95 ? "danger" : used >= 80 ? "warning" : "ok"
  return (
    <div className={cn("rounded-xl border bg-card px-4 py-3.5", signing && "border-foreground ring-1 ring-foreground")}>
      <div className="flex items-center justify-between gap-3">
        <span className="font-mono text-[11px] font-medium tracking-[0.08em] text-muted-foreground uppercase">
          {role}
        </span>
        <span className="flex items-center gap-2">
          {cert.pinned && <Pill tone="success">pinned</Pill>}
          {signing && (
            <span className="font-mono text-[11px] font-medium tracking-[0.08em] text-brand uppercase">Signing</span>
          )}
        </span>
      </div>
      <p className="mt-1.5 text-base font-semibold tracking-[-0.01em] break-words" title={cert.subject}>
        {commonName(cert.subject)}
      </p>
      <p className="mt-0.5 text-[13px] text-muted-foreground">
        {keyLabel(cert.key)} · until {formatDate(cert.not_after)}
      </p>
      <p className="mt-1.5 flex items-center gap-1 font-mono text-xs text-muted-foreground">
        SHA-256{" "}
        <span title={cert.fingerprint}>
          {cert.fingerprint.slice(0, 8)}…{cert.fingerprint.slice(-4)}
        </span>
        <CopyButton value={cert.fingerprint} label={`the ${role}'s SHA-256 fingerprint`} />
      </p>
      {used !== null && (
        <div className="mt-2.5">
          <div aria-hidden className="h-1.5 rounded-full bg-border-subtle">
            <div
              className={cn(
                "h-full rounded-full",
                level === "danger" ? "bg-danger" : level === "warning" ? "bg-warning" : "bg-foreground",
              )}
              style={{ width: `${Math.min(Math.max(used, 1), 100)}%` }}
            />
          </div>
          <p
            className={cn(
              "mt-1.5 text-[13px]",
              level === "danger" ? "text-danger-fg" : level === "warning" ? "text-warning-fg" : "text-muted-foreground",
            )}
          >
            {used}% of lifetime used · ends {fromNow(cert.not_after)}
          </p>
        </div>
      )}
    </div>
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
      {/* Both columns as tall as the taller; on the right, step-ca and the CRL share the height equally */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Section
          title="Chain of trust"
          actions={
            <>
              {!!data.roots?.length && <DownloadButton href="/api/v1/ca/roots.pem">roots.pem</DownloadButton>}
              {!!data.intermediates?.length && (
                <DownloadButton href="/api/v1/ca/intermediates.pem">intermediates.pem</DownloadButton>
              )}
            </>
          }
        >
          <ChainOfTrust roots={data.roots} intermediates={data.intermediates} />
        </Section>
        <div className="flex min-w-0 flex-col gap-4">
          <Section className="flex-1" title="step-ca">
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
                          This app is tested with step-ca {data.tested_versions.join(", ")}: it reads step-ca's
                          database, whose format can change.
                        </span>
                      </>
                    )}
                  </span>,
                ],
              ]}
            />
          </Section>
          <Section
            className="flex-1"
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
        </div>
      </div>
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
