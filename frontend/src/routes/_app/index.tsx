import { createFileRoute, Link } from "@tanstack/react-router"
import { Loader2 } from "lucide-react"
import { useState } from "react"
import { $api } from "@/api/client"
import type { CertificateItem, Dashboard } from "@/api/types"
import { ErrorState, LoadingBlock, PageHeader, Section } from "@/components/page"
import { AcmeStatusPill, EXPIRING_DAYS } from "@/components/status"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { ValidityBar } from "@/components/validity-bar"
import { formatDate, formatNumber, fromNow, plural } from "@/lib/format"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/")({ component: DashboardPage })

// The horizon: the next 13 weeks, a column per week
const HORIZON_WEEKS = 13
const HORIZON_DAYS = HORIZON_WEEKS * 7

function DashboardPage() {
  const dashboard = $api.useQuery("get", "/api/v1/dashboard")
  const horizon = $api.useQuery("get", "/api/v1/certificates", {
    params: { query: { status: "expiring", days: HORIZON_DAYS, sort: "not_after", order: "asc", per_page: 500 } },
  })
  return (
    <>
      <PageHeader title="Dashboard" description="What step-ca has issued, and what needs renewing soon." />
      {dashboard.error ? (
        <ErrorState error={dashboard.error} onRetry={() => dashboard.refetch()} />
      ) : !dashboard.data ? (
        <LoadingBlock lines={6} />
      ) : (
        <div className="flex flex-col gap-6">
          {dashboard.data.pending > 0 && (
            <p className="flex items-center gap-2 rounded-lg border bg-accent/50 px-4 py-3 text-sm">
              <Loader2 className="size-4 animate-spin" aria-hidden />
              Reading {plural(dashboard.data.pending, "more certificate")} from step-ca: the counts will grow until it
              is done.
            </p>
          )}
          <ExpiryHorizon dashboard={dashboard.data} certificates={horizon.data?.items} total={horizon.data?.total} />
          <Composition dashboard={dashboard.data} />
          <div className="grid gap-6 lg:grid-cols-2">
            <Section title="Issued per provisioner">
              <BarList
                rows={dashboard.data.issued_by_provisioner.map((row) => ({
                  label: row.name,
                  count: row.count,
                  link: row.name === "Unknown" ? undefined : { provisioner: row.name },
                }))}
                empty="No certificates yet."
              />
            </Section>
            <Section
              title="ACME orders by status"
              actions={
                <Link to="/acme/orders" className="text-sm text-primary underline-offset-4 hover:underline">
                  All orders
                </Link>
              }
            >
              <BarList
                rows={dashboard.data.acme_orders_by_status.map((row) => ({
                  label: <AcmeStatusPill status={row.name} />,
                  count: row.count,
                }))}
                empty="No ACME orders yet."
              />
            </Section>
          </div>
        </div>
      )}
    </>
  )
}

/** Certificates expiring each week of the next 13: the renewals ahead, soonest first. */
function ExpiryHorizon({
  dashboard,
  certificates,
  total,
}: {
  dashboard: Dashboard
  certificates: CertificateItem[] | undefined
  total: number | undefined
}) {
  const [now] = useState(() => Date.now())
  const weeks = Array.from({ length: HORIZON_WEEKS }, (_, index) => ({
    start: now + index * 7 * 86_400_000,
    items: [] as CertificateItem[],
  }))
  for (const certificate of certificates ?? []) {
    if (!certificate.not_after) continue
    const week = Math.floor((new Date(certificate.not_after).getTime() - now) / (7 * 86_400_000))
    weeks[Math.min(Math.max(week, 0), HORIZON_WEEKS - 1)]?.items.push(certificate)
  }
  const highest = Math.max(1, ...weeks.map((week) => week.items.length))
  const soonest = dashboard.expiring_soon[0]
  return (
    <section className="rounded-lg border bg-card p-5" aria-labelledby="horizon-title">
      <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <div>
          <h2 id="horizon-title" className="text-sm font-semibold">
            Expiry horizon
          </h2>
          <p className="mt-1 max-w-[65ch] text-lg leading-snug text-balance">
            {dashboard.expiring === 0 ? (
              <>Nothing needs renewing in the next {EXPIRING_DAYS} days.</>
            ) : (
              <>
                <span className="font-semibold text-expiring">{plural(dashboard.expiring, "certificate")}</span>{" "}
                {dashboard.expiring === 1 ? "needs" : "need"} renewing in the next {EXPIRING_DAYS} days
                {soonest && (
                  <>
                    , the first{" "}
                    <Link
                      to="/certificates/$serial"
                      params={{ serial: soonest.serial }}
                      className="font-medium underline-offset-4 hover:underline"
                    >
                      {soonest.common_name ?? soonest.subject}
                    </Link>{" "}
                    {fromNow(soonest.not_after)}
                  </>
                )}
                .
              </>
            )}
          </p>
        </div>
        <Link
          to="/certificates"
          search={{ status: "expiring", days: EXPIRING_DAYS, sort: "not_after", order: "asc" }}
          className="text-sm text-primary underline-offset-4 hover:underline"
        >
          See what expires
        </Link>
      </div>
      {certificates && weeks.every((week) => week.items.length === 0) ? (
        <p className="mt-5 grid h-20 place-items-center rounded-md border border-dashed text-sm text-muted-foreground">
          No long-lived certificate ends in the next {HORIZON_WEEKS} weeks.
        </p>
      ) : (
        <>
          <div
            className="mt-5 grid h-36 grid-cols-13 items-end gap-0.5"
            role="list"
            aria-label="Certificates expiring per week"
          >
            {weeks.map((week, index) => {
              const urgent = index * 7 < EXPIRING_DAYS
              const height = week.items.length === 0 ? 0 : Math.max((week.items.length / highest) * 100, 4)
              const label = `Week of ${formatDate(new Date(week.start).toISOString())}: ${plural(week.items.length, "certificate")}`
              return (
                <Tooltip key={week.start}>
                  <TooltipTrigger asChild>
                    <div
                      role="listitem"
                      aria-label={label}
                      className="group flex h-full flex-col justify-end rounded-sm hover:bg-muted/70"
                      tabIndex={0}
                    >
                      <div
                        className={cn(
                          "mx-[18%] rounded-t-[4px]",
                          urgent ? "bg-expiring" : "bg-primary/55 dark:bg-primary/70",
                        )}
                        style={{ height: `${height}%` }}
                      />
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p className="font-medium">{label}</p>
                    {week.items.slice(0, 4).map((item) => (
                      <p key={item.serial} className="max-w-64 truncate">
                        {item.common_name ?? item.subject}
                      </p>
                    ))}
                    {week.items.length > 4 && <p>and {formatNumber(week.items.length - 4)} more</p>}
                  </TooltipContent>
                </Tooltip>
              )
            })}
          </div>
          <div className="mt-2 grid grid-cols-13 gap-0.5 border-t pt-2 text-xs text-muted-foreground" aria-hidden>
            {weeks.map((week, index) => (
              <span key={week.start} className={cn("truncate", index % 2 === 1 && "max-sm:invisible")}>
                {index === 0
                  ? "This week"
                  : new Date(week.start).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
              </span>
            ))}
          </div>
        </>
      )}
      <p className="mt-3 text-xs text-muted-foreground">
        Certificates issued for 30 days or less are left out: they are meant to be renewed automatically.
        {total !== undefined && certificates && total > certificates.length && (
          <>
            {" "}
            The first {formatNumber(certificates.length)} of {formatNumber(total)} are shown.
          </>
        )}
      </p>
      {dashboard.expiring_soon.length > 0 && (
        <ul className="mt-5 divide-y border-t">
          {dashboard.expiring_soon.map((item) => (
            <li key={item.serial} className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1 py-2.5">
              <Link
                to="/certificates/$serial"
                params={{ serial: item.serial }}
                className="min-w-0 truncate text-sm font-medium underline-offset-4 hover:underline"
              >
                {item.common_name ?? item.subject}
              </Link>
              <ValidityBar
                notBefore={item.not_before}
                notAfter={item.not_after}
                status={item.status}
                expiring={item.expiring}
                className="w-48"
              />
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

const SEGMENTS = [
  { key: "healthy", label: "Valid", fill: "bg-valid", status: "valid" },
  { key: "expiring", label: `Expiring within ${EXPIRING_DAYS} days`, fill: "bg-expiring", status: "expiring" },
  { key: "expired", label: "Expired", fill: "bg-expired", status: "expired" },
  { key: "revoked", label: "Revoked", fill: "bg-revoked", status: "revoked" },
] as const

/** The whole inventory in one bar: what is valid, expiring, expired or revoked. */
function Composition({ dashboard }: { dashboard: Dashboard }) {
  const counts = {
    healthy: dashboard.valid - dashboard.expiring,
    expiring: dashboard.expiring,
    expired: dashboard.expired,
    revoked: dashboard.revoked,
  }
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0)
  return (
    <section className="rounded-lg border bg-card p-5" aria-labelledby="inventory-title">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="inventory-title" className="text-sm font-semibold">
          {plural(dashboard.total, "certificate")} issued
        </h2>
        <p className="text-sm text-muted-foreground">
          {plural(dashboard.acme_certificates, "issued", "issued")} over ACME,{" "}
          {plural(dashboard.provisioners, "provisioner")}
        </p>
      </div>
      {total > 0 && (
        <div className="mt-4 flex h-3 gap-0.5 overflow-hidden" aria-hidden>
          {SEGMENTS.map((segment) =>
            counts[segment.key] > 0 ? (
              <div
                key={segment.key}
                className={cn("rounded-[3px]", segment.fill)}
                style={{ flexGrow: counts[segment.key], flexBasis: 0, minWidth: 6 }}
              />
            ) : null,
          )}
        </div>
      )}
      <ul className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {SEGMENTS.map((segment) => (
          <li key={segment.key}>
            <Link
              to="/certificates"
              search={
                segment.status === "expiring"
                  ? { status: "expiring", days: EXPIRING_DAYS, sort: "not_after", order: "asc" }
                  : { status: segment.status }
              }
              className="group -m-2 flex flex-col rounded-md p-2 hover:bg-muted"
            >
              <span className="flex items-center gap-2 text-sm text-muted-foreground">
                <span className={cn("size-2.5 rounded-[3px]", segment.fill)} aria-hidden />
                {segment.label}
              </span>
              <span className="mt-0.5 text-xl font-semibold tabular-nums">{formatNumber(counts[segment.key])}</span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  )
}

type BarRow = { label: React.ReactNode; count: number; link?: { provisioner: string } }

function BarList({ rows, empty }: { rows: BarRow[]; empty: string }) {
  if (rows.length === 0) return <p className="p-4 text-sm text-muted-foreground">{empty}</p>
  const highest = Math.max(...rows.map((row) => row.count))
  return (
    <ul className="flex flex-col gap-3 p-4">
      {rows.map((row, index) => {
        const content = (
          <>
            <span className="flex items-center justify-between gap-3 text-sm">
              <span className="min-w-0 truncate">{row.label}</span>
              <span className="text-muted-foreground tabular-nums">{formatNumber(row.count)}</span>
            </span>
            <span className="mt-1.5 block h-1.5 rounded-full bg-track">
              <span
                className="block h-full rounded-full bg-primary/70"
                style={{ width: `${Math.max((row.count / highest) * 100, 1)}%` }}
              />
            </span>
          </>
        )
        return (
          <li key={index}>
            {row.link ? (
              <Link
                to="/certificates"
                search={{ provisioner: row.link.provisioner }}
                className="-m-1.5 block rounded-md p-1.5 hover:bg-muted"
              >
                {content}
              </Link>
            ) : (
              <div>{content}</div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
