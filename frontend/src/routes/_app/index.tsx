import { keepPreviousData } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import { Check, CircleHelp, Loader2, Plus } from "lucide-react"
import { $api } from "@/api/client"
import type { components } from "@/api/schema"
import { useCan } from "@/api/session"
import { Callout, Card, CardHeader, ErrorState, Loading, PageHeader, Segmented } from "@/components/kit"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useIssue } from "@/features/issue/issue-context"
import { formatDateTime, formatNumber, fromNow, plural } from "@/lib/format"
import { oneOf } from "@/lib/search-params"
import { cn } from "@/lib/utils"

type Overview = components["schemas"]["Overview"]
type Kpi = components["schemas"]["Kpi"]
type Range = "24h" | "7d" | "30d"

const RANGES: { value: Range; label: string }[] = [
  { value: "24h", label: "24h" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
]
const SINCE: Record<Range, string> = { "24h": "yesterday", "7d": "last week", "30d": "last month" }
const LAST: Record<Range, string> = {
  "24h": "in the last 24 hours",
  "7d": "in the last 7 days",
  "30d": "in the last 30 days",
}
const SERIES_COLORS = ["bg-chart-1", "bg-chart-2", "bg-chart-3"]

export const Route = createFileRoute("/_app/")({
  validateSearch: (search: Record<string, unknown>): { range?: Range } => ({
    range: oneOf(search.range, ["24h", "7d", "30d"] as const),
  }),
  component: OverviewPage,
})

function OverviewPage() {
  const { range = "30d" } = Route.useSearch()
  const navigate = Route.useNavigate()
  const issue = useIssue()
  const overview = $api.useQuery(
    "get",
    "/api/v1/overview",
    { params: { query: { range } } },
    { placeholderData: keepPreviousData },
  )
  return (
    <>
      <PageHeader
        title="Overview"
        actions={
          <>
            <Segmented
              label="Range"
              options={RANGES}
              value={range}
              onChange={(value) => navigate({ search: { range: value === "30d" ? undefined : value }, replace: true })}
            />
            {issue.allowed && (
              <Button onClick={issue.open}>
                <Plus strokeWidth={2.2} /> New certificate
              </Button>
            )}
          </>
        }
      />
      {overview.error ? (
        <ErrorState error={overview.error} onRetry={() => overview.refetch()} />
      ) : !overview.data ? (
        <Loading lines={8} />
      ) : (
        <>
          {overview.data.pending > 0 && (
            <p className="flex items-center gap-2 text-[13px] text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin" aria-hidden /> Reading{" "}
              {plural(overview.data.pending, "more certificate")} from step-ca: the figures will grow until it is done.
            </p>
          )}
          <Attention overview={overview.data} />
          <div className="grid grid-cols-[repeat(auto-fit,minmax(160px,1fr))] gap-3">
            {overview.data.kpis.map((kpi) => (
              <KpiCard key={kpi.key} kpi={kpi} range={range} />
            ))}
          </div>
          <div className="flex flex-wrap items-start gap-4">
            <Issuance overview={overview.data} range={range} />
            <div className="flex min-w-0 flex-[1_1_300px] flex-col gap-4">
              <Health overview={overview.data} />
              <Readiness />
            </div>
          </div>
          <Activity overview={overview.data} />
        </>
      )}
    </>
  )
}

function Attention({ overview }: { overview: Overview }) {
  const callout = overview.callout
  if (!callout) return null
  if (callout.kind === "expiring") {
    return (
      <Callout
        action={
          <Link
            to="/certificates"
            search={{ cert: callout.serial ?? undefined }}
            className="font-medium text-warning-strong"
          >
            Investigate →
          </Link>
        }
      >
        <strong className="font-semibold">{callout.name}</strong> expires {fromNow(callout.not_after)}.
        {callout.failed_renewals > 0 && (
          <>
            {" "}
            Automatic renewal via ACME has failed{" "}
            {callout.failed_renewals === 1 ? "once" : `${callout.failed_renewals} times`}
            {callout.error && ` (${callout.error})`}.
          </>
        )}
      </Callout>
    )
  }
  return (
    <Callout
      action={
        <Link to="/acme/orders" search={{ status: "invalid" }} className="font-medium text-warning-strong">
          Investigate →
        </Link>
      }
    >
      {plural(callout.failed_renewals, "ACME order")} failed in the last 24 hours, the latest for{" "}
      <strong className="font-semibold">{callout.name}</strong>
      {callout.error && ` (${callout.error})`}.
    </Callout>
  )
}

function sparkline(values: number[]) {
  const max = Math.max(...values)
  const min = Math.min(...values)
  return values
    .map(
      (value, index) =>
        `${index ? "L" : "M"}${((index * 88) / Math.max(values.length - 1, 1)).toFixed(1)} ${(28 - ((value - min) / (max - min || 1)) * 24).toFixed(1)}`,
    )
    .join(" ")
}

function delta(kpi: Kpi, range: Range) {
  const change = kpi.value - kpi.previous
  const sign = change > 0 ? "+" : change < 0 ? "−" : ""
  if (kpi.key === "active")
    return change ? `${sign}${formatNumber(Math.abs(change))} vs ${SINCE[range]}` : `no change since ${SINCE[range]}`
  if (!change) return "stable"
  if ((kpi.key === "issued" || kpi.key === "revoked") && kpi.previous)
    return `${sign}${Math.round((Math.abs(change) / kpi.previous) * 100)}%`
  return `${sign}${formatNumber(Math.abs(change))}`
}

function KpiCard({ kpi, range }: { kpi: Kpi; range: Range }) {
  const warning = kpi.key === "expiring"
  const text = delta(kpi, range)
  const quiet = text === "stable" || text.startsWith("no change")
  return (
    <div className="flex flex-col gap-2 rounded-xl border bg-card p-4">
      <p className="text-[13px] text-muted-foreground">{kpi.label}</p>
      <div className="flex items-end justify-between gap-2">
        <div>
          <p className="text-[26px] font-semibold tracking-[-0.02em] tabular-nums">{formatNumber(kpi.value)}</p>
          <p
            className={cn(
              "mt-0.5 text-xs",
              warning && !quiet ? "text-warning-fg" : quiet ? "text-muted-foreground" : "text-success",
            )}
          >
            {text}
          </p>
        </div>
        <svg
          width="88"
          height="32"
          viewBox="0 0 88 32"
          aria-hidden
          className={warning ? "text-warning-fg" : "text-brand"}
        >
          <path
            d={sparkline(kpi.series)}
            fill="none"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinejoin="round"
            strokeLinecap="round"
          />
        </svg>
      </div>
    </div>
  )
}

function axisLabel(value: string, range: Range) {
  const date = new Date(value)
  return range === "24h"
    ? date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString(undefined, { day: "numeric", month: "short" })
}

function Issuance({ overview, range }: { overview: Overview; range: Range }) {
  const { series, buckets, total } = overview.issuance
  const highest = Math.max(1, ...buckets.map((bucket) => bucket.counts.reduce((sum, count) => sum + count, 0)))
  const first = buckets[0]
  return (
    <Card className="flex-[2_1_520px]">
      <CardHeader
        title="Issuance by provisioner"
        description={`${plural(total, "certificate")} ${LAST[range]}`}
        actions={
          series.length > 0 && (
            <ul className="flex flex-wrap gap-3.5 text-xs text-fg-2">
              {series.map((name, index) => (
                <li key={name} className="flex items-center gap-1.5">
                  <span aria-hidden className={cn("size-2 rounded-[2px]", SERIES_COLORS[index])} />
                  {name}
                </li>
              ))}
            </ul>
          )
        }
      />
      <div
        role="img"
        aria-label={`Certificates issued ${LAST[range]}, by provisioner: ${series.join(", ") || "none"}`}
        className="flex h-[200px] items-end gap-[3px] px-4 pt-5 pb-2"
      >
        {buckets.map((bucket) => {
          const sum = bucket.counts.reduce((all, count) => all + count, 0)
          return (
            <Tooltip key={bucket.start}>
              <TooltipTrigger asChild>
                <div className="flex h-full min-w-0 flex-1 flex-col justify-end gap-px rounded-sm hover:bg-sidebar">
                  {[...bucket.counts.keys()].reverse().map((index) => {
                    const count = bucket.counts[index] ?? 0
                    const top = bucket.counts.findLastIndex((value) => value > 0) === index
                    return count ? (
                      <div
                        key={index}
                        className={cn(SERIES_COLORS[index], top && "rounded-t-[2px]")}
                        style={{ height: `${(count / highest) * 100}%` }}
                      />
                    ) : null
                  })}
                  {sum === 0 && <div className="h-px bg-border" />}
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p className="font-medium">
                  {formatDateTime(bucket.start)}: {plural(sum, "certificate")}
                </p>
                {series.map((name, index) =>
                  bucket.counts[index] ? <p key={name}>{`${name}: ${bucket.counts[index]}`}</p> : null,
                )}
              </TooltipContent>
            </Tooltip>
          )
        })}
      </div>
      <div aria-hidden className="flex justify-between px-4 pb-3.5 font-mono text-[11px] text-muted-foreground">
        <span>{first ? axisLabel(first.start, range) : ""}</span>
        <span>{range === "24h" ? "now" : "today"}</span>
      </div>
    </Card>
  )
}

const TONE_DOT = { ok: "bg-success", warn: "bg-warning", bad: "bg-danger", unknown: "bg-neutral-dot" } as const

function Health({ overview }: { overview: Overview }) {
  const ca = $api.useQuery("get", "/api/v1/ca", {}, { staleTime: 60_000 })
  const rows: { tone: keyof typeof TONE_DOT; label: string; value: string }[] = []
  if (ca.data) {
    const status = ca.data
    rows.push({
      tone: status.health === "ok" ? "ok" : "bad",
      label: "CA API",
      value: status.health === "ok" ? (status.version ? `v${status.version}` : "ok") : (status.health ?? "unreachable"),
    })
    rows.push(
      status.crl
        ? {
            tone: status.crl.next_update && new Date(status.crl.next_update) < new Date() ? "warn" : "ok",
            label: "CRL",
            value: `fresh · ${new Date(status.crl.this_update).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`,
          }
        : { tone: "unknown", label: "CRL", value: "not published" },
    )
    const root = status.roots?.[0]
    rows.push(
      root
        ? {
            tone: root.days_left < 180 ? "warn" : "ok",
            label: "Root certificate",
            value: `ends ${fromNow(root.not_after)}`,
          }
        : { tone: "unknown", label: "Root certificate", value: "—" },
    )
    const intermediate = status.intermediates?.[0]
    rows.push(
      intermediate
        ? {
            tone: intermediate.days_left < 30 ? "bad" : intermediate.days_left < 90 ? "warn" : "ok",
            label: "Intermediate",
            value: `ends ${fromNow(intermediate.not_after)}`,
          }
        : { tone: "unknown", label: "Intermediate", value: "—" },
    )
  }
  const failing = overview.callout?.failed_renewals ?? 0
  rows.push({
    tone: failing ? "warn" : "ok",
    label: "ACME renewals",
    value: failing ? `${failing} failing` : "no failures",
  })
  return (
    <Card>
      <h2 className="border-b border-border-subtle px-4 py-3.5 text-sm font-semibold">
        <Link to="/ca" className="text-foreground no-underline hover:underline">
          Authority health
        </Link>
      </h2>
      {ca.isPending ? (
        <Loading lines={4} />
      ) : (
        <ul className="py-1.5">
          {ca.error && (
            <li className="px-4 py-2">
              <ErrorState error={ca.error} />
            </li>
          )}
          {rows.map((row) => (
            <li key={row.label} className="flex items-center gap-2.5 px-4 py-2">
              <span aria-hidden className={cn("size-2 rounded-full", TONE_DOT[row.tone])} />
              <span className="flex-1">{row.label}</span>
              <span className="font-mono text-xs text-muted-foreground">{row.value}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function Readiness() {
  const readiness = $api.useQuery("get", "/api/v1/readiness", {}, { staleTime: 60_000 })
  const checks = readiness.data?.checks ?? []
  const done = checks.filter((check) => check.done).length
  return (
    <Card className="flex flex-col gap-3 px-4 py-3.5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">Production readiness</h2>
        {readiness.data && <span className="text-[13px] text-muted-foreground">{`${done} of ${checks.length}`}</span>}
      </div>
      {readiness.isPending ? (
        <Loading lines={4} className="p-0" />
      ) : readiness.error ? (
        <ErrorState error={readiness.error} />
      ) : (
        <>
          <div aria-hidden className="h-1.5 rounded-full bg-border-subtle">
            <div
              className="h-full rounded-full bg-brand"
              style={{ width: `${checks.length ? (done / checks.length) * 100 : 0}%` }}
            />
          </div>
          <ul className="flex flex-col gap-0.5">
            {checks.map((check) => (
              <li key={check.key}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p
                      tabIndex={0}
                      className={cn(
                        "flex min-h-8 items-center gap-2.5",
                        check.done ? "text-muted-foreground line-through" : "text-foreground",
                      )}
                    >
                      <span
                        className={cn(
                          "grid size-4 shrink-0 place-items-center rounded-[4px] border",
                          check.done ? "border-inverse bg-inverse text-inverse-foreground" : "border-separator bg-card",
                        )}
                      >
                        {check.done ? (
                          <Check className="size-3" strokeWidth={3} aria-hidden />
                        ) : check.done === null ? (
                          <CircleHelp className="size-3 text-muted-foreground" aria-hidden />
                        ) : null}
                      </span>
                      <span className="sr-only">
                        {check.done ? "Done: " : check.done === null ? "Unknown: " : "To do: "}
                      </span>
                      {check.label}
                    </p>
                  </TooltipTrigger>
                  <TooltipContent side="left">{check.detail}</TooltipContent>
                </Tooltip>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  )
}

const AVATARS = [
  ["#E0E7FF", "#3730A3"],
  ["#DBEAFE", "#1E40AF"],
  ["#FCE7F3", "#9D174D"],
  ["#F4F4F5", "#3F3F46"],
  ["#DCFCE7", "#166534"],
  ["#FEF3C7", "#92400E"],
] as const

function avatar(name: string) {
  let hash = 0
  for (const char of name) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
  const [background, color] = AVATARS[hash % AVATARS.length]!
  const parts = name.split(/[\s._@-]+/).filter(Boolean)
  return {
    background,
    color,
    initials: ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? parts[0]?.[1] ?? "")).toUpperCase(),
  }
}

function Activity({ overview }: { overview: Overview }) {
  const can = useCan()
  return (
    <Card>
      <CardHeader
        title="Recent activity"
        actions={
          can("admin") && (
            <Link to="/audit" className="text-[13px] font-medium">
              View audit log
            </Link>
          )
        }
      />
      {overview.activity.length === 0 ? (
        <p className="px-4 py-6 text-muted-foreground">Nothing yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <tbody>
              {overview.activity.map((event, index) => {
                const face = avatar(event.actor)
                return (
                  <tr key={index} className={cn(index > 0 && "border-t border-border-subtle")}>
                    <td className="w-8 py-2.5 pr-2 pl-4">
                      <span
                        aria-hidden
                        className="grid size-[26px] place-items-center rounded-full text-[11px] font-semibold"
                        style={{ background: face.background, color: face.color }}
                      >
                        {face.initials}
                      </span>
                    </td>
                    <td className="px-2 py-2.5 [overflow-wrap:anywhere] sm:whitespace-nowrap">
                      <strong className="font-medium">{event.actor}</strong>{" "}
                      <span className="text-muted-foreground">{event.action}</span>{" "}
                      {event.serial ? (
                        <Link
                          to="/certificates"
                          search={{ cert: event.serial }}
                          className="font-mono text-[13px] text-foreground hover:underline"
                        >
                          {event.subject}
                        </Link>
                      ) : (
                        <span className="font-mono text-[13px]">{event.subject}</span>
                      )}
                    </td>
                    <td
                      className="px-4 py-2.5 text-right whitespace-nowrap text-muted-foreground"
                      title={formatDateTime(event.at)}
                    >
                      {fromNow(event.at)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}
