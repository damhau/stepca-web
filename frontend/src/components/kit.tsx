import { AlertTriangle, RotateCw, X } from "lucide-react"
import { errorMessage } from "@/api/client"
import type { CertificateStatus } from "@/api/types"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

// The design's recurring pieces: cards with borders, status dots, chips, underline tabs, settings sections

export function PageHeader({
  title,
  description,
  actions,
  className,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn("flex flex-wrap items-center justify-between gap-3", className)}>
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-[-0.02em] break-words">{title}</h1>
        {description && <p className="mt-1 text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Card({ className, ...props }: React.ComponentProps<"section">) {
  return <section className={cn("min-w-0 rounded-xl border bg-card", className)} {...props} />
}

export function CardHeader({
  title,
  description,
  actions,
  className,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        "flex flex-wrap items-center justify-between gap-2.5 border-b border-border-subtle px-4 py-3.5",
        className,
      )}
    >
      <div className="min-w-0">
        <h2 className="text-sm font-semibold">{title}</h2>
        {description && <p className="mt-0.5 text-[13px] text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

const DOTS = {
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
  neutral: "bg-neutral-dot",
  brand: "bg-brand",
} as const

export type Tone = keyof typeof DOTS

/** A 7px dot and a label: status is never shown by colour alone. */
export function StatusDot({
  tone,
  children,
  className,
}: {
  tone: Tone
  children: React.ReactNode
  className?: string
}) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[13px] whitespace-nowrap", className)}>
      <span className={cn("size-[7px] shrink-0 rounded-full", DOTS[tone])} aria-hidden />
      {children}
    </span>
  )
}

export function certificateState(status: CertificateStatus, expiring: boolean): { tone: Tone; label: string } {
  if (status === "valid")
    return expiring ? { tone: "warning", label: "Expiring" } : { tone: "success", label: "Active" }
  if (status === "revoked") return { tone: "danger", label: "Revoked" }
  if (status === "not_yet_valid") return { tone: "brand", label: "Not yet valid" }
  if (status === "invalid") return { tone: "neutral", label: "Unreadable" }
  return { tone: "neutral", label: "Expired" }
}

export function CertificateStatus({ status, expiring }: { status: CertificateStatus; expiring: boolean }) {
  const state = certificateState(status, expiring)
  return <StatusDot tone={state.tone}>{state.label}</StatusDot>
}

const ACME_TONES: Record<string, Tone> = {
  valid: "success",
  ready: "brand",
  processing: "brand",
  pending: "warning",
  invalid: "danger",
  revoked: "danger",
  deactivated: "neutral",
  expired: "neutral",
}

/** The status of an ACME account, order, authorization or challenge (RFC 8555). */
export function AcmeStatus({ status }: { status: string }) {
  return <StatusDot tone={ACME_TONES[status] ?? "neutral"}>{status || "unknown"}</StatusDot>
}

/** A rounded badge: counts in tabs and the sidebar, environments, types. */
export function Pill({
  tone = "neutral",
  className,
  children,
}: {
  tone?: "neutral" | "warning" | "success" | "brand" | "danger"
  className?: string
  children: React.ReactNode
}) {
  const tones = {
    neutral: "bg-secondary text-fg-2",
    warning: "bg-warning-badge-bg text-warning-badge-fg",
    success: "bg-success-bg text-success-fg",
    brand: "bg-brand-soft text-brand",
    danger: "bg-danger-bg text-danger-fg",
  }
  return (
    <span className={cn("rounded-full px-1.5 text-xs font-medium whitespace-nowrap", tones[tone], className)}>
      {children}
    </span>
  )
}

/** A removable filter: "Provisioner is acme-internal, ops-jwk ×". */
export function FilterChip({ label, value, onRemove }: { label: string; value: string; onRemove: () => void }) {
  return (
    <span className="inline-flex min-h-8 items-center gap-1 rounded-full border bg-card py-0.5 pr-1 pl-2.5 text-[13px]">
      <span className="text-muted-foreground">{label}</span>
      <span className="max-w-64 truncate">{value}</span>
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove the ${label.toLowerCase().replace(/ is$/, "")} filter`}
        className="grid size-6 place-items-center rounded-full text-muted-foreground hover:bg-accent hover:text-foreground"
      >
        <X className="size-3.5" />
      </button>
    </span>
  )
}

export type LineTab<T extends string> = { value: T; label: React.ReactNode; count?: number | string }

/** Tabs drawn as a line under the selected one. */
export function LineTabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
  className,
  size = "default",
}: {
  tabs: LineTab<T>[]
  value: T
  onChange: (value: T) => void
  label: string
  className?: string
  size?: "default" | "sm"
}) {
  return (
    <div
      role="tablist"
      aria-label={label}
      className={cn(
        "flex [scrollbar-width:none] gap-5 overflow-x-auto overflow-y-hidden shadow-[inset_0_-1px_0_var(--border)]",
        size === "sm" && "gap-4",
        className,
      )}
      onKeyDown={(event) => {
        const index = tabs.findIndex((tab) => tab.value === value)
        const next = event.key === "ArrowRight" ? index + 1 : event.key === "ArrowLeft" ? index - 1 : null
        if (next === null) return
        const tab = tabs[(next + tabs.length) % tabs.length]
        if (tab) {
          event.preventDefault()
          onChange(tab.value)
          ;(event.currentTarget.querySelector(`[data-value="${tab.value}"]`) as HTMLElement | null)?.focus()
        }
      }}
    >
      {tabs.map((tab) => {
        const selected = tab.value === value
        return (
          <button
            key={tab.value}
            type="button"
            role="tab"
            data-value={tab.value}
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.value)}
            className={cn(
              "inline-flex shrink-0 items-center gap-1.5 border-b-2 px-0.5 font-medium whitespace-nowrap transition-colors",
              size === "sm" ? "min-h-[38px] text-[13px]" : "min-h-10 text-sm",
              selected
                ? "border-foreground text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {tab.label}
            {tab.count !== undefined && <Pill>{tab.count}</Pill>}
          </button>
        )
      })}
    </div>
  )
}

/** A segmented control: "24h | 7 days | 30 days". */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
}: {
  options: { value: T; label: string }[]
  value: T
  onChange: (value: T) => void
  label: string
}) {
  return (
    <div role="group" aria-label={label} className="flex rounded-lg border bg-card p-0.5">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={option.value === value}
          onClick={() => onChange(option.value)}
          className={cn(
            "min-h-[30px] rounded-md px-3 text-[13px] font-medium",
            option.value === value ? "bg-secondary text-foreground" : "text-fg-2 hover:text-foreground",
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}

/** A settings section: its title and description on the left, its controls on the right. */
export function SettingsSection({
  title,
  description,
  children,
  danger = false,
  last = false,
}: {
  title: React.ReactNode
  description: React.ReactNode
  children: React.ReactNode
  danger?: boolean
  last?: boolean
}) {
  return (
    <section className={cn("flex flex-wrap gap-x-10 gap-y-4 py-6", !last && "border-b")}>
      <div className="min-w-0 flex-[1_1_260px]">
        <h2 className={cn("text-[15px] font-semibold", danger && "text-danger-fg")}>{title}</h2>
        <p className="mt-1.5 leading-normal text-muted-foreground">{description}</p>
      </div>
      <div className="min-w-0 flex-[2_1_460px]">{children}</div>
    </section>
  )
}

/** Label/value rows. */
export function DefinitionList({
  rows,
  labelWidth = "110px",
}: {
  rows: [React.ReactNode, React.ReactNode][]
  labelWidth?: string
}) {
  return (
    <dl className="grid gap-x-3 gap-y-2.5 text-[13px]" style={{ gridTemplateColumns: `${labelWidth} minmax(0, 1fr)` }}>
      {rows.map(([label, value], index) => (
        <div key={index} className="contents">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Mono({ className, ...props }: React.ComponentProps<"span">) {
  return <span className={cn("font-mono text-[13px]", className)} {...props} />
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return <kbd className="rounded border bg-card px-1.5 font-mono text-[11px] text-muted-foreground">{children}</kbd>
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex flex-wrap items-center gap-3 rounded-xl border border-danger-border bg-danger-bg px-4 py-3 text-danger-fg"
    >
      <AlertTriangle className="size-4 shrink-0" aria-hidden />
      <span className="flex-1">{errorMessage(error)}</span>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RotateCw /> Try again
        </Button>
      )}
    </div>
  )
}

export function Loading({ lines = 4, className }: { lines?: number; className?: string }) {
  return (
    <div className={cn("flex flex-col gap-3 p-4", className)} aria-busy="true" aria-label="Loading">
      {Array.from({ length: lines }, (_, index) => (
        <Skeleton key={index} className="h-4" style={{ width: `${88 - index * 11}%` }} />
      ))}
    </div>
  )
}

/** A callout, the warning or error kind. */
export function Callout({
  tone = "warning",
  children,
  action,
}: {
  tone?: "warning" | "danger" | "brand"
  children: React.ReactNode
  action?: React.ReactNode
}) {
  const tones = {
    warning: "border-warning-border bg-warning-bg text-warning-strong",
    danger: "border-danger-border bg-danger-bg text-danger-fg",
    brand: "border-brand/30 bg-brand-soft text-fg-2",
  }
  return (
    <div
      role="status"
      className={cn("flex flex-wrap items-center gap-x-4 gap-y-2.5 rounded-xl border px-4 py-3", tones[tone])}
    >
      <AlertTriangle className={cn("size-4 shrink-0", tone === "warning" && "text-warning-fg")} aria-hidden />
      <span className="flex-[1_1_360px]">{children}</span>
      {action}
    </div>
  )
}
