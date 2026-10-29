import { AlertTriangle, RotateCw } from "lucide-react"
import { errorMessage } from "@/api/client"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

export function PageHeader({
  title,
  description,
  actions,
  children,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  children?: React.ReactNode
}) {
  return (
    <header className="mb-6 flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight text-balance break-words">{title}</h1>
          {description && <p className="mt-1 max-w-[70ch] text-sm text-muted-foreground">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </header>
  )
}

export function Section({
  title,
  actions,
  children,
  className,
}: {
  title: React.ReactNode
  actions?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <section className={cn("rounded-lg border bg-card", className)}>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </section>
  )
}

/** Label/value rows, for a record's fields. */
export function Fields({ rows }: { rows: [React.ReactNode, React.ReactNode][] }) {
  return (
    <dl className="divide-y">
      {rows.map(([label, value], index) => (
        <div key={index} className="grid gap-1 px-4 py-2.5 sm:grid-cols-[minmax(10rem,14rem)_1fr] sm:gap-4">
          <dt className="text-sm text-muted-foreground">{label}</dt>
          <dd className="min-w-0 text-sm break-words">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex flex-col items-start gap-3 rounded-lg border border-revoked/30 bg-revoked-soft/40 p-4 text-sm"
    >
      <p className="flex items-center gap-2 font-medium text-revoked">
        <AlertTriangle className="size-4" aria-hidden />
        {errorMessage(error)}
      </p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RotateCw /> Try again
        </Button>
      )}
    </div>
  )
}

export function LoadingBlock({ lines = 4 }: { lines?: number }) {
  return (
    <div className="flex flex-col gap-3 p-4" aria-busy="true" aria-label="Loading">
      {Array.from({ length: lines }, (_, index) => (
        <Skeleton key={index} className="h-5" style={{ width: `${90 - index * 12}%` }} />
      ))}
    </div>
  )
}
