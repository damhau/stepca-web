import { Card, CardHeader } from "./kit"
import { cn } from "@/lib/utils"

/** A card with a title, for a record's parts. */
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
    <Card className={className}>
      <CardHeader title={title} actions={actions} />
      {children}
    </Card>
  )
}

/** Label/value rows inside a card. */
export function Fields({ rows, className }: { rows: [React.ReactNode, React.ReactNode][]; className?: string }) {
  return (
    <dl className={cn("divide-y divide-border-subtle", className)}>
      {rows.map(([label, value], index) => (
        <div key={index} className="grid gap-1 px-4 py-2.5 sm:grid-cols-[minmax(9rem,13rem)_1fr] sm:gap-4">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  )
}
