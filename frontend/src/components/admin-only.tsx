import { useCan } from "@/api/session"

/** Pages for admins: the server refuses the others anyway, this says so instead of showing an error. */
export function AdminOnly({ children }: { children: React.ReactNode }) {
  const can = useCan()
  if (can("admin")) return <>{children}</>
  return (
    <div className="mx-auto max-w-md py-24 text-center">
      <h1 className="text-xl font-semibold">This page is for admins</h1>
      <p className="mt-2 text-sm text-muted-foreground">Ask an admin of this app if you need what it shows.</p>
    </div>
  )
}
