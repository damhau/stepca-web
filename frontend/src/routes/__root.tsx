import type { QueryClient } from "@tanstack/react-query"
import { createRootRouteWithContext, Link, Outlet } from "@tanstack/react-router"
import { Toaster } from "@/components/toaster"
import { TooltipProvider } from "@/components/ui/tooltip"

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: () => (
    <TooltipProvider delayDuration={300}>
      <Outlet />
      <Toaster />
    </TooltipProvider>
  ),
  notFoundComponent: NotFound,
})

function NotFound() {
  return (
    <div className="mx-auto max-w-md py-24 text-center">
      <h1 className="text-xl font-semibold">There is no page here</h1>
      <p className="mt-2 text-sm text-muted-foreground">The link may be out of date, or the page was renamed.</p>
      <Link to="/" className="mt-6 inline-block text-sm font-medium text-primary underline-offset-4 hover:underline">
        Go to the dashboard
      </Link>
    </div>
  )
}
