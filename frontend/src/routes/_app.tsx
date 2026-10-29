import { createFileRoute, Outlet, redirect } from "@tanstack/react-router"
import { rememberSession, sessionQuery } from "@/api/session"
import { AppShell } from "@/components/app-shell"

// Every page but the sign-in page: signed in, or sent to sign in and back
export const Route = createFileRoute("/_app")({
  beforeLoad: async ({ context, location }) => {
    const session = rememberSession(await context.queryClient.ensureQueryData(sessionQuery))
    if (!session.authenticated) throw redirect({ to: "/login", search: { redirect: location.href } })
    return { session }
  },
  component: () => (
    <AppShell>
      <Outlet />
    </AppShell>
  ),
})
