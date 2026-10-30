import { createFileRoute, redirect } from "@tanstack/react-router"

// The configuration is a tab of the Authority page
export const Route = createFileRoute("/_app/settings")({
  beforeLoad: () => {
    throw redirect({ to: "/ca", search: { tab: "configuration" }, replace: true })
  },
})
