import { createFileRoute, redirect } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/acme/")({
  beforeLoad: () => {
    throw redirect({ to: "/acme/orders", replace: true })
  },
})
