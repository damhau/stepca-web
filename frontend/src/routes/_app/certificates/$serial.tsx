import { createFileRoute, redirect } from "@tanstack/react-router"

// A certificate's page is the list with its details open
export const Route = createFileRoute("/_app/certificates/$serial")({
  beforeLoad: ({ params }) => {
    throw redirect({ to: "/certificates", search: { cert: params.serial }, replace: true })
  },
})
