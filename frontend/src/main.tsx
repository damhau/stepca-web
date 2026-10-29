import "@fontsource/ibm-plex-sans/400.css"
import "@fontsource/ibm-plex-sans/500.css"
import "@fontsource/ibm-plex-sans/600.css"
import "@fontsource/ibm-plex-mono/400.css"
import "@fontsource/ibm-plex-mono/500.css"
import "./index.css"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createRouter, RouterProvider } from "@tanstack/react-router"
import { setNonce } from "get-nonce"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { whenSignedOut } from "./api/client"
import { sessionQuery } from "./api/session"
import { cspNonce } from "./lib/nonce"
import { routeTree } from "./routeTree.gen"

// The dialogs' scroll lock adds a <style> element: the CSP allows it with this response's nonce
if (cspNonce) setNonce(cspNonce)

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 15_000, refetchOnWindowFocus: false, retry: 1 },
  },
})

const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: "intent",
  defaultPreloadStaleTime: 0,
  scrollRestoration: true,
})

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}

// The session ended on the server: back to the sign-in page, then back here
whenSignedOut(() => {
  queryClient.invalidateQueries({ queryKey: sessionQuery.queryKey }).then(() => router.invalidate())
})

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
)
