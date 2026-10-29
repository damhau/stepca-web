import createFetchClient, { type Middleware } from "openapi-fetch"
import createClient from "openapi-react-query"
import type { paths } from "./schema"

// The session's CSRF token, from GET /api/v1/session and sign-in: every write sends it back
let csrfToken = ""

export function setCsrfToken(token: string) {
  csrfToken = token
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"])

// Called when the server says the session is gone (expired, or signed out in another tab)
let onSignedOut: () => void = () => {}

export function whenSignedOut(callback: () => void) {
  onSignedOut = callback
}

const session: Middleware = {
  onRequest({ request }) {
    if (!SAFE_METHODS.has(request.method)) request.headers.set("X-CSRFToken", csrfToken)
    return request
  },
  onResponse({ request, response }) {
    if (response.status === 401 && !new URL(request.url).pathname.endsWith("/api/v1/session")) onSignedOut()
    return response
  },
}

export const fetchClient = createFetchClient<paths>({ baseUrl: window.location.origin, credentials: "same-origin" })
fetchClient.use(session)

// Typed TanStack Query hooks: $api.useQuery("get", "/api/v1/certificates", { params: { query } })
export const $api = createClient(fetchClient)

/** What went wrong, in words: the API's {"error"}, a list of invalid fields, or the network. */
export function errorMessage(error: unknown): string {
  if (error && typeof error === "object" && "error" in error && typeof error.error === "string") return error.error
  if (Array.isArray(error)) {
    return error
      .map((problem: { loc?: (string | number)[]; msg?: string }) =>
        [problem.loc?.join("."), problem.msg?.replace(/^Value error, /, "")].filter(Boolean).join(": "),
      )
      .join("; ")
  }
  if (error instanceof TypeError) return "The server could not be reached."
  if (error instanceof Error) return error.message
  return "Something went wrong."
}
